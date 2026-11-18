import argparse
import base64
import hashlib
import json
import os
import re
import subprocess
import tomllib
import zipfile
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

REPOSITORIES = {'ProvidersPlugin/Agent2Providers': 'agent', 'ProvidersPlugin/Agent2WebProviders': 'web'}
TARGET = 'wasm32-unknown-unknown'
PUBLIC_KEY = bytes.fromhex('7cdac378ff9bf23b72ae1b686f19859b3c802c26eed13c699f7df39f027352d6')
VERSION = re.compile(r'\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?')
MAX_BYTES = 24 * 1024 * 1024


def git(folder, *args):
    return subprocess.check_output(['git', '-C', str(folder), *args], text=True).strip()


def output(name, value):
    with open(os.environ['GITHUB_OUTPUT'], 'a', encoding='utf-8') as target:
        target.write(f'{name}={value}\n')


def prepare(source, repository, ref, expected_sha, sdk):
    if repository not in REPOSITORIES:
        raise ValueError('独立插件只允许指定的两个源码仓库')
    version = ref.removeprefix('refs/tags/').removeprefix('v')
    if not VERSION.fullmatch(version) or ref.removeprefix('refs/tags/') != f'v{version}':
        raise ValueError('批量发布必须使用完整仓库版本 tag')
    revision = git(source, 'rev-parse', 'HEAD')
    if expected_sha and (not re.fullmatch(r'[0-9a-f]{40}', expected_sha) or revision != expected_sha):
        raise ValueError('实际源码与派发时固定的提交不一致')
    git(source, 'fetch', '--no-tags', '--depth=1', 'origin', f'refs/tags/v{version}')
    if git(source, 'rev-parse', 'FETCH_HEAD^{commit}') != revision:
        raise ValueError('源码 tag 已移动，拒绝发布')
    package = tomllib.loads((source / 'Cargo.toml').read_text(encoding='utf-8'))['workspace']['package']
    if package['version'] != version or json.loads((source / 'pack.json').read_text())['version'] != version:
        raise ValueError('仓库版本与 tag 不一致')
    if REPOSITORIES[repository] == 'web':
        sdk_ref = os.environ.get('SDK_REF') or f'v{version}'
        if sdk_ref != f'v{version}':
            raise ValueError('网页插件必须固定同版本 SDK')
        git(sdk, 'fetch', '--no-tags', '--depth=1', 'origin', f'refs/tags/{sdk_ref}')
        sdk_sha = git(sdk, 'rev-parse', 'HEAD')
        if git(sdk, 'rev-parse', 'FETCH_HEAD^{commit}') != sdk_sha:
            raise ValueError('网页 SDK tag 已移动')
        dispatched = os.environ.get('SDK_SHA', '')
        if dispatched and dispatched != sdk_sha:
            raise ValueError('网页 SDK 与派发时固定的源码不一致')
    packages = []
    for file in sorted((source / 'wasm').glob('*/pack.json')):
        provider = file.parent.name
        manifest = json.loads(file.read_text(encoding='utf-8'))
        crate = tomllib.loads((file.parent / 'Cargo.toml').read_text(encoding='utf-8'))['package']
        identity = f'agent2api-wasm-{provider}'
        plugin_version = manifest['version']
        if not re.fullmatch(r'[a-z][a-z0-9-]*', provider) or not VERSION.fullmatch(plugin_version):
            raise ValueError('插件身份或版本不正确')
        if manifest['id'] != identity or crate['name'] != identity or crate['version'] != plugin_version:
            raise ValueError('插件清单与 Cargo 包身份不一致')
        if manifest.get('protocol') != 1 or list(manifest['entry']) != [TARGET] or len(manifest['providers']) != 1:
            raise ValueError('插件必须是单提供商的跨平台 WASM 包')
        if manifest['providers'][0]['id'] != provider or manifest.get('ui') or (file.parent / 'ui').exists():
            raise ValueError('插件身份不一致或包含可执行界面')
        if (manifest.get('provider_category', 'agent') == 'web') != (REPOSITORIES[repository] == 'web'):
            raise ValueError('插件分类与源码仓库不一致')
        if not (file.parent / 'wasm.json').is_file():
            raise ValueError('插件缺少权限清单')
        packages.append({'provider': provider, 'id': identity, 'version': plugin_version,
            'tag': f'wasm-{provider}-v{plugin_version}', 'file': f'{identity}-{plugin_version}-{TARGET}.zip'})
    if not packages or len(packages) > 50:
        raise ValueError('独立插件清单为空或超出发布上限')
    index = {'schema': 1, 'repository': repository, 'ref': f'v{version}', 'sha': revision, 'version': version,
        'aggregate_tag': ('web-v' if REPOSITORIES[repository] == 'web' else 'v') + version, 'packages': packages}
    Path('release-index.json').write_text(json.dumps(index, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    output('category', REPOSITORIES[repository])
    output('version', version)
    output('tag', index['aggregate_tag'])
    output('artifact', f"wasm-{REPOSITORIES[repository]}-{version}")
    print(f'固定源码 {repository}@{revision}，共 {len(packages)} 个独立包')


def verify_package(path, package):
    data = path.read_bytes()
    if not 0 < len(data) <= MAX_BYTES:
        raise ValueError('插件包大小不正确')
    digest = hashlib.sha256(data).hexdigest()
    if Path(str(path) + '.sha256').read_text(encoding='utf-8') != f'{digest}  {path.name}\n':
        raise ValueError('签名后下载校验值不一致')
    with zipfile.ZipFile(path) as archive:
        names = archive.namelist()
        if len(names) != len(set(names)) or archive.testzip() is not None:
            raise ValueError('插件包存在重复或损坏条目')
        if any(name.startswith('/') or '\\' in name or ':' in name or '..' in name.split('/') or name.startswith('ui/') for name in names):
            raise ValueError('插件包包含不安全路径或可执行界面')
        manifest = json.loads(archive.read('pack.json'))
        if manifest['id'] != package['id'] or manifest['version'] != package['version'] or manifest['protocol'] != 1:
            raise ValueError('签名包身份与发布清单不一致')
        if list(manifest['entry']) != [TARGET] or manifest['providers'][0]['id'] != package['provider']:
            raise ValueError('插件包入口或提供商不一致')
        permissions = archive.read('wasm.json')
        spec = json.loads(permissions)
        if spec['abi'] != 1:
            raise ValueError('WASM ABI 不一致')
        binary = archive.read(manifest['entry'][TARGET])
        if binary[:8] != b'\0asm\x01\0\0\0':
            raise ValueError('插件入口不是有效 WASM')
        providers = sorted(f"{item['id']}:{item.get('order', 0)}:{0 if item.get('default_enabled') is False else 1}" for item in manifest['providers'])
        entries = sorted(f'{key}={value}' for key, value in manifest['entry'].items())
        payload = '\n'.join(['agent2api-pack-v1', f"id={manifest['id']}", f"version={manifest['version']}",
            f"protocol={manifest['protocol']}", f'target={TARGET}', f"providers={','.join(providers)}",
            f"entry={','.join(entries)}", f'binary={hashlib.sha256(binary).hexdigest()}', 'ui=', ''])
        payload += f'wasm={hashlib.sha256(permissions).hexdigest()}\n'
        signature = manifest['signature']
        if signature['algorithm'] != 'ed25519' or signature['target'] != TARGET or signature['keyId'] != 'official-2026':
            raise ValueError('插件缺少正确官方签名')
        Ed25519PublicKey.from_public_bytes(PUBLIC_KEY).verify(base64.b64decode(signature['value'], validate=True), payload.encode())
    return digest


def verify(folder, index):
    expected = {'release-index.json', 'release-notes.md'}
    for package in index['packages']:
        expected.update([package['file'], package['file'] + '.sha256'])
        verify_package(folder / package['file'], package)
    if {path.name for path in folder.iterdir()} != expected:
        raise ValueError('发布产物不完整或包含额外文件')
    notes = (folder / 'release-notes.md').read_text(encoding='utf-8')
    if not notes.startswith('## 核心更新\n') or '\n## 其他更新\n' not in notes or index['version'] not in notes:
        raise ValueError('发布日志不完整')
    print(f"已核对 {len(index['packages'])} 个包的身份、版本、完整校验值和官方签名")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['prepare', 'verify'])
    parser.add_argument('--source', type=Path, default=Path('source'))
    parser.add_argument('--sdk', type=Path, default=Path('Agent2Providers'))
    parser.add_argument('--repository', default=os.environ.get('SOURCE_REPO', ''))
    parser.add_argument('--ref', default=os.environ.get('REF', ''))
    parser.add_argument('--sha', default=os.environ.get('SOURCE_SHA', ''))
    parser.add_argument('--directory', type=Path, default=Path('dist'))
    args = parser.parse_args()
    if args.command == 'prepare':
        prepare(args.source, args.repository, args.ref, args.sha, args.sdk)
    else:
        verify(args.directory, json.loads((args.directory / 'release-index.json').read_text(encoding='utf-8')))
