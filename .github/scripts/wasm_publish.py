import argparse
import hashlib
import hmac
import json
import os
import subprocess
import time
import uuid
from pathlib import Path
from urllib.error import HTTPError, URLError
from urllib.parse import quote
from urllib.request import HTTPRedirectHandler, Request, build_opener

from wasm_batch import verify

BUILD_REPO = 'Agent2Builder/agent2api-providers-releases'
ENDPOINT = 'https://oyl.agent2api.dev/api/ci/plugins'


def gh(*args, token=None, missing=False):
    env = dict(os.environ)
    if token:
        env['GH_TOKEN'] = token
    result = subprocess.run(['gh', *args], capture_output=True, text=True, env=env, timeout=180)
    if result.returncode:
        if missing and ('HTTP 404' in result.stderr or 'release not found' in result.stderr.lower()):
            return None
        raise RuntimeError(result.stderr.strip()[:1000])
    return result.stdout


def api(path, token=None):
    return json.loads(gh('api', path, token=token))


def find_release(repository, tag, token=None):
    published = gh('api', f'repos/{repository}/releases/tags/{quote(tag, safe="")}', token=token, missing=True)
    if published:
        return json.loads(published)
    for page in range(1, 11):
        releases = api(f'repos/{repository}/releases?per_page=100&page={page}', token)
        for release in releases:
            if release['tag_name'] == tag:
                return release
        if len(releases) < 100:
            break
    return None


def publish_release(repository, tag, notes, files, prerelease, token=None):
    release = find_release(repository, tag, token)
    flag = str(prerelease).lower()
    if release:
        if release['prerelease'] != prerelease:
            raise ValueError('已有 Release 的预发布标记不一致，拒绝修改')
        if not release['draft']:
            if release['body'].rstrip() != notes.read_text(encoding='utf-8').rstrip():
                raise ValueError('已公开同版本日志不同，拒绝覆盖')
            assets = {asset['name']: asset for asset in release['assets']}
            if set(assets) != {file.name for file in files}:
                raise ValueError('已公开同版本附件清单不同，拒绝覆盖')
            for file in files:
                digest = 'sha256:' + hashlib.sha256(file.read_bytes()).hexdigest()
                if assets[file.name].get('digest') != digest or assets[file.name]['size'] != file.stat().st_size:
                    raise ValueError('已公开同版本附件内容不同，请使用新版本号')
            print(f'{repository} {tag} 已发布相同内容，跳过上传', flush=True)
            return release
    else:
        gh('release', 'create', tag, '-R', repository, '--draft', '--latest=false', f'--prerelease={flag}',
            '--title', tag, '--notes-file', str(notes), token=token)
    for file in files:
        gh('release', 'upload', tag, str(file), '-R', repository, '--clobber', token=token)
    release = find_release(repository, tag, token)
    if not release:
        raise ValueError('Release 草稿无法读取，停止公开')
    if {asset['name'] for asset in release['assets']} != {file.name for file in files}:
        raise ValueError('Release 附件尚未齐全，保留草稿')
    for file in files:
        asset = next(asset for asset in release['assets'] if asset['name'] == file.name)
        if asset.get('digest') != 'sha256:' + hashlib.sha256(file.read_bytes()).hexdigest():
            raise ValueError('GitHub 附件完整校验值不一致，保留草稿')
    gh('release', 'edit', tag, '-R', repository, '--draft=false', '--latest=false', f'--prerelease={flag}',
        '--title', tag, '--notes-file', str(notes), token=token)
    print(f'已发布 {repository} {tag}，附件 {len(files)} 个', flush=True)
    return api(f'repos/{repository}/releases/tags/{quote(tag, safe="")}', token)


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, request, fp, code, message, headers, target):
        return None


def notify(package, release, run_id):
    secret = os.environ.get('PLUGIN_PUBLISH_SECRET', '').encode('utf-8')
    if len(secret) < 32:
        raise RuntimeError('插件官网发布凭据尚未配置')
    payload = {'schema': 1, 'repository': BUILD_REPO, 'pluginId': package['id'], 'runId': str(run_id), 'release': release}
    body = json.dumps(payload, ensure_ascii=False, separators=(',', ':')).encode('utf-8')
    digest = hashlib.sha256(body).hexdigest()
    opener = build_opener(NoRedirect())
    for attempt in range(5):
        timestamp = str(int(time.time()))
        nonce = str(uuid.uuid4())
        signed = f'{timestamp}\n{nonce}\nPOST\n/api/ci/plugins\n{digest}'.encode()
        request = Request(ENDPOINT, data=body, method='POST', headers={'Content-Type': 'application/json',
            'User-Agent': 'agent2api-wasm-release', 'X-Release-Timestamp': timestamp, 'X-Release-Nonce': nonce,
            'X-Release-Signature': hmac.new(secret, signed, hashlib.sha256).hexdigest()})
        try:
            with opener.open(request, timeout=180) as response:
                content = response.read(65537)
                if len(content) > 65536:
                    raise RuntimeError('官网插件登记响应过大')
                result = json.loads(content)
            data = result.get('data', {})
            if result.get('success') is not True or data.get('ready') is not True or data.get('tag') != package['tag']:
                raise RuntimeError('官网没有确认插件上传并开放成功')
            print(f"官网已上传并核对 {package['id']} {package['version']}，完整独立包已开放", flush=True)
            return
        except HTTPError as error:
            message = error.read(65536).decode('utf-8', errors='replace')
            if error.code not in (409, 429, 500, 502, 503, 504) or attempt == 4:
                raise RuntimeError(f'官网插件登记 HTTP {error.code}：{message[:500]}') from error
        except (URLError, TimeoutError, OSError):
            if attempt == 4:
                raise
        time.sleep(min(2 ** (attempt + 1), 20))


def publish(folder, only):
    index = json.loads((folder / 'release-index.json').read_text(encoding='utf-8'))
    verify(folder, index)
    notes = folder / 'release-notes.md'
    prerelease = '-' in index['version'].split('+', 1)[0]
    files = [folder / filename for package in index['packages'] for filename in (package['file'], package['file'] + '.sha256')]
    if only in ('all', 'publish'):
        publish_release(BUILD_REPO, index['aggregate_tag'], notes, files, prerelease)
        for package in index['packages']:
            publish_release(BUILD_REPO, package['tag'], notes,
                [folder / package['file'], folder / (package['file'] + '.sha256')], '-' in package['version'].split('+', 1)[0])
    if only in ('all', 'website'):
        for package in index['packages']:
            release = api(f"repos/{BUILD_REPO}/releases/tags/{quote(package['tag'], safe='')}")
            notify(package, release, os.environ['RUN_ID'])
    if only == 'mirror':
        token = os.environ.get('SOURCE_RELEASE_TOKEN', '')
        if not token:
            raise RuntimeError('源码 Release 同步凭据未配置')
        source_tag = index['ref']
        tagged = api(f"repos/{index['repository']}/git/ref/tags/{quote(source_tag, safe='')}", token)
        if tagged['object']['sha'] != index['sha']:
            raise ValueError('源码发布 tag 与构建来源不一致')
        publish_release(index['repository'], source_tag, notes, files, prerelease, token)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--directory', type=Path, default=Path('dist'))
    parser.add_argument('--only', choices=['all', 'publish', 'website', 'mirror'], default='all')
    args = parser.parse_args()
    publish(args.directory, args.only)
