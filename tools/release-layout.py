#!/usr/bin/env python3
"""Keep the public release to one ZIP without losing router distributions."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import zipfile

REPO = 'YUNGSLXRD/fnport'
ROOT = Path(__file__).resolve().parents[1]
DIST = ROOT / 'dist'


def gh(*args):
    return subprocess.check_output(['gh', *args], text=True)


def release(tag):
    try:
        return json.loads(gh('api', f'repos/{REPO}/releases/tags/{tag}'))
    except subprocess.CalledProcessError:
        # GitHub's by-tag endpoint cannot find a draft whose tag has not been
        # created yet. The authenticated list endpoint includes those drafts.
        pages = json.loads(gh('api', '--paginate', '--slurp', f'repos/{REPO}/releases?per_page=100'))
        for page in pages:
            for item in page:
                if item['tag_name'] == tag:
                    return item
        raise


def sha256(path):
    return hashlib.file_digest(path.open('rb'), 'sha256').hexdigest()


def verify_remote(tag, paths):
    assets = {a['name']: a for a in release(tag)['assets']}
    for path in paths:
        asset = assets.get(path.name)
        if not asset or asset['size'] != path.stat().st_size:
            raise RuntimeError(f'Uploaded asset missing or incomplete: {tag}/{path.name}')
        if asset.get('digest') != 'sha256:' + sha256(path):
            raise RuntimeError(f'Uploaded asset checksum mismatch: {tag}/{path.name}')


def prepare(version):
    # Packaging revisions reuse the byte-identical cores already built and attested
    # for this version. Never rebuild or replace the application here.
    cache = ROOT / 'dist-previous'
    cache.mkdir(exist_ok=True)
    try:
        old = release(version)
        source = version if any(a['name'].startswith('fnport-connections-linux-') for a in old['assets']) else f'components-{version}'
    except subprocess.CalledProcessError:
        source = f'components-{version}'
    gh('release', 'download', source, '--repo', REPO, '--dir', str(cache), '--clobber',
       '--pattern', 'fnport-connections-linux-*.tar.gz',
       '--pattern', 'fnport-sing-box-linux-*.tar.gz',
       '--pattern', 'fnport-router-core-source-*.tar.gz', '--pattern', 'SHA256SUMS.txt')
    expected = {}
    for line in (cache / 'SHA256SUMS.txt').read_text().splitlines():
        digest, name = line.split(maxsplit=1)
        expected[name.removeprefix('*')] = digest
    archives = sorted(cache.glob('*.tar.gz'))
    if len(archives) != 15:
        raise RuntimeError('Expected seven helpers, seven cores and one source archive')
    for path in archives:
        if sha256(path) != expected.get(path.name):
            raise RuntimeError(f'Previous release checksum mismatch: {path.name}')
    DIST.mkdir(exist_ok=True)
    for path in archives:
        path.replace(DIST / path.name)
    print('Verified and reused 15 router component archives')


def publish(version):
    archive = DIST / f'fnport-windows-{version}.zip'
    with zipfile.ZipFile(archive) as zipped:
        names = zipped.namelist()
        if 'fnport/fnport.exe' not in names:
            raise RuntimeError('Windows application missing')
        if any('license' in name.lower() for name in names):
            raise RuntimeError('Loose license file remains in the Windows ZIP')
        exe = zipped.read('fnport/fnport.exe')
        for notice in (b'== sing-box and libcronet', b'GNU GENERAL PUBLIC LICENSE', b'Source revision: c005f35300ce76427dc285481ec5695f5b179cd2'):
            if notice not in exe:
                raise RuntimeError('Bundled core license or source notice missing from fnport.exe')
    components = sorted(p for p in DIST.iterdir() if p.is_file() and p != archive)
    if len(components) != 22 or not (DIST / 'SHA256SUMS.txt').is_file():
        raise RuntimeError('Incomplete router packages, cores or checksum list')
    tag = f'components-{version}'
    try:
        release(tag)
    except subprocess.CalledProcessError:
        gh('release', 'create', tag, '--repo', REPO, '--target', os.environ['GITHUB_SHA'],
           '--title', f'Компоненты fnport {version.removeprefix("v")}', '--draft',
           '--notes', 'Служебный выпуск для установщика OpenWrt. Обычная загрузка Windows находится в основном релизе. Эти файлы не нужно скачивать все вместе.')
    gh('release', 'upload', tag, '--repo', REPO, '--clobber', *(str(p) for p in components))
    verify_remote(tag, components)
    gh('release', 'edit', tag, '--repo', REPO, '--draft=false', '--latest=false')
    notes = ROOT / 'docs' / f'release-{version.removeprefix("v")}.md'
    try:
        release(version)
    except subprocess.CalledProcessError:
        gh('release', 'create', version, '--repo', REPO, '--target', os.environ['GITHUB_SHA'],
           '--draft', '--title', f'fnport {version.removeprefix("v")}', '--notes-file', str(notes))
    gh('release', 'upload', version, '--repo', REPO, '--clobber', str(archive))
    verify_remote(version, [archive])
    # Remove old technical attachments only after every replacement has been
    # uploaded and checked by its server-side SHA-256 digest.
    for asset in release(version)['assets']:
        if asset['name'] != archive.name:
            gh('release', 'delete-asset', version, asset['name'], '--repo', REPO, '--yes')
    gh('release', 'edit', version, '--repo', REPO, '--title', f'fnport {version.removeprefix("v")}',
       '--notes-file', str(notes), '--draft=false', '--latest=true')
    if [a['name'] for a in release(version)['assets']] != [archive.name]:
        raise RuntimeError('Public release still contains extra attachments')
    print(f'Published {version}: one Windows ZIP; router components in {tag}')


if __name__ == '__main__':
    if len(sys.argv) != 3 or not re.fullmatch(r'v[0-9]+\.[0-9]+\.[0-9]+', sys.argv[2]):
        raise SystemExit('usage: release-layout.py prepare|publish vMAJOR.MINOR.PATCH')
    if sys.argv[1] not in ('prepare', 'publish'):
        raise SystemExit('unknown action')
    globals()[sys.argv[1]](sys.argv[2])
