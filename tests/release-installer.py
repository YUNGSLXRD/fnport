#!/usr/bin/env python3
"""Exercise release discovery and package downloads without touching a router."""
import json
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerDiscovery(unittest.TestCase):
    def run_fixture(self, split, ext, public=False, install=False, api_failure=False, corrupt_api=False, corrupt_all=False):
        with tempfile.TemporaryDirectory(prefix='installer-', dir=ROOT / 'windows/dist') as temp:
            root = Path(temp)
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            pm = 'apk' if ext == 'apk' else 'opkg'
            version = '0.6.3-r1' if install else '0.7.0-r2'
            current = f'fnport-{version} all installed' if pm == 'apk' else f'Version: {version}'
            (bin_dir / pm).write_text('''#!/bin/sh
case "$1" in
 status|list) printf '%s\\n' ''' + repr(current) + ''';;
 update) exit 0;;
 install|add) printf '%s\\n' "$@" > "$FIXTURE/install-args"; exit 17;;
 *) exit 2;;
esac
''')
            names = (['fnport-0.7.0-r2.apk', 'luci-app-fnport-0.7.0-r2.apk', 'luci-i18n-fnport-ru-0.7.0.apk']
                     if ext == 'apk' else
                     ['fnport_0.7.0-r2_all.ipk', 'luci-app-fnport_0.7.0-r2_all.ipk', 'luci-i18n-fnport-ru_0.7.0_all.ipk'])
            urls = [{'browser_download_url': 'https://github.com/YUNGSLXRD/fnport/releases/download/' +
                     ('v0.7.0/' if public else 'components-v0.7.0/') + ('openwrt-' if public else '') + name}
                    for name in names]
            for index, asset in enumerate(urls):
                asset['url'] = f'https://api.github.com/repos/YUNGSLXRD/fnport/releases/assets/{index + 1}'
                asset['digest'] = 'sha256:' + hashlib.sha256(b'package fixture\n').hexdigest()
            (root / 'release.json').write_text(json.dumps({'tag_name': 'v0.7.0', 'assets': [] if split else urls}))
            (root / 'components.json').write_text(json.dumps({'assets': urls}))
            (bin_dir / 'uclient-fetch').write_text('''#!/bin/sh
url= dest= accept=
while [ "$#" -gt 0 ]; do
 case "$1" in
  -O) dest=$2; shift 2;;
  --header=*) accept=${1#--header=}; shift;;
  -*) shift;;
  *) url=$1; shift;;
 esac
done
printf '%s\\n' "$url" >> "$FIXTURE/fetched"
case "$url" in
 */releases/latest) cp "$FIXTURE/release.json" "$dest";;
 */releases/tags/components-v0.7.0) cp "$FIXTURE/components.json" "$dest";;
 */releases/assets/*)
  [ "$accept" = 'Accept: application/octet-stream' ] || exit 9
  [ "${FIXTURE_API_FAILURE:-0}" = 0 ] || exit 4
  if [ "${FIXTURE_CORRUPT_API:-0}" = 1 ] || [ "${FIXTURE_CORRUPT_ALL:-0}" = 1 ]; then
   printf '{"error":"not a package"}\\n' > "$dest"
  else printf 'package fixture\\n' > "$dest"; fi;;
 */releases/download/v0.7.0/openwrt-*)
  if [ "${FIXTURE_CORRUPT_ALL:-0}" = 1 ]; then printf 'wrong bytes\\n' > "$dest"
  else printf 'package fixture\\n' > "$dest"; fi;;
 *) exit 3;;
esac
''')
            (bin_dir / 'jsonfilter').write_text(r'''#!/usr/bin/env python3
import json,re,sys
value=json.load(open(sys.argv[2])); query=sys.argv[4]
if query=='@.tag_name': print(value['tag_name'])
elif query=='@.assets[*].browser_download_url':
 for a in value['assets']: print(a['browser_download_url'])
else:
 match=re.fullmatch(r'@\.assets\[@\.browser_download_url="([^\"]+)"\]\.(url|digest)',query)
 if not match: raise SystemExit(2)
 for a in value['assets']:
  if a['browser_download_url']==match[1] and a.get(match[2]): print(a[match[2]])
''')
            for path in bin_dir.iterdir():
                path.chmod(0o755)
            installer = root / 'install.sh'
            installer.write_text((ROOT / 'install.sh').read_text()
                                 .replace('TMP="/tmp/fnport-install"', 'TMP="' + str(root / 'download') + '"')
                                 .replace('CONF="/etc/config/fnport"', 'CONF="' + str(root / 'unused-config') + '"'))
            env = dict(os.environ, FIXTURE_API_FAILURE=str(int(api_failure)), FIXTURE_CORRUPT_API=str(int(corrupt_api)), FIXTURE_CORRUPT_ALL=str(int(corrupt_all)), PATH=str(bin_dir) + ':' + os.environ['PATH'], FIXTURE=str(root))
            result = subprocess.run(['sh', str(installer)], env=env, text=True, capture_output=True)
            if install and corrupt_all:
                self.assertNotEqual(result.returncode, 0)
                self.assertFalse((root / 'install-args').exists())
                self.assertFalse(any((root / 'download').glob('*.apk')))
                self.assertFalse(any((root / 'download').glob('*.partial')))
                self.assertIn('no packages were installed', result.stderr)
            elif install:
                # Stop deliberately at the mocked package manager, before any
                # real service/config/cache action at the end of the installer.
                self.assertEqual(result.returncode, 17, result.stdout + result.stderr)
                actual = [Path(arg).name for arg in (root / 'install-args').read_text().splitlines()
                          if arg.startswith(str(root / 'download') + '/')]
                self.assertEqual(actual, names)
                self.assertIn('0.6.3-r1 -> 0.7.0-r2', result.stdout)
                self.assertTrue(all((root / 'download' / name).is_file() for name in names))
                fetched = (root / 'fetched').read_text().splitlines()
                self.assertEqual(sum('/releases/assets/' in url for url in fetched), 3)
                self.assertEqual(sum('/releases/download/' in url for url in fetched), 3 if api_failure or corrupt_api else 0)
            else:
                self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
                self.assertIn('already the latest version', result.stdout)

    def test_legacy_ipk(self): self.run_fixture(False, 'ipk')
    def test_split_ipk(self): self.run_fixture(True, 'ipk')
    def test_split_apk(self): self.run_fixture(True, 'apk')
    def test_public_ipk(self): self.run_fixture(False, 'ipk', public=True)
    def test_public_apk(self): self.run_fixture(False, 'apk', public=True)
    def test_downloaded_ipk_names(self): self.run_fixture(False, 'ipk', public=True, install=True)
    def test_downloaded_apk_names(self): self.run_fixture(False, 'apk', public=True, install=True)
    def test_api_failure_uses_browser_url(self): self.run_fixture(False, 'apk', public=True, install=True, api_failure=True)
    def test_api_json_response_falls_back(self): self.run_fixture(False, 'apk', public=True, install=True, corrupt_api=True)
    def test_bad_download_never_reaches_package_manager(self): self.run_fixture(False, 'apk', public=True, install=True, corrupt_all=True)


if __name__ == '__main__':
    unittest.main()
