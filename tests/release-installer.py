#!/usr/bin/env python3
"""Exercise old and split release discovery without touching a router."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class InstallerDiscovery(unittest.TestCase):
    def run_fixture(self, split, ext):
        with tempfile.TemporaryDirectory(prefix='installer-', dir=ROOT / 'windows/dist') as temp:
            root = Path(temp)
            bin_dir = root / 'bin'
            bin_dir.mkdir()
            pm = 'apk' if ext == 'apk' else 'opkg'
            current = 'fnport-0.7.0-r2 all installed' if pm == 'apk' else 'Version: 0.7.0-r2'
            (bin_dir / pm).write_text('#!/bin/sh\nprintf \'%s\\n\' ' + repr(current) + '\n')
            # Hide the host package managers by putting only the selected one in PATH.
            urls = [{'browser_download_url': f'https://github.com/{"YUNGSLXRD/fnport"}/releases/download/components-v0.7.0/fnport' + ('-0.7.0-r2.apk' if ext == 'apk' else '_0.7.0-r2_all.ipk')}]
            (root / 'release.json').write_text(json.dumps({'tag_name': 'v0.7.0', 'assets': [] if split else urls}))
            (root / 'components.json').write_text(json.dumps({'assets': urls}))
            (bin_dir / 'uclient-fetch').write_text('''#!/bin/sh
case "$4" in
 */releases/latest) cp "$FIXTURE/release.json" "$3";;
 */releases/tags/components-v0.7.0) cp "$FIXTURE/components.json" "$3";;
 *) exit 3;;
esac
''')
            (bin_dir / 'jsonfilter').write_text('''#!/usr/bin/env python3
import json,sys
value=json.load(open(sys.argv[2]))
if sys.argv[4]=='@.tag_name': print(value['tag_name'])
else:
 for a in value['assets']: print(a['browser_download_url'])
''')
            for path in bin_dir.iterdir():
                path.chmod(0o755)
            installer = root / 'install.sh'
            installer.write_text((ROOT / 'install.sh').read_text().replace('TMP="/tmp/fnport-install"', 'TMP="' + str(root / 'download') + '"'))
            env = dict(os.environ, PATH=str(bin_dir) + ':' + os.environ['PATH'], FIXTURE=str(root))
            result = subprocess.run(['sh', str(installer)], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertIn('already the latest version', result.stdout)

    def test_legacy_ipk(self): self.run_fixture(False, 'ipk')
    def test_split_ipk(self): self.run_fixture(True, 'ipk')
    def test_split_apk(self): self.run_fixture(True, 'apk')


if __name__ == '__main__':
    unittest.main()
