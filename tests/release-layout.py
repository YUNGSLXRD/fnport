#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('layout', ROOT / 'tools/release-layout.py')
layout = importlib.util.module_from_spec(spec)
spec.loader.exec_module(layout)


class DownloadLayout(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'windows/dist')
        self.addCleanup(self.temp.cleanup)
        self.dist = Path(self.temp.name)
        self.patch = patch.object(layout, 'DIST', self.dist)
        self.patch.start()
        self.addCleanup(self.patch.stop)
        self.native = ['fnport-0.7.0-r2.apk', 'fnport_0.7.0-r2_all.ipk',
                       'luci-app-fnport-0.7.0-r2.apk', 'luci-app-fnport_0.7.0-r2_all.ipk',
                       'luci-i18n-fnport-ru-26.311.69244.f2afef4.apk',
                       'luci-i18n-fnport-ru_26.311.69244.f2afef4_all.ipk']
        for name in self.native:
            (self.dist / name).write_bytes(('package: ' + name).encode())
        for arch in ('amd64', 'arm64', 'armv5', 'armv6', 'armv7', 'mips-softfloat', 'mipsle-softfloat'):
            for prefix in ('fnport-connections-linux-', 'fnport-sing-box-linux-'):
                (self.dist / (prefix + arch + '.tar.gz')).write_bytes(b'component fixture')
        (self.dist / 'fnport-router-core-source-1.14.4.tar.gz').write_bytes(b'source fixture')
        self.archive = self.dist / 'fnport-windows-v0.7.0.zip'
        with zipfile.ZipFile(self.archive, 'w') as z:
            z.writestr('fnport/fnport.exe', b'== sing-box and libcronet\nGNU GENERAL PUBLIC LICENSE\nSource revision: c005f35300ce76427dc285481ec5695f5b179cd2')

    def checksums(self):
        files = sorted(p for p in self.dist.iterdir() if p.name != 'SHA256SUMS.txt')
        (self.dist / 'SHA256SUMS.txt').write_text(''.join(layout.sha256(p) + '  ' + p.name + '\n' for p in files))

    def test_compact_public_names_preserve_package_bytes(self):
        public = layout.public_packages('v0.7.0')
        self.assertEqual(len(public), 6)
        self.assertEqual(sorted([self.archive.name, *(p.name for p in public)])[0], self.archive.name)
        self.assertTrue(all('26.311' not in p.name and 'f2afef4' not in p.name for p in public))
        for source, target in zip(self.native, public):
            self.assertEqual((self.dist / source).read_bytes(), target.read_bytes())

    def test_publication_keeps_exactly_seven_public_files(self):
        public = layout.public_packages('v0.7.0')
        self.checksums()
        state = {'v0.7.0': {'assets': [{'name': 'old-core.tar.gz'}]}, 'components-v0.7.0': {'assets': []}}
        events = []
        def gh(*args):
            action, tag = args[1], args[2]
            if action == 'upload':
                files = [Path(p) for p in args[args.index('--clobber') + 1:]]
                state[tag]['assets'] = [{'name': p.name, 'size': p.stat().st_size, 'digest': 'sha256:' + layout.sha256(p)} for p in files] + [a for a in state[tag]['assets'] if a['name'] not in {p.name for p in files}]
                events.append(('upload', tag, len(files)))
            elif action == 'delete-asset':
                self.assertIn(('upload', 'components-v0.7.0', 22), events)
                self.assertIn(('upload', 'v0.7.0', 7), events)
                state[tag]['assets'] = [a for a in state[tag]['assets'] if a['name'] != args[3]]
            return ''
        with patch.object(layout, 'gh', side_effect=gh), patch.object(layout, 'release', side_effect=lambda tag: state[tag]):
            layout.publish('v0.7.0')
        self.assertEqual({a['name'] for a in state['v0.7.0']['assets']}, {self.archive.name, *(p.name for p in public)})
        self.assertEqual(len(state['components-v0.7.0']['assets']), 22)

    def test_checksum_failure_prevents_remote_changes(self):
        layout.public_packages('v0.7.0')
        self.checksums()
        (self.dist / self.native[0]).write_bytes(b'changed after checksum creation')
        with patch.object(layout, 'gh') as gh, self.assertRaises(RuntimeError):
            layout.publish('v0.7.0')
        gh.assert_not_called()

    def test_mismatched_version_is_rejected(self):
        with self.assertRaises(RuntimeError):
            layout.public_packages('v0.7.1')


if __name__ == '__main__':
    unittest.main()
