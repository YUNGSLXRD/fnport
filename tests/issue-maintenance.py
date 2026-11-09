#!/usr/bin/env python3
import importlib.util
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('maintenance', ROOT / 'tools/issue-maintenance.py')
maintenance = importlib.util.module_from_spec(spec)
spec.loader.exec_module(maintenance)


class BotReplies(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(dir=ROOT / 'windows/dist')
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.batch_dir = self.root / '.github/issue-replies'
        self.batch_dir.mkdir(parents=True)
        self.original = {'id': 11, 'user': {'login': 'YUNGSLXRD'}, 'body': 'Reviewed answer'}
        self.marker = '<!-- fnport-reviewed-reply:2026-11-10:41 -->'
        self.entry = {'number': 41, 'body': 'Reviewed answer',
                      'fingerprint': maintenance.fingerprint('report', []),
                      'original_comment': {'id': 11, 'author': 'YUNGSLXRD', 'body': 'Reviewed answer'}}
        self.events = []

    def api(self, path, method='GET', data=None):
        if path == 'issues/41' and method == 'GET':
            return {'state': 'open', 'body': 'report'}
        if path == 'issues/41/comments' and method == 'POST':
            self.events.append('post-bot')
            return {'id': 22, 'user': {'login': maintenance.BOT}, 'body': data['body'], 'html_url': 'bot-reply'}
        if method == 'DELETE':
            self.events.append('delete-' + path.rsplit('/', 1)[-1])
            return None
        self.fail((path, method))

    def run_batch(self, conversation):
        (self.batch_dir / '2026-11-10.json').write_text(json.dumps([self.entry]))
        with patch.object(maintenance, 'ROOT', self.root), patch.object(maintenance, 'api', side_effect=self.api), patch.object(maintenance, 'comments', return_value=conversation):
            maintenance.reply_batch('2026-11-10')

    def test_replacement_is_verified_before_deletion(self):
        earlier = {'id': 9, 'user': {'login': 'YUNGSLXRD'}, 'body': 'Earlier answer'}
        self.run_batch([earlier, self.original])
        self.assertEqual(self.events, ['post-bot', 'delete-11'])

    def test_existing_bot_reply_is_not_duplicated(self):
        bot = {'id': 22, 'user': {'login': maintenance.BOT}, 'body': self.marker, 'html_url': 'bot-reply'}
        self.run_batch([bot])
        self.assertEqual(self.events, [])

    def test_edited_personal_comment_is_preserved(self):
        with self.assertRaises(RuntimeError):
            self.run_batch([{**self.original, 'body': 'Manually edited'}])
        self.assertEqual(self.events, [])

    def test_wrong_posting_identity_is_removed_without_deleting_original(self):
        def api(path, method='GET', data=None):
            if method == 'POST':
                return {'id': 33, 'user': {'login': 'YUNGSLXRD'}}
            if method == 'DELETE':
                self.events.append(path)
        with patch.object(maintenance, 'api', side_effect=api), self.assertRaises(RuntimeError):
            maintenance.post_as_bot(41, 'text')
        self.assertEqual(self.events, ['issues/comments/33'])

    def test_new_discussion_is_not_answered_with_old_draft(self):
        self.entry.pop('original_comment')
        with self.assertRaises(RuntimeError):
            self.run_batch([{'id': 12, 'user': {'login': 'reporter'}, 'body': 'New details'}])
        self.assertEqual(self.events, [])

    def test_personal_cli_environment_cannot_send(self):
        with patch.dict(os.environ, {'GITHUB_ACTIONS': 'false'}), patch.object(maintenance, 'api') as api, self.assertRaises(RuntimeError):
            maintenance.main()
        api.assert_not_called()


if __name__ == '__main__':
    unittest.main()
