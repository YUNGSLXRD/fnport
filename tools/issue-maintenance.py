#!/usr/bin/env python3
"""Publish reviewed issue replies with the Actions token, never personal auth."""
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess

ROOT = Path(__file__).resolve().parents[1]
REPO = 'YUNGSLXRD/fnport'
BOT = 'github-actions[bot]'
FOOTER = ('После 14 дней без активности бот автоматически закроет issue. '
          'Перед этим появится напоминание. Метки bug, keep-open и security '
          'исключают обращение из автоматического закрытия. '
          'Закрытие по неактивности не означает, что ошибка исправлена.')


def api(path, method='GET', data=None):
    command = ['gh', 'api', f'repos/{REPO}/{path}', '--method', method]
    if data is not None:
        command += ['--input', '-']
    output = subprocess.check_output(command, input=json.dumps(data) if data is not None else None, text=True)
    return json.loads(output) if output.strip() else None


def comments(number):
    output = subprocess.check_output(['gh', 'api', '--paginate', '--slurp',
                                     f'repos/{REPO}/issues/{number}/comments?per_page=100'], text=True)
    return [comment for page in json.loads(output) for comment in page]


def fingerprint(body, conversation):
    value = {'body': body, 'comments': [(author, text) for author, text in conversation]}
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True).encode()).hexdigest()


def post_as_bot(number, body):
    result = api(f'issues/{number}/comments', 'POST', {'body': body})
    if result['user']['login'] != BOT:
        # Fail closed if this script is accidentally given personal credentials.
        api(f'issues/comments/{result["id"]}', 'DELETE')
        raise RuntimeError('Comment identity is not github-actions[bot]; comment removed')
    return result


def welcome(event):
    issue = event['issue']
    if issue.get('pull_request'):
        return
    marker = '<!-- fnport-welcome:v1 -->'
    if any(marker in comment['body'] for comment in comments(issue['number'])):
        return
    body = (ROOT / '.github/ISSUE_REPLY.md').read_text().strip() + '\n\n' + marker
    result = post_as_bot(issue['number'], body)
    print(f'Welcomed #{issue["number"]}: {result["html_url"]}', flush=True)


def reply_batch(batch):
    if not re.fullmatch(r'\d{4}-\d{2}-\d{2}', batch):
        raise RuntimeError('Invalid prepared reply batch ID')
    entries = json.loads((ROOT / '.github/issue-replies' / (batch + '.json')).read_text())
    skipped = []
    for entry in entries:
        number = entry['number']
        issue = api(f'issues/{number}')
        if issue['state'] != 'open':
            print(f'Skipped #{number}: already closed', flush=True)
            continue
        marker = f'<!-- fnport-reviewed-reply:{batch}:{number} -->'
        conversation = comments(number)
        bot_comment = next((c for c in conversation if c['user']['login'] == BOT and marker in c['body']), None)
        original = entry.get('original_comment')
        original_id = original['id'] if original else None
        current_original = next((c for c in conversation if c['id'] == original_id), None)
        if current_original and (current_original['user']['login'] != original['author'] or
                                 current_original['body'].strip() != original['body'].strip()):
            skipped.append(number)
            print(f'Skipped #{number}: original comment was edited', flush=True)
            continue
        if bot_comment is None:
            if not current_original:
                current = [(c['user']['login'], c['body']) for c in conversation
                           if c['user']['login'] != BOT]
                if fingerprint(issue['body'], current) != entry['fingerprint']:
                    skipped.append(number)
                    print(f'Skipped #{number}: new discussion requires review', flush=True)
                    continue
            body = entry['body'].strip() + '\n\n---\n\n' + FOOTER + '\n\n' + marker
            bot_comment = post_as_bot(number, body)
        # Migrate only the exact comments from the interrupted batch, after a
        # verified bot replacement exists. Never touch earlier maintainer replies.
        if current_original:
            api(f'issues/comments/{original_id}', 'DELETE')
        print(f'#{number}: {bot_comment["html_url"]}', flush=True)
    if skipped:
        raise RuntimeError('Fresh review required for issues: ' + ', '.join(map(str, skipped)))


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != REPO or not os.environ.get('GH_TOKEN'):
        raise RuntimeError('This script only runs inside this repository with an Actions token')
    event = json.loads(Path(os.environ['GITHUB_EVENT_PATH']).read_text())
    batch = os.environ.get('REPLY_BATCH', '')
    if os.environ['GITHUB_EVENT_NAME'] == 'issues' and event.get('action') == 'opened':
        welcome(event)
    elif os.environ['GITHUB_EVENT_NAME'] == 'workflow_dispatch' and batch:
        reply_batch(batch)
    else:
        raise RuntimeError('Unsupported event')


if __name__ == '__main__':
    main()
