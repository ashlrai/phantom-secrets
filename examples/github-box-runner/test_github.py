"""Hermetic contract tests with synthetic sessions, fake curl, and loopback HTTP."""
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
import unittest

SCRIPT = Path(__file__).with_name('github.sh')


class GithubClient(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.log = self.root / 'requests'
        self.env = dict(HOME=str(self.root),
                        PATH=str(self.root) + os.pathsep + os.environ.get('PATH', os.defpath),
                        GITHUB_TOKEN_BASE_URL='http://127.0.0.1:9999/github_api/_phantom/test-session/',
                        PHANTOM_PROXY_TOKEN='test-session', LOG=str(self.log))
        curl = self.root / 'curl'
        curl.write_text('''#!/usr/bin/env python3
import json, os, sys
from pathlib import Path
config = sys.stdin.read()
import atexit
atexit.register(lambda: print('200'))
with open(os.environ['LOG'], 'a') as log:
    log.write(json.dumps({'args':sys.argv[1:], 'config':config}) + '\\n')
if os.environ.get('REPLY'):
    print(os.environ['REPLY'])
    sys.exit(0)
if os.environ.get('FAIL'):
    print('sensitive diagnostics', file=sys.stderr)
    sys.exit(22)
if '/graphql"' in config and os.environ.get('GQL_REPLY'):
    print(os.environ['GQL_REPLY'])
elif '/graphql"' in config:
    print('{"errors":[{"message":"denied"}]}' if os.environ.get('GQL_ERROR') else '{"data":{"enablePullRequestAutoMerge":{"pullRequest":{"number":42}}}}')
elif '/pulls/42"' in config:
    print('{"node_id":"PR_fake"}')
elif 'update-branch' in config:
    print('{}')
else:
    print('[{"number":42,"title":"Example","state":"open","head":{"sha":"abc"}}]')
''')
        curl.chmod(0o755)

    def run_client(self, *args, ok=True):
        result = subprocess.run(['bash', str(SCRIPT), *args], env=self.env,
                                capture_output=True, text=True)
        self.assertEqual(result.returncode == 0, ok, result.stderr)
        self.assertNotIn('test-session', result.stdout + result.stderr)
        self.assertNotIn('sensitive diagnostics', result.stdout + result.stderr)
        return result

    def requests(self):
        return [json.loads(line) for line in self.log.read_text().splitlines()]

    def test_list_and_transport(self):
        result = self.run_client('owner/repo', 'list', '2')
        self.assertEqual(json.loads(result.stdout)[0]['head_sha'], 'abc')
        req = self.requests()[0]
        self.assertIn('per_page=100&page=2', req['config'])
        self.assertEqual(req['args'][0], '-q')
        self.assertIn('--fail', req['args'])
        self.assertNotIn('--location', req['args'])
        self.assertNotIn('test-session', ' '.join(req['args']))
        self.assertNotIn('Authorization', req['config'])

    def test_real_curl_and_redirect_refusal(self):
        class Handler(BaseHTTPRequestHandler):
            redirect = False
            paths = []

            def do_GET(self):
                self.paths.append(self.path)
                self.send_response(302 if self.redirect else 200)
                if self.redirect:
                    self.send_header('Location', '/must-not-follow')
                self.end_headers()
                self.wfile.write(b'[]')

            def log_message(self, *_args):
                pass

        with HTTPServer(('127.0.0.1', 0), Handler) as server:
            worker = threading.Thread(target=server.serve_forever, daemon=True)
            worker.start()
            try:
                self.env['PATH'] = os.environ.get('PATH', os.defpath)
                self.env['GITHUB_TOKEN_BASE_URL'] = (
                    f'http://127.0.0.1:{server.server_port}/github_api')
                # A hostile curlrc must not alter the request or enable tracing.
                (self.root / '.curlrc').write_text('url = "http://127.0.0.1:1/"\n')
                self.run_client('owner/repo', 'list')
                Handler.redirect = True
                self.run_client('owner/repo', 'list', ok=False)
                self.assertEqual(len(Handler.paths), 2)
                self.assertTrue(all(path.startswith('/github_api/repos/owner/repo/pulls?')
                                    for path in Handler.paths))
            finally:
                server.shutdown()
                worker.join()

    def test_header_only(self):
        self.env['GITHUB_TOKEN_BASE_URL'] = 'http://127.0.0.1:9999/github_api'
        self.run_client('owner/repo', 'list')

    def test_update_pins_head(self):
        self.run_client('owner/repo', 'update-branch', '42', 'a' * 40)
        req = self.requests()[0]
        self.assertIn('/pulls/42/update-branch', req['config'])
        self.assertEqual(req['args'][req['args'].index('--request') + 1], 'PUT')
        self.assertEqual(json.loads(req['args'][-1]), {'expected_head_sha': 'a' * 40})

    def test_auto_merge(self):
        self.run_client('owner/repo', 'auto-merge', '42', 'SQUASH')
        reqs = self.requests()
        self.assertEqual(len(reqs), 2)
        self.assertIn('/graphql', reqs[1]['config'])
        payload = json.loads(reqs[1]['args'][-1])
        self.assertEqual(payload['variables'], {'id': 'PR_fake', 'method': 'SQUASH'})
        self.assertIn('enablePullRequestAutoMerge', payload['query'])

    def test_graphql_error_is_failure(self):
        self.env['GQL_ERROR'] = '1'
        self.run_client('owner/repo', 'auto-merge', '42', 'MERGE', ok=False)

    def test_http_error_stops_before_mutation(self):
        self.env['FAIL'] = '1'
        self.run_client('owner/repo', 'auto-merge', '42', 'MERGE', ok=False)
        self.assertEqual(len(self.requests()), 1)

    def test_malformed_or_missing_data_is_failure(self):
        for reply in ['not json', '{}', '{"node_id":null}', ' ']:
            self.env['REPLY'] = reply
            self.run_client('owner/repo', 'auto-merge', '42', 'MERGE', ok=False)
        self.assertEqual(len(self.requests()), 4)

    def test_graphql_missing_or_wrong_confirmation(self):
        for reply in [' ', '{}', '{"data":{"enablePullRequestAutoMerge":{"pullRequest":{"number":43}}}}']:
            self.env['GQL_REPLY'] = reply
            self.run_client('owner/repo', 'auto-merge', '42', 'MERGE', ok=False)

    def test_invalid_arguments_never_call_curl(self):
        for args in [('owner/repo', 'list', '0'), ('owner/repo?x', 'list'),
                     ('../repo', 'list'), ('owner/..', 'list'),
                     ('owner/repo', 'update-branch', '42', 'bad'),
                     ('owner/repo', 'auto-merge', '42', 'DELETE'),
                     ('owner/repo', 'list', '1', 'extra')]:
            self.run_client(*args, ok=False)
        self.assertFalse(self.log.exists())

    def test_invalid_session_never_calls_curl(self):
        for base in ['', 'https://api.github.com', 'http://127.0.0.1:1/other',
                     'http://127.0.0.1:1/github_api?x',
                     'http://127.0.0.1:1/github_api/_phantom/bad"/']:
            self.env['GITHUB_TOKEN_BASE_URL'] = base
            self.run_client('owner/repo', 'list', ok=False)
        self.env['GITHUB_TOKEN_BASE_URL'] = 'http://127.0.0.1:1/github_api'
        self.env['PHANTOM_PROXY_TOKEN'] = 'bad\nheader'
        self.run_client('owner/repo', 'list', ok=False)
        self.assertFalse(self.log.exists())


if __name__ == '__main__':
    unittest.main()
