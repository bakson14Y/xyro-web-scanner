"""Redirect regressions use only local HTTP servers; external destinations are never requested."""
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest.mock import patch

from engine import builtin
from engine.model import Scope, atomic_json, validate_config
from engine.worker import Run


class RedirectTests(unittest.TestCase):
    def setUp(self):
        self.seen = []
        seen = self.seen
        class Fixture(BaseHTTPRequestHandler):
            def log_message(self, *args): pass
            def do_GET(self):
                seen.append((self.server.server_port, self.path, dict(self.headers)))
                destination = self.server.redirects.get(self.path)
                self.send_response(302 if destination else 200)
                if destination:
                    self.send_header('Location', destination)
                    self.send_header('X-Response-Only', 'never-send-back')
                self.send_header('Content-Type', 'text/plain')
                self.end_headers()
                self.wfile.write(b'local fixture')
        self.sites = []
        for _ in range(2):
            site = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
            site.redirects = {}
            threading.Thread(target=site.serve_forever, daemon=True).start()
            self.sites.append(site)
        self.url = f'http://127.0.0.1:{self.sites[0].server_port}/'
        self.outside = f'http://127.0.0.1:{self.sites[1].server_port}/'

    def tearDown(self):
        for site in self.sites:
            site.shutdown()
            site.server_close()

    def test_relative_redirect_preserves_request_headers(self):
        self.sites[0].redirects = {'/start': 'middle', '/middle': '/final'}
        headers = {'Authorization': 'Bearer fixture', 'X-Test': 'session'}
        status, pairs, body, final = builtin.request(Scope(self.url), self.url+'start', headers=headers)
        self.assertEqual((status, body, final), (200, 'local fixture', self.url+'final'))
        self.assertEqual([p for _, p, _ in self.seen], ['/start', '/middle', '/final'])
        for _, _, sent in self.seen:
            self.assertEqual(sent['Authorization'], 'Bearer fixture')
            self.assertEqual(sent['X-Test'], 'session')
            self.assertNotIn('X-Response-Only', sent)
        self.assertEqual(headers, {'Authorization': 'Bearer fixture', 'X-Test': 'session'})

    def test_external_redirect_is_blocked_before_connection(self):
        self.sites[0].redirects['/start'] = self.outside
        with self.assertRaises(builtin.RedirectOutsideScope) as caught:
            builtin.request(Scope(self.url), self.url+'start')
        self.assertEqual(caught.exception.destination, self.outside)
        self.assertEqual(caught.exception.source, self.url+'start')
        self.assertEqual(caught.exception.status, 302)
        self.assertEqual(len(self.seen), 1)
        self.assertEqual(self.seen[0][0], self.sites[0].server_port)

    def test_recon_continues_other_seeds_and_reports_redirect(self):
        self.sites[0].redirects['/start'] = self.outside
        scope = Scope(self.url+'start', targets=[self.url+'other'])
        found, urls = [], []
        builtin.run(scope, {'max_urls': 3, 'rps': 50}, found.append, urls.append, lambda: None)
        self.assertIn(self.url+'other', urls)
        self.assertNotIn(self.outside, urls)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['title'], 'Редирект за пределы области')
        self.assertEqual(found[0]['severity'], 'info')
        self.assertEqual(found[0]['redirect_url'], self.outside)
        self.assertIn(self.outside, found[0]['remediation'])
        self.assertEqual([p for _, p, _ in self.seen], ['/start', '/other'])

    def test_explicit_second_origin_can_be_followed(self):
        self.sites[0].redirects['/start'] = self.outside
        scope = Scope(self.url, targets=[self.outside])
        self.assertEqual(builtin.request(scope, self.url+'start')[3], self.outside)
        self.assertEqual(len(self.seen), 2)

    def test_excluded_path_is_not_requested(self):
        self.sites[0].redirects['/start'] = '/logout'
        with self.assertRaises(builtin.RedirectOutsideScope):
            builtin.request(Scope(self.url, exclude_paths=['/logout']), self.url+'start')
        self.assertEqual([p for _, p, _ in self.seen], ['/start'])

    def test_https_redirect_does_not_expand_scope_implicitly(self):
        self.sites[0].redirects['/start'] = 'https://127.0.0.1/'
        with patch('engine.builtin.http.client.HTTPSConnection') as tls:
            with self.assertRaises(builtin.RedirectOutsideScope):
                builtin.request(Scope(self.url), self.url+'start')
            tls.assert_not_called()

    def test_worker_has_no_recon_error_or_traceback(self):
        self.sites[0].redirects['/start'] = self.outside
        with tempfile.TemporaryDirectory() as folder:
            config = validate_config({'target': self.url+'start', 'tools': ['recon', 'dns'], 'rps': 50})
            atomic_json(Path(folder)/'config.json', config)
            report = Run(folder).execute()
            self.assertEqual(report['status'], 'completed')
            self.assertEqual([s['status'] for s in report['stages']], ['completed', 'completed'])
            self.assertEqual(report['findings'][0]['redirect_url'], self.outside)
            self.assertFalse((Path(folder)/'recon.log').exists())


if __name__ == '__main__': unittest.main()
