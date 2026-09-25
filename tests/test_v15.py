import io
import json
from pathlib import Path
import tempfile
import threading
import unittest
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from engine.model import Scope, atomic_json, finding, validate_config
from engine.worker import Run
from engine.server import Manager
from engine.templates import select, manifest

class Fixture(BaseHTTPRequestHandler):
    seen = []
    def log_message(self, *args): pass
    def do_GET(self):
        type(self).seen.append((self.path, self.headers.get('Authorization')))
        paths = {
            '/': ('text/html', '<title>Fixture</title><script src="/assets/app.js"></script><input name="search"><a href="/catalog?q=1">Catalog</a>'),
            '/robots.txt': ('text/plain', 'User-agent: *\nDisallow: /private-route'),
            '/openapi.json': ('application/json', '{"openapi":"3.0.0","paths":{"/api/inventory":{}}}'),
            '/assets/app.js': ('text/javascript', 'const endpoint="/api/from-script";'),
        }
        kind, body = paths.get(self.path, ('text/html', '<title>Soft 404</title>Page not found'))
        data = body.encode()
        self.send_response(200)
        self.send_header('Content-Type', kind)
        self.send_header('Server', 'nginx')
        self.send_header('Content-Length', str(len(data)))
        if self.headers.get('Origin'):
            self.send_header('Access-Control-Allow-Origin', self.headers['Origin'])
            self.send_header('Access-Control-Allow-Credentials', 'true')
        self.end_headers(); self.wfile.write(data)

class V15Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = ThreadingHTTPServer(('127.0.0.1', 0), Fixture)
        threading.Thread(target=cls.site.serve_forever, daemon=True).start()
        cls.url = f'http://127.0.0.1:{cls.site.server_port}/'
    @classmethod
    def tearDownClass(cls): cls.site.shutdown(); cls.site.server_close()

    def test_multi_origin_scope_and_subdomain_boundary(self):
        scope = Scope('https://example.test', ['http://another.test:8080'], True, [8443], ['/logout'])
        for url in ('https://api.example.test/a', 'https://a.b.example.test', 'http://another.test:8080/x', 'https://example.test:8443'):
            self.assertTrue(scope.contains(url), url)
        for url in ('https://example.test.evil.test', 'https://otherexample.test', 'http://example.test', 'https://example.test:444', 'https://example.test/logout/now'):
            self.assertFalse(scope.contains(url), url)
        self.assertFalse(Scope('https://example.test').contains('https://api.example.test'))

    def test_bad_config_does_not_crash_api(self):
        for item in ({'tools': 42}, {'stage_budgets': []}, {'stage_budgets': {'dns': None}}, {'headers': 'broken line'}, {'headers': {'Host':'other.test'}}, {'nuclei_ids': ['../../escape']}, {'ports':[0]}):
            with self.subTest(item=item), self.assertRaises(ValueError): validate_config({'target':self.url, **item})

    def test_recon_assets_soft404_auth_and_exports(self):
        secret = 'Bearer fixture-session-secret'
        with tempfile.TemporaryDirectory() as folder:
            manager = Manager(folder, launcher=lambda *_: None)
            job = manager.create({'target':self.url, 'tools':['dns','ports','webprobe','discovery'], 'rps':50, 'headers':{'Authorization':secret}, 'max_urls':100})
            result = Run(manager.path(job)).execute()
            self.assertEqual(result['status'], 'completed', result['stages'])
            for path in ('/private-route', '/api/inventory', '/api/from-script'):
                self.assertIn(self.url.rstrip('/')+path, result['urls'])
            self.assertNotIn(self.url+'admin', result['urls'])
            self.assertTrue(any(a['kind']=='service' for a in result['assets']))
            self.assertTrue(any(a['kind']=='dns' for a in result['assets']))
            self.assertTrue(any('nginx' in a.get('technologies',[]) for a in result['assets']))
            self.assertTrue(any(f['tool']=='webprobe' and f['severity']=='medium' for f in result['findings']))
            self.assertTrue(all(value==secret for path,value in Fixture.seen))
            (manager.path(job)/'synthetic.log').write_text('Authorization: '+secret)
            with zipfile.ZipFile(io.BytesIO(manager.export(job))) as pack:
                self.assertTrue({'report.json','report.html','findings.csv','report.sarif'}.issubset(pack.namelist()))
                for name in pack.namelist(): self.assertNotIn(secret.encode(),pack.read(name),name)
                self.assertEqual(json.loads(pack.read('report.sarif'))['version'],'2.1.0')

    def test_resume_reuses_completed_stage(self):
        launches=[]
        with tempfile.TemporaryDirectory() as folder:
            manager=Manager(folder, launcher=lambda *args:launches.append(args))
            job=manager.create({'target':self.url,'tools':['recon','ports']})
            path=manager.path(job)
            report=manager.report(job)
            report.update(status='partial',stages=[{'tool':'recon','status':'completed'},{'tool':'ports','status':'timeout'}])
            report['findings']=[finding('recon','Preserved',self.url,'original')]
            atomic_json(path/'report.json',report)
            (path/'cancel').touch()
            manager.resume(job)
            self.assertFalse((path/'cancel').exists())
            result=Run(path).execute()
            self.assertEqual(result['status'],'completed')
            self.assertTrue(result['stages'][0]['reused'])
            self.assertEqual(result['findings'][0]['title'],'Preserved')
            self.assertEqual(len(launches),2)

    def test_csv_cannot_execute_formula(self):
        from engine.reports import csv_report
        result=csv_report({'findings':[{'title':'=HYPERLINK("https://evil.invalid")'}]})
        self.assertIn("'=HYPERLINK",result)

    def test_templates_selection_is_pinned(self):
        if not manifest()['count']:self.skipTest('Run prepare_templates.py')
        rows=select({'nuclei_ids':['git-config']})
        self.assertEqual(len(rows),1)
        self.assertEqual(rows[0]['id'],'git-config')
        self.assertEqual(len(rows[0]['sha256']),64)
        with self.assertRaises(ValueError):select({'nuclei_ids':['nonexistent-fixture-template']})
        self.assertTrue(all(r['severity']=='high' for r in select({'nuclei_preset':'all','nuclei_severities':['high']})))

if __name__=='__main__':unittest.main()
