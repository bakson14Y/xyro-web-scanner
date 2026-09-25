import json
from pathlib import Path
import runpy
import tempfile
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from engine import builtin
from engine.adapters import inventory, python_context
from engine.model import Scope, atomic_json, canonical_url, validate_config
from engine.server import Manager, serve, render_html
from engine.worker import Run, Cancelled, StageTimeout
from engine.proxy import start as start_proxy

class Fixture(BaseHTTPRequestHandler):
    def log_message(self, *args): pass
    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(302); self.send_header('Location', 'http://not-in-scope.invalid/'); self.end_headers(); return
        body = b'<html><a href="/page?q=1">Page</a><a href="https://outside.invalid/">external</a></html>'
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Set-Cookie', 'session=do-not-export-this')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers(); self.wfile.write(body)

class EngineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.site = ThreadingHTTPServer(('127.0.0.1',0),Fixture)
        threading.Thread(target=cls.site.serve_forever,daemon=True).start()
        cls.url='http://127.0.0.1:'+str(cls.site.server_port)+'/'
    @classmethod
    def tearDownClass(cls): cls.site.shutdown(); cls.site.server_close()

    def test_url_validation(self):
        for value in ('file:///etc/passwd','https://user:secret@x.test','https://x.test:99999','https://x.test\\@evil.test','https://x.test/a\nb'):
            with self.subTest(value=value),self.assertRaises(ValueError):canonical_url(value)
        self.assertEqual(canonical_url('https://EXAMPLE.test:443/#x'),'https://example.test/')
        self.assertEqual(canonical_url('https://пример.рф/'),'https://xn--e1afmkfd.xn--p1ai/')

    def test_scope_origin_exact(self):
        scope=Scope('https://example.test/')
        self.assertTrue(scope.contains('https://example.test/page?a=b'))
        for value in ('https://example.test.evil.test','http://example.test','https://example.test:444','https://sub.example.test'):
            self.assertFalse(scope.contains(value))

    def test_redirect_cannot_escape(self):
        with self.assertRaises(ValueError):builtin.request(Scope(self.url),self.url+'redirect')

    def test_baseline_finds_header_cookie_without_secret(self):
        found=[];urls=[]
        builtin.run(Scope(self.url),{'max_urls':3,'rps':20},found.append,urls.append,lambda:None)
        self.assertTrue(any(x['title']=='Нет content-security-policy' for x in found))
        self.assertTrue(any('Атрибуты cookie' in x['title'] for x in found))
        self.assertNotIn('do-not-export-this',json.dumps(found))
        self.assertTrue(all(Scope(self.url).contains(u) for u in urls))

    def test_config_limits(self):
        with self.assertRaises(ValueError):validate_config({'target':self.url,'rps':999})
        with self.assertRaises(ValueError):validate_config({'target':self.url,'profile':'shell'})
        self.assertEqual(validate_config({'target':self.url})['profile'],'recon')

    def test_html_escapes_findings(self):
        report={'target':'<script>','status':'partial','stages':[], 'findings':[{'title':'<img src=x onerror=alert(1)>','evidence':'<script>'}]}
        output=render_html(report)
        self.assertNotIn('<script>',output); self.assertIn('&lt;script&gt;',output)

    def test_api_auth_origin_and_traversal(self):
        with tempfile.TemporaryDirectory() as folder:
            manager=Manager(folder,launcher=lambda *_:None)
            server,url=serve(manager)
            base,token=url.split('/#')
            auth={'Authorization':'Bearer '+token}
            try:
                with self.assertRaises(urllib.error.HTTPError) as cm:urllib.request.urlopen(base+'/api/info')
                self.assertEqual(cm.exception.code,401)
                req=urllib.request.Request(base+'/api/info',headers=auth)
                self.assertIn('tools',json.load(urllib.request.urlopen(req)))
                req=urllib.request.Request(base+'/api/info',headers={**auth,'Origin':'https://evil.invalid'})
                with self.assertRaises(urllib.error.HTTPError):urllib.request.urlopen(req)
                with self.assertRaises(ValueError):manager.path('../escape')
                with self.assertRaises(ValueError):manager.path('shell;id')
            finally:server.shutdown();server.server_close()

    def test_cancel_timeout_and_persistence(self):
        with tempfile.TemporaryDirectory() as folder:
            config=validate_config({'target':self.url})
            atomic_json(Path(folder)/'config.json',config)
            run=Run(folder)
            run.deadline=time.monotonic()-1
            with self.assertRaises(StageTimeout):run.check()
            (Path(folder)/'cancel').touch()
            with self.assertRaises(Cancelled):run.check()
            result=run.execute()
            self.assertEqual(result['status'],'cancelled')
            self.assertEqual(json.loads((Path(folder)/'report.json').read_text())['status'],'cancelled')

    def test_python_scope_guard_and_help(self):
        if not all(inventory()[t]['ready'] for t in ('arjun','ghauri','snallygaster','finalrecon')):
            self.skipTest('Install requirements.txt for the upstream compatibility tests')
        with tempfile.TemporaryDirectory() as folder:
            atomic_json(Path(folder)/'config.json',validate_config({'target':self.url}))
            run=Run(folder)
            import requests
            for tool,module in (('arjun','arjun.__main__'),('ghauri','ghauri.scripts.ghauri')):
                with python_context(run,tool,['--help']):
                    with self.assertRaises(SystemExit) as cm:runpy.run_module(module,run_name='__main__')
                    self.assertIn(cm.exception.code,(0,None))
            from engine.adapters import ROOT
            with python_context(run,'snallygaster',['--help']):
                with self.assertRaises(SystemExit) as cm:runpy.run_path(str(ROOT/'vendor/snallygaster/snallygaster'),run_name='__main__')
                self.assertIn(cm.exception.code,(0,None))
            with python_context(run,'finalrecon',[]):
                with self.assertRaises(ValueError):requests.get('http://outside.invalid/',timeout=1)
                import types,sys
                settings=types.ModuleType('settings');settings.log_file_path=str(Path(folder)/'finalrecon.log');sys.modules['settings']=settings
                from modules.headers import headers
                data={};headers(self.url,{'directory':folder,'format':'txt','file':folder+'/headers.txt'},data)
                self.assertIn('module-headers',data)

    def test_proxy_refuses_outside_connect(self):
        server,url=start_proxy(Scope(self.url))
        import http.client
        connection=http.client.HTTPConnection('127.0.0.1',server.server_port)
        try:
            connection.request('CONNECT','outside.invalid:443')
            self.assertEqual(connection.getresponse().status,403)
        finally:connection.close();server.shutdown();server.server_close()

if __name__=='__main__':unittest.main()
