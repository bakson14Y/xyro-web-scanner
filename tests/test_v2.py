import base64
import hashlib
import hmac
import io
import json
from pathlib import Path
import tempfile
import threading
import time
import unittest
from unittest.mock import patch
from xml.etree import ElementTree
import zipfile
from engine import templates, osint, authchecks
from engine.forms import capture
from engine.model import validate_config, atomic_json, finding, public_config, secret_values, TOOLS
from engine.nuclei_runner import burp_input
from engine.server import Manager
from engine.worker import Run, StageTimeout
from engine.workflow import targets_for, Scheduler, verify, TaskView

class V2Tests(unittest.TestCase):
    def worker(self,folder,**values):
        config=validate_config({'target':'https://fixture.invalid/','tools':['nuclei','dalfox'],
            'agent_mode':'fixed','agents':2,'rps':20,'concurrency':4,**values})
        atomic_json(Path(folder)/'config.json',config)
        return Run(folder)

    def test_scheduler_bounds_concurrency_and_resumes_only_incomplete_tasks(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder)
            for i in range(104):scan.add_url('https://fixture.invalid/path/'+str(i)+'?q=test')
            guard=threading.Lock();active=0;peak=0;called=[];failed=[]
            def execute(view,tool):
                nonlocal active,peak
                with guard:active+=1;peak=max(peak,active);called.append(view.task['id'])
                try:
                    time.sleep(.04)
                    if tool=='dalfox' and not failed:
                        failed.append(view.task['id']);raise StageTimeout()
                    view.add(finding(tool,'fixture',view.seed_targets[0],'fixture'))
                finally:
                    with guard:active-=1
            available={t:{'ready':True} for t in TOOLS}
            with patch('engine.adapters.run_tool',side_effect=execute):Scheduler(scan,available).execute()
            self.assertEqual(peak,2);self.assertEqual(scan.state['status'],'partial')
            self.assertEqual(len(scan.state['tasks']),4)
            completed={t['id'] for t in scan.state['tasks'] if t['status']=='completed'}
            self.assertEqual(len(completed),3)
            scan.persist();scan.config['_resume']=True;atomic_json(Path(folder)/'config.json',scan.config)
            resumed=Run(folder);called.clear()
            with patch('engine.adapters.run_tool',side_effect=lambda v,t:called.append(v.task['id'])):
                Scheduler(resumed,available).execute()
            self.assertEqual(called,failed)
            self.assertEqual(resumed.state['status'],'completed')
            self.assertEqual({t['id'] for t in resumed.state['tasks']},completed|set(failed))
            self.assertEqual(len(resumed.findings),len(scan.findings))

    def test_cancel_does_not_start_queued_tasks(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder);(Path(folder)/'cancel').touch()
            with patch('engine.adapters.run_tool') as execute:
                Scheduler(scan,{t:{'ready':True} for t in TOOLS}).execute()
            execute.assert_not_called();self.assertEqual(scan.state['status'],'cancelled')

    def test_static_urls_are_not_dalfox_inputs_and_dast_needs_input(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder)
            for url in ('a.css','a.png','manifest.webmanifest','api?q=test','api?q=other','page'):
                scan.add_url('https://fixture.invalid/'+url)
            self.assertFalse(any(x.endswith(('.css','.png','.webmanifest')) for x in targets_for(scan,'dalfox')))
            self.assertEqual(targets_for(scan,'dast'),['https://fixture.invalid/api?q=test'])

    def test_forms_capture_is_explicit_and_scope_limited(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder)
            html='<form action="/query" method="post"><input name="q" value="test"></form><form action="https://outside.invalid/"><input name="q"></form>'
            capture(scan,scan.scope.target,html)
            self.assertFalse(scan.captured_requests)
            self.assertEqual(scan.findings[0]['verification'],'context_required')
            scan.config['scan_forms']=True;capture(scan,scan.scope.target,html)
            self.assertEqual(scan.captured_requests,[{'url':'https://fixture.invalid/query','method':'POST','headers':{'Content-Type':'application/x-www-form-urlencoded'},'body':'q=test'}])
            self.assertEqual(targets_for(scan,'dast'),['https://fixture.invalid/query'])

    def test_burp_preserves_post_body_and_dedupes_url(self):
        with tempfile.TemporaryDirectory() as folder:
            file=Path(folder)/'requests.xml'
            count=burp_input(file,['https://fixture.invalid/api'],[{'url':'https://fixture.invalid/api','method':'POST','headers':{'Content-Type':'application/json'},'body':'{"q":"тест"}'}],{'Authorization':'Bearer fixture'})
            self.assertEqual(count,1)
            raw=base64.b64decode(ElementTree.parse(file).find('.//request').text)
            self.assertTrue(raw.startswith(b'POST /api HTTP/1.1'))
            self.assertIn(('Content-Length: '+str(len('{"q":"тест"}'.encode()))).encode(),raw)
            self.assertIn(b'authorization: Bearer fixture',raw)

    def test_censys_pagination_filters_unrelated_domains(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder,censys_token='fixture-token',censys_pages=2)
            seen=[]
            class Client:
                def search(self,query,cursor):
                    seen.append(cursor)
                    return {'hits':[{'host_v1':{'resource':{'ip':'192.0.2.3','dns':{'names':['sub.fixture.invalid','other.invalid']}}}}],
                            'next_page_token':'next' if len(seen)==1 else ''}
            osint.run(scan,Client())
            self.assertEqual(seen,['','next'])
            self.assertIn('sub.fixture.invalid',scan.hosts);self.assertNotIn('other.invalid',scan.hosts)
            self.assertFalse(scan.scope.host_allowed('192.0.2.3'))
            self.assertTrue(any(a['kind']=='osint' for a in scan.assets))

    def test_censys_partial_on_exhausted_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder,censys_token='fixture',targets=['https://second.invalid/'])
            scan.state['stages']=[{}]
            class Client:
                def search(self,*args):return {'hits':[],'next_page_token':''}
            osint.run(scan,Client())
            self.assertEqual(scan.state['stages'][0]['status'],'partial')

    def test_jwt_hmac_check_is_offline_and_does_not_expose_key(self):
        encode=lambda b:base64.urlsafe_b64encode(b).decode().rstrip('=')
        message=encode(b'{"alg":"HS256"}')+'.'+encode(b'{"sub":"fixture"}')
        token=message+'.'+encode(hmac.new(b'secret',message.encode(),hashlib.sha256).digest())
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder,headers={'Authorization':'Bearer '+token})
            authchecks.jwt_audit(scan)
            self.assertEqual(scan.findings[0]['verification'],'reproduced')
            self.assertNotIn(token,json.dumps(scan.findings))
            self.assertNotIn('secret',scan.findings[0]['evidence'])

    def test_role_comparison_uses_anonymous_control_and_two_role_b_reads(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder,headers={'Authorization':'Bearer owner'},auth_headers_b={'Authorization':'Bearer other'},
                             auth_urls=['https://fixture.invalid/private'],auth_marker='private-data')
            seen=[]
            def request(scope,url,timeout,headers):
                seen.append(headers)
                return (200,[],'private-data' if headers else 'login',url)
            with patch('engine.authchecks.builtin.request',side_effect=request):authchecks.run(scan)
            self.assertEqual(seen,[{'Authorization':'Bearer owner'},{},{'Authorization':'Bearer other'},{'Authorization':'Bearer other'}])
            self.assertEqual(scan.findings[0]['confidence'],'candidate')

    def test_nested_export_and_logs_redact_new_credentials(self):
        with tempfile.TemporaryDirectory() as folder:
            manager=Manager(folder,launcher=lambda *args:None)
            job=manager.create({'target':'https://fixture.invalid','tools':['censys'],'censys_token':'top-secret-token',
                                'auth_headers_b':{'Authorization':'Bearer role-b-secret'},'requests':[{'url':'https://fixture.invalid/api','method':'POST','body':'{"key":"body-secret"}'}]})
            task=manager.path(job)/'tasks'/'fixture';task.mkdir(parents=True)
            (task/'censys.log').write_text('top-secret-token role-b-secret body-secret')
            (manager.path(job)/'captured-requests.json').write_text('never-export-this')
            output=manager.export(job)
            with zipfile.ZipFile(io.BytesIO(output)) as archive:
                self.assertIn('tasks/fixture/censys.log',archive.namelist())
                self.assertNotIn('captured-requests.json',archive.namelist())
                text=''.join(archive.read(n).decode('utf-8') for n in archive.namelist())
                for secret in ('top-secret-token','role-b-secret','body-secret','never-export-this'):self.assertNotIn(secret,text)
            self.assertNotIn('top-secret-token',manager.logs(job,'censys'))

    def test_verification_resumes_remaining_findings(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder,tools=['verify'],verify_limit=1)
            for i in range(2):
                scan.add(finding('nuclei','fixture',f'https://fixture.invalid/{i}','match','high',template_id='git-config',verification='pending'))
            def repeat(view,mode):
                view.add(finding(mode,'fixture',view.seed_targets[0],'repeat',template_id='git-config'))
            available={t:{'ready':True} for t in TOOLS}
            with patch('engine.adapters.nuclei',side_effect=repeat):Scheduler(scan,available).execute()
            self.assertEqual([f['verification'] for f in scan.findings],['reproduced','pending'])
            self.assertEqual(scan.state['status'],'partial')
            scan.persist();scan.config['_resume']=True;atomic_json(Path(folder)/'config.json',scan.config)
            scan=Run(folder)
            with patch('engine.adapters.nuclei',side_effect=repeat):Scheduler(scan,available).execute()
            self.assertTrue(all(f['verification']=='reproduced' for f in scan.findings))
            scan.persist()
            scan=Run(folder)
            scan.add(finding('nuclei','new','https://fixture.invalid/third','match','high',template_id='git-config',verification='pending'))
            with patch('engine.adapters.nuclei',side_effect=repeat):Scheduler(scan,available).execute()
            self.assertEqual(scan.findings[-1]['verification'],'reproduced')

    def test_censys_resume_continues_cursor(self):
        with tempfile.TemporaryDirectory() as folder:
            scan=self.worker(folder,censys_token='fixture-token',censys_pages=1)
            seen=[]
            class Client:
                def search(self,query,cursor):
                    seen.append(cursor)
                    return {'hits':[],'next_page_token':'next' if not cursor else ''}
            osint.run(scan,Client())
            scan.config['_resume']=True;osint.run(scan,Client())
            self.assertEqual(seen,['','next'])

    def test_full_dast_tree_and_ssl_catalogue(self):
        m=templates.manifest()
        if not m.get('count'):self.skipTest('Prepare pinned catalogue')
        with zipfile.ZipFile(templates.DATA/'nuclei-templates.zip') as z:
            files={n for n in z.namelist() if n.endswith('.yaml') and n.startswith(('dast/vulnerabilities/','dast/cves/','ssl/'))}
        rows={r['path'] for r in m['templates']}
        self.assertTrue(files<=rows)
        self.assertEqual(m['dast_years'],['2018','2020','2021','2022','2024'])
        config=validate_config({'target':'https://fixture.invalid','tools':['dast','tls'],'nuclei_preset':'all'})
        self.assertTrue(templates.select(config,'dast'));self.assertEqual(len(templates.select(config,'tls')),38)
        headless=[r for r in m['templates'] if r['path'].startswith('dast/') and 'headless' in r['protocols']]
        self.assertTrue(headless);self.assertTrue(all(not r['supported'] for r in headless))
        self.assertTrue(any('Chromium' in key for row in templates.coverage(config) for key in row['reasons']))

if __name__=='__main__':unittest.main()
