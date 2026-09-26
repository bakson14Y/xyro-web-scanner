import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

from engine import adapters, templates
from engine.healthchecks import run as healthchecks
from engine.model import atomic_json, safe_join, validate_config
from engine.server import Manager
from engine.worker import Run, StageTimeout


class RuntimeFixTests(unittest.TestCase):
    def worker(self,folder):
        atomic_json(Path(folder)/'config.json',validate_config({'target':'http://127.0.0.1:12345/api/one',
                    'tools':['arjun'],'rps':50}))
        return Run(folder)

    def test_real_http_tls_scope_and_timeout_regressions(self):
        result=healthchecks()
        self.assertTrue(result)
        self.assertTrue(all(value is True for value in result.values()),result)

    def test_malformed_extracted_links_are_not_targets(self):
        base='https://fixture.invalid/'
        for candidate in ('https://[broken','//[broken','javascript:alert(1)','https://u:p@fixture.invalid',None):
            self.assertIsNone(safe_join(base,candidate),candidate)
        self.assertEqual(safe_join(base,'/api?q=1#ignored'),base+'api?q=1')

    def test_arjun_preserves_partial_findings_and_resumes_remaining_routes(self):
        with tempfile.TemporaryDirectory() as folder:
            run=self.worker(folder)
            run.add_url('http://127.0.0.1:12345/api/two?q=1')
            for value in ('theme.css','bundle.js','logo.png'):
                run.add_url('http://127.0.0.1:12345/'+value)
            routes=adapters.parameter_targets(run)
            self.assertEqual(len(routes),2)
            called=[]
            def execute(*args,**kwargs):
                route=sys.argv[sys.argv.index('-u')+1]
                output=Path(sys.argv[sys.argv.index('-oJ')+1])
                output.write_text(json.dumps({route:{'params':['fixture_parameter']}}))
                called.append(route)
                if len(called)==2:raise StageTimeout()
                return {'xyro_completed':True}
            with patch('engine.adapters.runpy.run_module',side_effect=execute):
                with self.assertRaises(StageTimeout):adapters.run_tool(run,'arjun')
            self.assertEqual({f['url'] for f in run.findings},set(routes))
            saved=json.loads((Path(folder)/'arjun-progress.json').read_text())
            self.assertEqual(saved['completed'],[called[0]])
            run.config['_resume']=True
            def finish(*args,**kwargs):
                called.append(sys.argv[sys.argv.index('-u')+1])
                return {'xyro_completed':True}
            with patch('engine.adapters.runpy.run_module',side_effect=finish):
                adapters.run_tool(run,'arjun')
            self.assertEqual(called,[routes[0],routes[1],routes[1]])
            self.assertEqual(set(json.loads((Path(folder)/'arjun-progress.json').read_text())['completed']),set(routes))

    def test_resume_budget_is_validated_without_discarding_results(self):
        with tempfile.TemporaryDirectory() as folder:
            manager=Manager(folder,launcher=lambda *_:None)
            job=manager.create({'target':'https://example.invalid','tools':['arjun']})
            report=manager.report(job);report['status']='partial'
            atomic_json(manager.path(job)/'report.json',report)
            original=(manager.path(job)/'config.json').read_bytes()
            with self.assertRaises(ValueError):manager.resume(job,14)
            self.assertEqual((manager.path(job)/'config.json').read_bytes(),original)
            manager.resume(job,900)
            self.assertEqual(json.loads((manager.path(job)/'config.json').read_text())['stage_timeout'],900)
            self.assertEqual(manager.report(job)['config']['stage_timeout'],900)

    def test_katana_timeout_keeps_urls_and_does_not_recrawl_all_discovered_urls(self):
        with tempfile.TemporaryDirectory() as folder:
            run=self.worker(folder);run.proxy_url='http://127.0.0.1:11111'
            run.add_url('http://127.0.0.1:12345/archive/page')
            def timeout(worker,tool,args,**kwargs):
                seeds=Path(args[args.index('-list')+1]).read_text().splitlines()
                self.assertEqual(seeds,run.scope.targets)
                self.assertEqual(args[args.index('-mdp')+1],str(run.config['max_urls']))
                (run.folder/'katana.log').write_text(json.dumps({'request':{'endpoint':'http://127.0.0.1:12345/found'}})+'\n')
                raise StageTimeout()
            with patch('engine.adapters.native',side_effect=timeout):
                with self.assertRaises(StageTimeout):adapters.run_tool(run,'katana')
            self.assertIn('http://127.0.0.1:12345/found',run.urls)

    def test_snallygaster_timeout_keeps_already_reported_finding(self):
        with tempfile.TemporaryDirectory() as folder:
            run=self.worker(folder)
            def timeout(*args):
                print(json.dumps({'cause':'git_dir','url':'http://127.0.0.1:12345/.git/config'}))
                raise StageTimeout()
            with patch('engine.adapters.run_script',side_effect=timeout):
                with self.assertRaises(StageTimeout):adapters.run_tool(run,'snallygaster')
            self.assertEqual(run.findings[0]['title'],'git_dir')

    def test_pinned_ignore_file_is_installed_and_old_cache_repaired(self):
        if not templates.manifest().get('ignore_sha256'):self.skipTest('Prepare pinned templates first')
        with tempfile.TemporaryDirectory() as folder:
            root=templates.materialize(folder)
            config=templates.configure(folder,root)
            expected=templates.manifest()['ignore_sha256']
            self.assertEqual(hashlib.sha256((config/'.nuclei-ignore').read_bytes()).hexdigest(),expected)
            self.assertIn('nuclei-templates-version',json.loads((config/'.templates-config.json').read_text()))
            (root/'.nuclei-ignore').unlink()
            templates.materialize(folder)
            self.assertEqual(hashlib.sha256((root/'.nuclei-ignore').read_bytes()).hexdigest(),expected)


if __name__=='__main__':unittest.main()
