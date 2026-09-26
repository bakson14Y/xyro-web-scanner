"""Bounded mechanical workers, dependency phases and durable task checkpoints."""
from concurrent.futures import ThreadPoolExecutor, as_completed
from contextlib import nullcontext
import hashlib
from itertools import zip_longest
import json
import math
from pathlib import Path
import threading
import time
import traceback
from urllib.parse import urlsplit, urlunsplit, parse_qsl
from .model import atomic_json, origin

PYTHON_TOOLS={'arjun','ghauri','snallygaster','finalrecon'}
PHASES=(('recon',),('subfinder','gau','censys'),('dns','ports'),('webprobe',),
        ('katana','cariddi'),('discovery','finalrecon','snallygaster'),('arjun',),
        ('nuclei','dast','tls','dalfox','ghauri','auth'),('verify',))


def dynamic_urls(scan):
    from .adapters import STATIC_SUFFIXES
    result=[];seen=set()
    for url in sorted(scan.urls,key=lambda u:(not bool(urlsplit(u).query),len(u),u)):
        p=urlsplit(url)
        if Path(p.path).suffix.lower() in STATIC_SUFFIXES | {'.webmanifest','.jsonld'}:continue
        shape=(p.scheme,p.netloc,p.path,tuple(sorted(k for k,v in parse_qsl(p.query,keep_blank_values=True))))
        if shape in seen:continue
        seen.add(shape);result.append(url)
    return result


def worker_count(scan):
    c=scan.config
    if c.get('agent_mode')=='off': return 1
    desired=c.get('agents',2)
    if c.get('agent_mode','auto')=='auto' and len(scan.urls)<50 and len(scan.active_hosts())<3: desired=1
    # Native processes need substantially more memory than Python task records.
    memory_mb=0
    try:
        for line in Path('/proc/meminfo').read_text().splitlines():
            if line.startswith('MemAvailable:'):memory_mb=int(line.split()[1])//1024;break
    except (OSError,ValueError):pass
    memory_cap=max(1,memory_mb//700) if memory_mb else 2 if scan.native_dir else 4
    return max(1,min(desired,4,memory_cap,c['rps'],c['concurrency']))


def targets_for(scan,tool):
    if tool in ('dalfox','dast'):
        urls=dynamic_urls(scan)
        if tool=='dast':
            urls=[u for u in urls if urlsplit(u).query]
            urls+= [r['url'] for r in scan.config.get('requests',[])]
            urls+= [r['url'] for r in getattr(scan,'captured_requests',[])]
        return list(dict.fromkeys(urls))
    if tool in ('nuclei','tls'):
        urls=list(scan.scope.targets)+[a['url'] for a in scan.assets if a['kind']=='web']
        result=[];seen=set();seed_origins={origin(u) for u in scan.scope.targets}
        for url in urls:
            if not scan.scope.contains(url) or (tool=='tls' and urlsplit(url).scheme!='https'):continue
            # Preserve explicit application base paths; discoveries dedupe origins.
            if tool=='tls':identity=origin(url)
            elif url in scan.scope.targets:identity=url
            else:
                if origin(url) in seed_origins:continue
                identity=origin(url)
            if identity not in seen:seen.add(identity);result.append(url)
        return result
    return list(scan.scope.targets)


class TaskView:
    def __init__(self,parent,task,stage,workers):
        self.parent,self.task,self.stage=parent,task,stage
        self.folder=parent.folder/'tasks'/task['id'];self.folder.mkdir(parents=True,exist_ok=True)
        self.config={**parent.config,'rps':max(1,parent.config['rps']//workers),
                     'concurrency':max(1,parent.config['concurrency']//workers)}
        self.seed_targets=task['targets']
        self.urls=task['targets'] if task['tool'] in ('dalfox','dast') else parent.urls
        self.cache_dir=parent.cache_dir
        self.deadline=stage['_deadline']

    def __getattr__(self,name):return getattr(self.parent,name)

    def check(self):
        from .worker import StageTimeout
        self.parent.check()
        if time.monotonic()>self.deadline:raise StageTimeout()

    def request(self,*args,**kwargs):
        self.check()
        result=self.parent.request(*args,**kwargs)
        self.check()
        return result

    def progress(self,**values):
        with self.parent.lock:
            self.task.update(values)
            tasks=[t for t in self.parent.state['tasks'] if t['tool']==self.task['tool']]
            for key in ('templates_total','templates_done','processed_pairs'):
                self.stage[key]=sum(t.get(key,0) for t in tasks)

    def log(self,tool,line):
        self.parent.log(tool,'['+self.task['id']+'] '+line)

    def add(self,item):
        item.setdefault('task_id',self.task['id'])
        self.parent.add(item)


class Scheduler:
    def __init__(self,scan,available):
        self.scan,self.available=scan,available
        self.python_lock=threading.Lock()
        self.saved={t['id']:t for t in scan.state.get('tasks',[])}
        scan.state['tasks']=[{**t,'reused':True} for t in self.saved.values() if t['tool'] in scan.completed]
        self.stages={}

    def persist(self):
        scan=self.scan
        with scan.lock:
            for tool,stage in self.stages.items():
                tasks=[t for t in scan.state['tasks'] if t['tool']==tool]
                if not tasks:continue
                stage['tasks_total']=len(tasks)
                stage['tasks_done']=sum(t['status']=='completed' for t in tasks)
                stage['targets_total']=sum(len(t['targets']) for t in tasks)
                stage['targets_done']=sum(len(t['targets']) for t in tasks if t['status']=='completed')
                stage['templates_total']=sum(t.get('templates_total',0) for t in tasks)
                stage['templates_done']=sum(t.get('templates_done',0) for t in tasks)
            scan.state['agents']['active']=sum(t['status']=='running' for t in scan.state['tasks'])
        scan.persist()

    def make_tasks(self,tool):
        scan=self.scan
        stage=self.stages[tool]
        targets=targets_for(scan,tool)
        if not targets:
            stage.update(status='skipped',detail='Нет HTTPS-целей' if tool=='tls' else 'Нет подходящих параметров / импортированных запросов')
            return []
        chunk=25 if tool=='dast' else 50 if tool=='dalfox' else 8 if tool in ('nuclei','tls') else max(1,len(targets))
        tasks=[]
        # Keep every chunk within one origin for native vulnerability tasks.
        groups={}
        for target in targets:
            key=origin(target) if tool in ('nuclei','dast','tls','dalfox') else 'all'
            groups.setdefault(key,[]).append(target)
        for group in groups.values():
            for i in range(0,len(group),chunk):
                subset=group[i:i+chunk]
                key=tool+'-'+hashlib.sha256(json.dumps(subset,sort_keys=True).encode()).hexdigest()[:16]
                old=self.saved.get(key,{})
                task={**old,'id':key,'tool':tool,'targets':subset,'status':'completed' if old.get('status')=='completed' and tool!='verify' else 'queued'}
                if task['status']=='completed':task['reused']=True
                scan.state['tasks'].append(task);tasks.append(task)
        return tasks

    def execute_task(self,task,workers):
        from .worker import Cancelled,StageTimeout
        from .adapters import run_tool
        from .recon import STAGES
        from . import builtin,osint,authchecks
        scan=self.scan;tool=task['tool'];stage=self.stages[tool]
        if task['status']=='completed':return
        gate=self.python_lock if tool in PYTHON_TOOLS else nullcontext()
        try:
            with gate:
                with scan.lock:
                    if '_deadline' not in stage:
                        stage['_deadline']=time.monotonic()+stage['budget'];stage['started']=time.time()
                    stage['status']='running';task.update(status='running',started=time.time())
                view=TaskView(scan,task,stage,workers)
                self.persist();view.check()
                if not self.available[tool]['ready']:
                    task.update(status='missing',error='Модуль не включён в сборку');return
                if tool=='recon':builtin.run(view.scope,view.config,view.add,view.add_url,view.check)
                elif tool=='censys':osint.run(view)
                elif tool=='auth':authchecks.run(view)
                elif tool=='verify':verify(view)
                elif tool in STAGES:STAGES[tool](view)
                else:run_tool(view,tool)
                if task['status']=='running':task['status']='completed'
        except Cancelled:task['status']='cancelled'
        except StageTimeout:
            task.update(status='timeout',error='Общий бюджет модуля исчерпан. Прогресс сохранён; увеличьте время и продолжите.')
        except (Exception,SystemExit) as exc:
            task.update(status='error',error=scan.redact(str(exc))[:1800]);scan.log(tool,traceback.format_exc())
        finally:
            task['finished']=time.time();self.persist()

    def execute(self):
        scan=self.scan;pipeline=scan.config['tools'];scan.state['pipeline']=pipeline
        scan.state['agents']={'mode':scan.config.get('agent_mode','auto'),'workers':1,'active':0,'kind':'deterministic'}
        for tool in pipeline:
            stage={'tool':tool,'status':'queued','budget':scan.config.get('stage_budgets',{}).get(tool,scan.config['stage_timeout'])}
            if tool in scan.completed:stage={**scan.completed[tool],'reused':True}
            self.stages[tool]=stage;scan.state['stages'].append(stage)
        for phase in PHASES:
            if (scan.folder/'cancel').exists():break
            tools=[t for t in phase if t in self.stages and self.stages[t]['status']!='completed']
            groups=[self.make_tasks(t) for t in tools]
            tasks=[t for pack in zip_longest(*groups) for t in pack if t is not None] if groups else []
            workers=worker_count(scan)
            scan.state['agents']['workers']=workers
            self.persist()
            with ThreadPoolExecutor(max_workers=workers,thread_name_prefix='XYRO-agent') as pool:
                futures=[pool.submit(self.execute_task,t,workers) for t in tasks]
                for future in as_completed(futures):future.result()
            for tool in tools:
                stage=self.stages[tool]
                group=[t for t in tasks if t['tool']==tool]
                if not group:continue
                errors=[t for t in group if t['status'] not in ('completed','skipped')]
                stage['status']='cancelled' if any(t['status']=='cancelled' for t in group) else 'partial' if errors else 'skipped' if all(t['status']=='skipped' for t in group) else 'completed'
                stage['finished']=time.time()
                if errors:stage['error']='; '.join(dict.fromkeys(t.get('error',t['status']) for t in errors))[:1800]
                details=[t.get('detail','') for t in group if t.get('detail')]
                if details:stage['detail']='; '.join(dict.fromkeys(details))[:1800]
            self.persist()
        for stage in self.stages.values():
            stage.pop('_deadline',None)
            if stage['status']=='queued':stage['status']='cancelled'
        for task in scan.state['tasks']:
            if task['status']=='queued':task['status']='cancelled'
        scan.state['status']='cancelled' if (scan.folder/'cancel').exists() else 'completed' if all(s['status']=='completed' for s in self.stages.values()) else 'partial'
        return scan.state


def verify(scan):
    from .adapters import nuclei
    from .worker import StageTimeout,Cancelled
    candidates=[f for f in scan.findings if f.get('template_id') and f['tool'] in ('nuclei','dast','tls') and f.get('verification') not in ('reproduced','not_reproduced','not_applicable')]
    candidates.sort(key=lambda f: ('critical','high','medium','low','info').index(f['severity']))
    limit=scan.config.get('verify_limit',30)
    scan.progress(targets_total=len(candidates),targets_done=0)
    for index,item in enumerate(candidates):
        if index>=limit:
            item['verification']='pending';continue
        scan.check()
        original_folder,original_config,original_targets=scan.folder,scan.config,scan.seed_targets
        matches=[]
        original_add=scan.add
        original_progress=scan.progress
        progress={}
        try:
            scan.folder=original_folder/item['id'];scan.folder.mkdir(exist_ok=True)
            scan.config={**original_config,'nuclei_ids':[item['template_id']],'_resume':False}
            scan.seed_targets=[item.get('scan_target',item['url'])]
            scan.add=matches.append
            scan.progress=lambda **values:progress.update(values)
            nuclei(scan,mode=item['tool'])
            item['verification']='not_applicable' if progress.get('status')=='skipped' else 'reproduced' if any(f.get('template_id')==item['template_id'] and f.get('matcher','')==item.get('matcher','') for f in matches) else 'not_reproduced'
            item['verification_at']=time.time()
        except (StageTimeout,Cancelled):
            item['verification']='pending';raise
        except Exception as exc:
            item['verification']='error';item['verification_error']=scan.redact(str(exc))[:500]
        finally:
            scan.folder,scan.config,scan.seed_targets=original_folder,original_config,original_targets
            scan.add=original_add
            scan.progress=original_progress
        scan.progress(targets_done=index+1);scan.persist()
    if len(candidates)>limit:scan.progress(status='partial',detail=f'Перепроверено {limit}; ещё {len(candidates)-limit} ожидают следующего продолжения')
