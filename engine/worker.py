import json
import os
from pathlib import Path
import sys
import threading
import time
import traceback
from urllib.parse import urlsplit, parse_qsl
from . import builtin
from .adapters import inventory, run_tool
from .model import Scope, PROFILES, VERSION, atomic_json, canonical_url, plain, public_config, safe_join, secret_values
from .proxy import start as start_proxy

class Cancelled(BaseException): pass
class StageTimeout(BaseException): pass

class Run:
    def __init__(self, folder, native_dir=''):
        self.folder=Path(folder).resolve()
        self.config=json.loads((self.folder/'config.json').read_text(encoding='utf-8'))
        c=self.config
        self.scope=Scope(c['target'],c.get('targets',[]),c.get('include_subdomains',False),c.get('ports',[]),c.get('exclude_paths',[]))
        self.native_dir=native_dir
        self.cache_dir=(self.folder.parent if self.folder.parent.name=='scans' else self.folder)/'runtime'
        self.captured_requests=[]
        capture=self.folder/'captured-requests.json'
        if c.get('_resume') and capture.exists():
            self.captured_requests=json.loads(capture.read_text(encoding='utf-8'))
        previous={}
        if c.get('_resume') and (self.folder/'report.json').exists():
            previous=json.loads((self.folder/'report.json').read_text(encoding='utf-8'))
        self.urls=previous.get('urls',list(self.scope.targets))
        self.url_set=set(self.urls)
        self.findings=previous.get('findings',[])
        self.ids={f['id'] for f in self.findings}
        self.assets=previous.get('assets',[])
        self.asset_index={(a['kind'],a['key']):a for a in self.assets}
        self.hosts=list(self.scope.hosts)
        for a in self.assets:
            if a['kind']=='domain' and a['key'] not in self.hosts:self.hosts.append(a['key'])
        self.lock=threading.RLock()
        self.rate_lock=threading.Lock()
        self.last_request=0.0
        self.deadline=float('inf')
        self.completed={s['tool']:s for s in previous.get('stages',[]) if s['status']=='completed' and previous.get('version',VERSION)==VERSION and s['tool']!='verify'}
        self.state={'id':self.folder.name,'version':VERSION,'status':'running','created':previous.get('created',time.time()),
                    'target':self.scope.target,'config':public_config(c),'stages':[],'findings':self.findings,'urls':self.urls,
                    'assets':self.assets,'metrics':previous.get('metrics',{'http_requests':0}), 'resumed':bool(previous),
                    'tasks':previous.get('tasks',[])}
        from .templates import coverage
        self.state['coverage']=coverage(c)
        self.done=threading.Event()
        for url in self.urls:
            self.asset('url',url,url=url,source='seed')

    def persist(self):
        with self.lock:
            self.state.update(findings=self.findings,urls=self.urls,assets=self.assets,heartbeat=time.time())
            atomic_json(self.folder/'report.json',self.state)

    def heartbeat(self):
        while not self.done.wait(2):self.persist()

    def check(self):
        if (self.folder/'cancel').exists():raise Cancelled()
        if time.monotonic()>self.deadline:raise StageTimeout()

    def request(self,url,timeout=10,headers=None,method='GET'):
        self.pace()
        with self.lock:self.state['metrics']['http_requests']=self.state['metrics'].get('http_requests',0)+1
        return builtin.request(self.scope,url,timeout,headers={**self.config.get('headers',{}),**(headers or {})},method=method)

    def active_hosts(self):
        return [h for h in self.hosts if self.scope.host_allowed(h)][:self.config.get('max_hosts',40)]

    def add_host(self,host,source):
        import re
        host=str(host).lower().rstrip('.')
        if not re.fullmatch(r'[a-z0-9.-]+',host) or not any(host==h or host.endswith('.'+h) for h in self.scope.hosts):return
        with self.lock:
            if host not in self.hosts and len(self.hosts)<2000:self.hosts.append(host)
            self.asset('domain',host,host=host,source=source,in_scope=self.scope.host_allowed(host))

    def asset(self,kind,key,**details):
        with self.lock:
            identity=(kind,key)
            if identity in self.asset_index:
                row=self.asset_index[identity]
                if 'source' in details:
                    row['sources']=sorted(set(row.get('sources',[row.get('source','')])+[details['source']]))
                row.update(details)
            elif len(self.assets)<60000:
                row={'kind':kind,'key':key,**details}
                self.asset_index[identity]=row;self.assets.append(row)

    def add_url(self,url,source='tool'):
        if self.scope.contains(url):
            value=canonical_url(url)
            with self.lock:
                if value not in self.url_set and len(self.urls)<self.config['max_urls']:
                    self.urls.append(value);self.url_set.add(value)
                if value in self.url_set:self.asset('url',value,url=value,source=source)
                for key,_ in parse_qsl(urlsplit(value).query,keep_blank_values=True):
                    self.asset('parameter',value.split('?')[0]+'|'+key,url=value.split('?')[0],name=key,source='query')

    def capture_request(self, record):
        if not self.scope.contains(record['url']):return
        with self.lock:
            if len(self.captured_requests)<100 and record not in self.captured_requests:
                self.captured_requests.append(record)
                atomic_json(self.folder/'captured-requests.json',self.captured_requests)

    def pace(self):
        self.check()
        with self.rate_lock:
            wait=1/self.config['rps']-(time.monotonic()-self.last_request)
            if wait>0:time.sleep(wait)
            self.last_request=time.monotonic()
        self.check()

    def add_link(self,base,reference,source='tool'):
        url=safe_join(base,reference)
        if url:self.add_url(url,source=source)

    def redact(self,text):
        text=plain(text)
        for value in secret_values(self.config):text=text.replace(value,'[скрыто]')
        return text

    def add(self,item):
        with self.lock:
            item['evidence']=self.redact(item['evidence'])
            if item['id'] not in self.ids:
                self.ids.add(item['id']);self.findings.append(item)

    def log(self,tool,line):
        path=self.folder/(tool+'.log')
        with self.lock:
            if not path.exists() or path.stat().st_size<10*1024*1024:
                with path.open('a',encoding='utf-8') as file:file.write(self.redact(line)[:16000]+'\n')

    def progress(self,**values):
        with self.lock:
            if self.state['stages']:self.state['stages'][-1].update(values)

    def execute(self):
        from .workflow import Scheduler
        server,self.proxy_url=start_proxy(self.scope)
        threading.Thread(target=self.heartbeat,daemon=True).start()
        available=inventory(self.native_dir)
        self.state['inventory']=available
        try:
            Scheduler(self,available).execute()
        finally:
            self.done.set();server.shutdown();server.server_close()
            self.state['finished']=time.time();self.persist()
        return self.state

def run(folder,native_dir=''):return Run(folder,native_dir).execute()

if __name__=='__main__':run(sys.argv[1],sys.argv[2] if len(sys.argv)>2 else '')
