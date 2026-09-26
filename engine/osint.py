"""Censys Platform v3, opt-in credentials, domain-bound passive inventory."""
import http.client
import ipaddress
import json
import ssl
from urllib.parse import urlencode
import certifi


class CensysClient:
    def __init__(self, token, organization=''):
        self.token, self.organization = token, organization

    def search(self, query, page_token=''):
        connection=http.client.HTTPSConnection('api.platform.censys.io',timeout=15,
            context=ssl.create_default_context(cafile=certifi.where()))
        path='/v3/global/search/query'
        if self.organization: path+='?'+urlencode({'organization_id':self.organization})
        payload={'query':query,'page_size':100}
        if page_token: payload['page_token']=page_token
        try:
            connection.request('POST',path,body=json.dumps(payload),headers={
                'Authorization':'Bearer '+self.token,'Content-Type':'application/json',
                'Accept':'application/json','User-Agent':'XYRO/2.0'})
            response=connection.getresponse()
            if response.status!=200:
                reasons={401:'неверный API token',403:'нет доступа к API или данным',429:'лимит API; повторите позднее'}
                raise RuntimeError('Censys: '+reasons.get(response.status,'HTTP '+str(response.status)))
            raw=response.read(4*1024*1024+1)
            if len(raw)>4*1024*1024: raise RuntimeError('Ответ Censys превышает лимит 4 MiB')
            data=json.loads(raw)
            result=data.get('result')
            if isinstance(result,dict) and result.get('hits') is None:result['hits']=[]
            if not isinstance(result,dict) or not isinstance(result.get('hits',[]),list):
                raise RuntimeError('Неизвестный формат ответа Censys')
            return result
        finally: connection.close()


def strings(value, wanted):
    if isinstance(value,dict):
        for key,item in value.items():
            if key in wanted:
                for v in (item if isinstance(item,list) else [item]):
                    if isinstance(v,str): yield v
            if isinstance(item,(dict,list)): yield from strings(item,wanted)
    elif isinstance(value,list):
        for item in value: yield from strings(item,wanted)


def run(scan, client=None):
    token=scan.config.get('censys_token')
    if not token:
        scan.progress(status='skipped',detail='Censys не настроен: добавьте Personal Access Token')
        return
    client=client or CensysClient(token,scan.config.get('censys_org',''))
    from .model import atomic_json
    import hashlib
    hosts=sorted(scan.scope.hosts)
    fingerprint=hashlib.sha256(json.dumps([hosts,scan.config.get('censys_org',''),token]).encode()).hexdigest()
    checkpoint=scan.folder/'censys-progress.json'
    saved=json.loads(checkpoint.read_text()) if scan.config.get('_resume') and checkpoint.exists() else {}
    if saved.get('fingerprint')!=fingerprint:saved={}
    host_index=saved.get('host_index',0);cursor=saved.get('cursor','');pages=0;seen=set()
    while host_index<len(hosts) and pages<scan.config.get('censys_pages',1):
        host=hosts[host_index]
        try: ipaddress.ip_address(host);query='host.ip = '+json.dumps(host)
        except ValueError:
            literal=json.dumps(host)
            query='(host.dns.names: '+literal+' or web.hostname: '+literal+' or cert.names: '+literal+')'
        scan.check()
        result=client.search(query,cursor);pages+=1
        for hit in result.get('hits') or []:
            for name in strings(hit,{'names','hostname','name'}):
                scan.add_host(name.removeprefix('*.'),'censys')
            for address in strings(hit,{'ip'}):
                try: ipaddress.ip_address(address)
                except ValueError: continue
                scan.asset('osint',host+'|'+address,host=host,address=address,source='censys',
                           in_scope=scan.scope.host_allowed(address),detail='Пассивная связь; IP не добавлен в активную область')
        scan.progress(pages_done=pages,targets_done=pages,targets_total=scan.config.get('censys_pages',1))
        next_cursor=result.get('next_page_token','')
        if next_cursor and (next_cursor==cursor or (host,next_cursor) in seen):
            raise RuntimeError('Censys повторил page token; пагинация остановлена')
        cursor=next_cursor
        if cursor:seen.add((host,cursor))
        else:host_index+=1
        atomic_json(checkpoint,{'fingerprint':fingerprint,'host_index':host_index,'cursor':cursor})
        scan.persist()
    if host_index<len(hosts):
        scan.progress(status='partial',detail='Лимит страниц Censys исчерпан; продолжение начнётся со следующей страницы')
