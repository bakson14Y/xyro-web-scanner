"""Pinned Nuclei HTTP/DAST/SSL runner with target-bound checkpoints."""
import base64
import hashlib
import json
from pathlib import Path
from urllib.parse import urlsplit
from xml.etree import ElementTree as ET
from .model import atomic_json, finding, canonical_url, origin
from . import templates


def burp_input(path, urls, requests, default_headers):
    root=ET.Element('items',{'burpVersion':'XYRO 2.0'})
    explicit={r['url'] for r in requests}
    records=[{'url':u,'method':'GET','headers':{},'body':''} for u in urls if u not in explicit]+requests
    for row in records:
        u=urlsplit(row['url']);item=ET.SubElement(root,'item')
        method=row.get('method','GET')
        headers={k.lower():v for k,v in default_headers.items()}
        headers.update({k.lower():v for k,v in row.get('headers',{}).items()})
        body=row.get('body','').encode('utf-8')
        headers['Host']=u.netloc
        if body:headers['Content-Length']=str(len(body))
        raw=(method+' '+(u.path or '/')+('?' + u.query if u.query else '')+' HTTP/1.1\r\n'+
             ''.join(k+': '+v+'\r\n' for k,v in headers.items())+'\r\n').encode()+body
        for key,value in {'url':row['url'],'host':u.hostname,'port':str(u.port or (443 if u.scheme=='https' else 80)),
                          'protocol':u.scheme,'method':method,'path':u.path or '/'}.items():ET.SubElement(item,key).text=value
        ET.SubElement(item,'request',{'base64':'true'}).text=base64.b64encode(raw).decode('ascii')
    ET.ElementTree(root).write(path,encoding='utf-8',xml_declaration=True)
    return len(records)


def normalized_target(raw, scan):
    try:
        value=canonical_url(raw)
        return value if scan.scope.contains(value) else None
    except (ValueError,UnicodeError):pass
    for seed in getattr(scan,'seed_targets',scan.scope.targets):
        p=urlsplit(seed)
        if raw in (p.hostname,p.netloc,p.hostname+':'+str(p.port or (443 if p.scheme=='https' else 80))):return seed
    return None


def run(scan, mode='nuclei'):
    from .adapters import native, runtime_dir, json_objects
    config=scan.config
    selected=templates.select(config,mode)
    candidates=templates.candidates(config,mode)
    scan.progress(templates_total=len(selected),templates_done=0,templates_skipped=len(candidates)-len(selected))
    if not selected:
        scan.progress(status='skipped',detail='Нет исполняемых шаблонов: проверьте фильтры и условия в «Покрытие»');return
    root=templates.materialize(runtime_dir(scan))
    templates.configure(runtime_dir(scan),root)
    targets=list(dict.fromkeys(getattr(scan,'seed_targets',[]) or list(scan.scope.targets)+[a['url'] for a in scan.assets if a['kind']=='web']))
    targets=[u for u in targets if scan.scope.contains(u) and (mode!='tls' or urlsplit(u).scheme=='https')]
    if not targets:
        scan.progress(status='skipped',detail='Нет подходящих целей');return
    requests=[r for r in config.get('requests',[])+getattr(scan,'captured_requests',[]) if r['url'] in targets]
    seeds=scan.folder/(mode+'-targets.txt')
    input_args=['-l',str(seeds)]
    if mode=='dast':
        seeds=scan.folder/'dast-requests.xml'
        target_count=burp_input(seeds,targets,requests,config.get('headers',{}))
        input_args=['-l',str(seeds),'-im','burp']
    else:
        seeds.write_text('\n'.join(targets),encoding='utf-8');target_count=len(targets)
    fingerprint=hashlib.sha256(json.dumps({'targets':targets,'requests':requests,'headers':config.get('headers',{}),
        'templates':[r['sha256'] for r in selected]},sort_keys=True).encode()).hexdigest()
    checkpoint=scan.folder/(mode+'-progress.json');completed=set()
    if config.get('_resume') and checkpoint.exists():
        saved=json.loads(checkpoint.read_text(encoding='utf-8'))
        if saved.get('fingerprint')==fingerprint: completed=set(saved.get('completed',[]))
    pending=[r for r in selected if r['path'] not in completed]
    scan.progress(templates_done=len(completed),input_records=target_count)
    lookup={r['id']:r for r in selected}
    def consume(result):
        if not result.exists():return
        for row in json_objects(result):
            raw=row.get('matched-at') or row.get('url') or row.get('host') or ''
            target=normalized_target(raw,scan)
            if not target:continue
            template=lookup.get(row.get('template-id'))
            if not template:continue
            info=row.get('info',{});classification=info.get('classification') or {}
            evidence='; '.join(filter(None,[row.get('matcher-name',''),str(info.get('description',''))[:2000]])) or 'Совпадение условий шаблона'
            extracted=row.get('extracted-results') or []
            if extracted:evidence+='; значения: '+str(len(extracted))+'; SHA256='+hashlib.sha256(json.dumps(extracted).encode()).hexdigest()[:20]
            source=next((u for u in targets if u==row.get('url')),None)
            if source is None:
                source=next((u for u in targets if origin(u)==origin(target) and urlsplit(u).path==urlsplit(target).path),None)
            if source is None:source=next((u for u in targets if origin(u)==origin(target)),targets[0])
            item=finding(mode,info.get('name',row['template-id']),target,evidence,info.get('severity','info'),'template-match',
                template_id=row['template-id'],template_path=template['path'],categories=template['categories'],
                matcher=row.get('matcher-name',''),scan_target=source,verification='pending',
                cve=classification.get('cve-id',[]),cwe=classification.get('cwe-id',[]),cvss=classification.get('cvss-score'),
                references=info.get('reference',[]),remediation=info.get('remediation','Проверьте условия шаблона и рекомендации производителя.'))
            if template.get('weak_matcher'):item['upstream_warning']='Шаблон исключён upstream из-за слабого matcher'
            scan.add(item)
    for offset in range(0,len(pending),32):
        scan.check();batch=pending[offset:offset+32]
        for row in batch:
            if hashlib.sha256((root/row['path']).read_bytes()).hexdigest()!=row['sha256']:
                raise RuntimeError('Изменён файл шаблона: '+row['path'])
        key=hashlib.sha256('\n'.join(r['path'] for r in batch).encode()).hexdigest()[:16]
        result=scan.folder/(mode+'-'+key+'.jsonl')
        result.unlink(missing_ok=True)
        paths=','.join(str(root/r['path']) for r in batch)
        args=input_args+['-t',paths,'-jle',str(result),'-nc','-silent','-duc','-dut','-dr','-nh','-no-stdin',
              '-or','-ot','-c',str(config.get('concurrency',2)),'-bs','1','-pc','1',
              '-rl',str(config['rps']),'-timeout','20' if mode=='dast' else '8','-retries','0',
              '-rsr','1048576','-p',scan.proxy_url]
        # Include overrides only for templates the catalogue explicitly allowed.
        overrides=[r for r in batch if r.get('weak_matcher') or r.get('ignored_tags')]
        if overrides:args+=['-it',','.join(str(root/r['path']) for r in overrides)]
        if mode=='dast':args+=['-dast','-fa','medium','-cs',scan.scope.regex()]
        if config.get('oast_enabled'):
            args+=['-iserver',config['oast_server']]
            if config.get('oast_token'):args+=['-itoken',config['oast_token']]
        else:args+=['-ni']
        scan.log(mode,f'Пакет {offset//32+1}/{(len(pending)+31)//32}: {len(batch)} шаблонов, {target_count} входных запросов')
        try:native(scan,'nuclei',args,append=True,extra_env={'NUCLEI_TEMPLATES_DIR':str(root)},log_name=mode,
                   include_headers=mode!='dast')
        finally:consume(result)
        completed.update(r['path'] for r in batch)
        atomic_json(checkpoint,{'completed':sorted(completed),'fingerprint':fingerprint,'snapshot':templates.manifest()['commit']})
        scan.progress(templates_done=len(completed),processed_pairs=len(completed)*target_count)
        scan.persist()
