"""Pinned templates are local assets, selected deterministically. No API or AI."""
import hashlib
import json
from pathlib import Path
import zipfile
import threading
from functools import wraps
from collections import Counter
from .catalog import CATEGORIES, exclusion

DATA=Path(__file__).resolve().parent/'data'
_manifest=None
_lock=threading.RLock()

def synchronized(fn):
    @wraps(fn)
    def call(*args,**kwargs):
        with _lock:return fn(*args,**kwargs)
    return call

def manifest():
    global _manifest
    if _manifest is None:
        file=DATA/'nuclei-manifest.json'
        _manifest=json.loads(file.read_text(encoding='utf-8')) if file.exists() else {'count':0,'templates':[]}
    return _manifest

def summary():
    m=manifest()
    return {k:m.get(k) for k in ('count','supported_count','commit','snapshot_date','upstream_release','groups','dast_years','dast_folders')}

def candidates(config,mode='nuclei'):
    rows=manifest()['templates']
    identifiers=set(config.get('nuclei_ids',[]))
    if identifiers:
        unknown=identifiers-{r['id'] for r in rows}
        if unknown:raise ValueError('Шаблоны не входят в сборку: '+', '.join(sorted(unknown)))
    preset=config.get('nuclei_preset','balanced')
    groups={'fast':{'technologies','exposures','misconfiguration'},
            'balanced':{'technologies','exposures','misconfiguration','cves','vulnerabilities'},'all':None}[preset]
    severities=set(config.get('nuclei_severities',['critical','high','medium','low','info']))
    categories=set(config.get('categories',CATEGORIES))
    return [r for r in rows if r['severity'] in severities and r.get('mode','nuclei')==mode and
            bool(categories.intersection(r.get('categories',['exposure']))) and
            (r['id'] in identifiers if identifiers else mode!='nuclei' or groups is None or r['group'] in groups)]

def select(config,mode='nuclei'):
    return [r for r in candidates(config,mode) if not exclusion(r,config)]

def coverage(config):
    selected={r['path'] for mode in ('nuclei','dast','tls') if mode in config.get('tools',[])
              for r in select(config,mode)}
    rows=[]
    for key,label in CATEGORIES.items():
        all_rows=[r for r in manifest()['templates'] if key in r.get('categories',[])]
        active=[r for r in all_rows if r['path'] in selected]
        reasons=Counter(exclusion(r,config) or 'Не выбран модуль / фильтр' for r in all_rows if r['path'] not in selected)
        rows.append({'category':key,'label':label,'catalog':len(all_rows),'selected':len(active),
                     'status':'planned' if active else 'not_selected' if all_rows else 'no_template',
                     'reasons':dict(reasons)})
    return rows

@synchronized
def materialize(cache_dir):
    m=manifest()
    if not m.get('count'): raise FileNotFoundError('Шаблоны Nuclei не включены в сборку')
    root=Path(cache_dir)/('nuclei-templates-'+m['commit'][:12])
    marker=root/'.complete'
    if marker.is_file() and marker.read_text(encoding='utf-8')==m['archive_sha256'] and (root/'.nuclei-ignore').is_file():return root
    pack=DATA/'nuclei-templates.zip'
    if hashlib.sha256(pack.read_bytes()).hexdigest()!=m['archive_sha256']:
        raise ValueError('Нарушена контрольная сумма архива Nuclei')
    root.mkdir(parents=True,exist_ok=True)
    with zipfile.ZipFile(pack) as archive:
        for item in archive.infolist():
            target=(root/item.filename).resolve()
            if not target.is_relative_to(root.resolve()):raise ValueError('Некорректный путь шаблона')
        archive.extractall(root)
    (root/'.complete').write_text(m['archive_sha256'],encoding='utf-8')
    return root

@synchronized
def configure(cache_dir, root):
    """Install the pinned upstream ignore policy before Nuclei starts offline."""
    from .model import atomic_json
    m=manifest()
    content=(Path(root)/'.nuclei-ignore').read_bytes()
    if hashlib.sha256(content).hexdigest()!=m['ignore_sha256']:
        raise ValueError('Нарушена контрольная сумма .nuclei-ignore')
    config=Path(cache_dir)/'nuclei-config'
    config.mkdir(parents=True,exist_ok=True)
    temp=config/'.nuclei-ignore.tmp'
    temp.write_bytes(content)
    temp.replace(config/'.nuclei-ignore')
    atomic_json(config/'.templates-config.json',{
        'nuclei-templates-directory':str(root),
        'nuclei-templates-version':'v'+m['upstream_release']+'-xyro.'+m['snapshot_date'].replace('-',''),
    })
    return config
