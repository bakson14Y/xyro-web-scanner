"""Pinned templates are local assets, selected deterministically. No API or AI."""
import hashlib
import json
from pathlib import Path
import zipfile

DATA=Path(__file__).resolve().parent/'data'
_manifest=None

def manifest():
    global _manifest
    if _manifest is None:
        file=DATA/'nuclei-manifest.json'
        _manifest=json.loads(file.read_text(encoding='utf-8')) if file.exists() else {'count':0,'templates':[]}
    return _manifest

def summary():
    m=manifest()
    return {k:m.get(k) for k in ('count','commit','snapshot_date','upstream_release','excluded')}

def select(config):
    rows=manifest()['templates']
    identifiers=set(config.get('nuclei_ids',[]))
    if identifiers:
        unknown=identifiers-{r['id'] for r in rows}
        if unknown:raise ValueError('Шаблоны не входят в сборку: '+', '.join(sorted(unknown)))
    preset=config.get('nuclei_preset','balanced')
    groups={'fast':{'technologies','exposures','misconfiguration'},
            'balanced':{'technologies','exposures','misconfiguration','cves','vulnerabilities'},'all':None}[preset]
    severities=set(config.get('nuclei_severities',['critical','high','medium','low','info']))
    return [r for r in rows if r['severity'] in severities and
            (r['id'] in identifiers if identifiers else groups is None or r['group'] in groups)]

def materialize(cache_dir):
    m=manifest()
    if not m.get('count'): raise FileNotFoundError('Шаблоны Nuclei не включены в сборку')
    root=Path(cache_dir)/('nuclei-templates-'+m['commit'][:12])
    if (root/'.complete').is_file():return root
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
