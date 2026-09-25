"""Fetch a pinned official template snapshot and produce identical mobile/desktop data."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import zipfile
import yaml

ROOT = Path(__file__).resolve().parent.parent
EXCLUDED_TAGS = {'dos', 'fuzz', 'fuzzing', 'bruteforce', 'headless', 'code'}
DISALLOWED_PROTOCOLS = {'code','javascript','headless','file','dns','tcp','network','ssl','websocket','whois'}

def main():
    lock = json.loads((ROOT/'templates.lock.json').read_text())
    src = ROOT/'build/upstream/nuclei-templates'
    if not (src/'.git').exists():
        subprocess.run(['git','clone','--no-checkout','--filter=blob:none',lock['repository'],str(src)],check=True)
    subprocess.run(['git','fetch','--depth','1','origin',lock['commit']],cwd=src,check=True)
    subprocess.run(['git','checkout','--detach',lock['commit']],cwd=src,check=True)
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=src,text=True).strip()!=lock['commit']:
        raise RuntimeError('Template revision mismatch')
    entries, excluded = [], {}
    for path in sorted((src/'http').rglob('*.yaml')):
        try:
            text = path.read_text(encoding='utf-8')
            doc = yaml.safe_load(text)
            if not isinstance(doc,dict) or 'http' not in doc: continue
            tags = doc.get('info',{}).get('tags',[])
            if isinstance(tags,str): tags=[x.strip() for x in tags.split(',')]
            reason = ('excluded group' if path.relative_to(src).parts[1] == 'credential-stuffing' else
                      'protocol' if DISALLOWED_PROTOCOLS.intersection(doc) or doc.get('self-contained') else
                      'excluded tag' if EXCLUDED_TAGS.intersection(tags) else
                      'external callback' if 'interactsh-' in text or 'interactsh_' in text else
                      'unsigned' if '# digest:' not in text else '')
            if reason:
                excluded[reason]=excluded.get(reason,0)+1;continue
            info=doc.get('info',{})
            rel=path.relative_to(src).as_posix()
            entries.append({'id':doc['id'],'path':rel,'name':str(info.get('name',doc['id'])),
                            'severity':str(info.get('severity','info')),'tags':tags,
                            'group':Path(rel).parts[1], 'sha256':hashlib.sha256(path.read_bytes()).hexdigest()})
        except (ValueError,KeyError,yaml.YAMLError) as exc:
            raise RuntimeError(f'Cannot parse upstream template {path}: {exc}') from exc
    destination=ROOT/'engine/data';destination.mkdir(parents=True,exist_ok=True)
    pack=destination/'nuclei-templates.zip'
    with zipfile.ZipFile(pack,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        selected={e['path'] for e in entries}
        for path in sorted((src/'http').rglob('*')):
            if path.is_file() and (path.relative_to(src).as_posix() in selected or path.suffix!='.yaml'):
                archive.write(path,path.relative_to(src).as_posix())
        for name in ('helpers','LICENSE.md','LICENSE'):
            path=src/name
            if path.is_dir():
                for item in sorted(path.rglob('*')):
                    if item.is_file():archive.write(item,item.relative_to(src).as_posix())
            elif path.is_file():archive.write(path,name)
    manifest={**lock,'count':len(entries),'excluded':excluded,'templates':entries,
              'archive_sha256':hashlib.sha256(pack.read_bytes()).hexdigest()}
    (destination/'nuclei-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False),encoding='utf-8')
    for source,name in ((src/'LICENSE.md','nuclei-templates-LICENSE.md'),(ROOT/'build/upstream/nuclei/LICENSE.md','nuclei-LICENSE.md')):
        if source.exists():shutil.copy2(source,ROOT/'licenses'/name)
    print(json.dumps({'templates':len(entries),'excluded':excluded,'bytes':pack.stat().st_size,'commit':lock['commit']}))

if __name__=='__main__':main()
