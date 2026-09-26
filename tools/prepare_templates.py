"""Bundle the pinned upstream tree verbatim; classify execution separately."""
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import sys
import zipfile
import yaml

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from engine.catalog import classify


def main():
    lock = json.loads((ROOT/'templates.lock.json').read_text())
    src = ROOT/'build/upstream/nuclei-templates'
    if not (src/'.git').exists():
        src.mkdir(parents=True, exist_ok=True)
        subprocess.run(['git','init',str(src)],check=True)
        subprocess.run(['git','remote','add','origin',lock['repository']],cwd=src,check=True)
    subprocess.run(['git','fetch','--depth','1','origin',lock['commit']],cwd=src,check=True)
    subprocess.run(['git','checkout','--detach',lock['commit']],cwd=src,check=True)
    if subprocess.check_output(['git','rev-parse','HEAD'],cwd=src,text=True).strip()!=lock['commit']:
        raise RuntimeError('Template revision mismatch')
    ignore_file = src/'.nuclei-ignore'
    ignore = yaml.safe_load(ignore_file.read_text(encoding='utf-8'))
    entries = []
    roots = ('http','dast','ssl','network','dns','javascript','headless','code','file','workflows')
    for group in roots:
        for path in sorted((src/group).rglob('*.yaml')):
            raw = path.read_bytes()
            text = raw.decode('utf-8')
            doc = yaml.safe_load(text)
            if not isinstance(doc, dict) or not doc.get('id') or not isinstance(doc.get('info'),dict): continue
            rel = path.relative_to(src).as_posix()
            row = classify(rel,doc,text,ignore.get('files',[]),ignore.get('tags',[]))
            row['sha256'] = hashlib.sha256(raw).hexdigest()
            entries.append(row)
    destination=ROOT/'engine/data';destination.mkdir(parents=True,exist_ok=True)
    pack=destination/'nuclei-templates.zip'
    with zipfile.ZipFile(pack,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as archive:
        archive.write(ignore_file,'.nuclei-ignore')
        for group in (*roots,'helpers'):
            for path in sorted((src/group).rglob('*')):
                if path.is_file(): archive.write(path,path.relative_to(src).as_posix())
        for name in ('LICENSE.md','LICENSE'):
            if (src/name).is_file(): archive.write(src/name,name)
    counts = {group:sum(e['path'].startswith(group+'/') for e in entries) for group in roots}
    years = sorted({e['year'] for e in entries if e['path'].startswith('dast/cves/') and e['year']})
    folders = sorted(p.name for p in (src/'dast/vulnerabilities').iterdir() if p.is_dir())
    manifest = {**lock,'schema':2,'count':len(entries),'supported_count':sum(e['supported'] for e in entries),
                'groups':counts,'dast_years':years,'dast_folders':folders,'templates':entries,
                'ignore_sha256':hashlib.sha256(ignore_file.read_bytes()).hexdigest(),
                'archive_sha256':hashlib.sha256(pack.read_bytes()).hexdigest()}
    (destination/'nuclei-manifest.json').write_text(json.dumps(manifest,ensure_ascii=False),encoding='utf-8')
    for source,name in ((src/'LICENSE.md','nuclei-templates-LICENSE.md'),(ROOT/'build/upstream/nuclei/LICENSE.md','nuclei-LICENSE.md')):
        if source.exists():shutil.copy2(source,ROOT/'licenses'/name)
    print(json.dumps({k:v for k,v in manifest.items() if k!='templates'},ensure_ascii=False))

if __name__=='__main__': main()
