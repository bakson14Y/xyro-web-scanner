from pathlib import Path
import shutil
ROOT = Path(__file__).resolve().parent.parent
dest = ROOT/'build/python'
dest.mkdir(parents=True, exist_ok=True)
for name in ('engine','vendor'):
    shutil.copytree(ROOT/name, dest/name, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('__pycache__','*.pyc','.git'))
shutil.copy2(ROOT/'tools.lock.json', dest/'tools.lock.json')
print('Python sources prepared:', dest)
