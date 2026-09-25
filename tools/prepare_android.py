from pathlib import Path
import shutil
import subprocess
import sys
ROOT = Path(__file__).resolve().parent.parent
wheel_dir = ROOT/'build/wheels'
wheel_dir.mkdir(parents=True, exist_ok=True)
subprocess.run([sys.executable, '-m', 'pip', 'wheel', '--no-deps', '--wheel-dir', str(wheel_dir),
                'ratelimit==2.2.1'], check=True)
dest = ROOT/'build/python'
dest.mkdir(parents=True, exist_ok=True)
for name in ('engine','vendor'):
    shutil.copytree(ROOT/name, dest/name, dirs_exist_ok=True,
                    ignore=shutil.ignore_patterns('__pycache__','*.pyc','.git'))
shutil.copy2(ROOT/'tools.lock.json', dest/'tools.lock.json')
print('Python sources prepared:', dest)
