import os
import ast
import sys
from pathlib import Path
import subprocess
ROOT=Path(__file__).resolve().parent.parent
sep=os.pathsep
cmd=['python','-m','PyInstaller','--noconfirm','--clean','--name','XYRO','--onedir',
     '--add-data',f'engine/web{sep}engine/web','--add-data',f'vendor{sep}vendor',
     '--add-data',f'tools.lock.json{sep}.','--add-data',f'licenses{sep}licenses',
     '--add-binary',f'bin{sep}bin']
for package in ('requests','urllib3','certifi','dns','dicttoxml','ratelimit','tldextract',
                'colorama','chardet','ua_generator','bs4','lxml','cryptography'):
    cmd += ['--collect-all',package]
cmd += ['--hidden-import','concurrent.futures','--hidden-import','asyncio',
        '--hidden-import','sqlite3','--hidden-import','difflib','--hidden-import','csv',
        '--hidden-import','gzip','--hidden-import','http.cookies']
# Vendored programs are loaded with runpy, so freezing cannot infer their imports.
stdlib = set()
for path in (ROOT/'vendor').rglob('*.py'):
    tree = ast.parse(path.read_text(encoding='utf-8'))
    for node in ast.walk(tree):
        names = ([alias.name for alias in node.names] if isinstance(node, ast.Import)
                 else [node.module] if isinstance(node, ast.ImportFrom) and node.level == 0 else [])
        for name in names:
            if name and name.split('.')[0] in sys.stdlib_module_names:
                stdlib.add(name)
for name in sorted(stdlib): cmd += ['--hidden-import', name]
cmd += ['desktop.py']
subprocess.run(cmd,cwd=ROOT,check=True)
