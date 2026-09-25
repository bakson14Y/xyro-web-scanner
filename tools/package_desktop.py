import os
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
        '--hidden-import','gzip','--hidden-import','http.cookies','desktop.py']
subprocess.run(cmd,cwd=ROOT,check=True)
