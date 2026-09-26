import hashlib
from pathlib import Path
import shutil
import sys
import tarfile
import zipfile
ROOT=Path(__file__).resolve().parent.parent
source=ROOT/'dist/XYRO'
dest=ROOT/'release-assets';dest.mkdir(exist_ok=True)
if sys.platform=='win32':
    output=dest/'XYRO-1.5.2-Windows-x64.zip'
    with zipfile.ZipFile(output,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as pack:
        for path in sorted(source.rglob('*')):
            if path.is_file():pack.write(path,path.relative_to(source))
else:
    output=dest/'XYRO-1.5.2-Linux-x64.tar.gz'
    with tarfile.open(output,'w:gz',compresslevel=6) as pack:pack.add(source,arcname='XYRO')
print(output.name, output.stat().st_size, hashlib.sha256(output.read_bytes()).hexdigest())
