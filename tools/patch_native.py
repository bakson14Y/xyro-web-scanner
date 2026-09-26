"""Small, reviewed source patches for pinned native dependencies."""
from pathlib import Path
import hashlib
import json
import shutil

ROOT = Path(__file__).resolve().parent.parent


def dalfox(source):
    source = Path(source)
    files = {'src/target_parser/mod.rs': 1, 'src/oob/interactsh/mod.rs': 1,
             'src/payload/remote.rs': 3}
    for name, count in files.items():
        path = source / name
        text = path.read_text(encoding='utf-8')
        if text.count('Client::builder()') != count:
            raise RuntimeError('Dalfox TLS patch does not match pinned source: ' + name)
        text = text.replace('Client::builder()', 'crate::xyro_tls::builder()')
        if name == 'src/target_parser/mod.rs':
            # Do not silently discard the proxy on an upstream builder error.
            start = text.index('        self.build_client().unwrap_or_else(|e| {')
            end = text.index('\n    }', start)
            text = text[:start] + '''        self.build_client().expect("XYRO HTTP client configuration failed")''' + text[end:]
        path.write_text(text, encoding='utf-8')
    lib = source/'src/lib.rs'
    lib.write_text(lib.read_text(encoding='utf-8').replace('pub mod cmd;', 'pub(crate) mod xyro_tls;\npub mod cmd;'), encoding='utf-8')
    bundle = ROOT/'tools/patches/ca-bundle.pem'
    expected = json.loads((ROOT/'tools.lock.json').read_text())['dalfox']['ca_sha256']
    if hashlib.sha256(bundle.read_bytes()).hexdigest() != expected:
        raise RuntimeError('CA bundle checksum mismatch')
    shutil.copy2(bundle, source/'src/xyro-ca.pem')
    shutil.copy2(ROOT/'tools/patches/dalfox_tls.rs', source/'src/xyro_tls.rs')
