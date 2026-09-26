"""Regression probes on private loopback fixtures, also shipped in app selftest."""
import datetime
import ipaddress
import json
from pathlib import Path
import ssl
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def run(native_dir=''):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from .adapters import python_context, run_script, ROOT, json_objects, run_tool, binary
    from .model import atomic_json, validate_config
    from .worker import Run, StageTimeout
    from .recon import discovery
    from .proxy import start as start_proxy
    from . import builtin
    result={}
    seen=[]
    class Fixture(BaseHTTPRequestHandler):
        protocol_version='HTTP/1.1'
        def log_message(self,*args):pass
        def do_GET(self):
            path=self.path.split('?')[0];seen.append(path)
            body={
                '/':b'<html><a href="https://[broken">bad</a><script src="/app.js"></script>fixture</html>',
                '/app.js':b'const bad="https://[broken"; const good="/api/valid";',
                '/.git/config':b'[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = https://example.invalid/fixture.git\n',
            }.get(path,b'not found')
            self.send_response(200 if path in ('/','/app.js','/.git/config') else 404)
            self.send_header('Content-Type','application/javascript' if path.endswith('.js') else 'text/html')
            self.send_header('Content-Length',str(len(body)))
            self.end_headers()
            try:self.wfile.write(body)
            except (BrokenPipeError,ConnectionResetError):pass
    with tempfile.TemporaryDirectory() as folder:
        root=Path(folder)
        key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
        name=x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME,'localhost')])
        now=datetime.datetime.now(datetime.timezone.utc)
        cert=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
              .serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(minutes=1))
              .not_valid_after(now+datetime.timedelta(days=1))
              .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False)
              .sign(key,hashes.SHA256()))
        (root/'cert.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root/'key.pem').write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
        sites=[ThreadingHTTPServer(('127.0.0.1',0),Fixture) for _ in range(2)]
        ctx=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(root/'cert.pem'),str(root/'key.pem'))
        sites[1].socket=ctx.wrap_socket(sites[1].socket,server_side=True)
        for site in sites:threading.Thread(target=site.serve_forever,daemon=True).start()
        url=f'http://127.0.0.1:{sites[0].server_port}/'
        tls=f'https://127.0.0.1:{sites[1].server_port}/'
        def worker(name,target):
            path=root/name;path.mkdir()
            atomic_json(path/'config.json',validate_config({'target':target,'tools':['finalrecon'],'rps':50}))
            return Run(path,native_dir)
        try:
            scan=worker('links',url)
            links=[]
            builtin.run(scan.scope,{'max_urls':1,'rps':50},lambda _:None,links.append,lambda:None)
            result['malformed_html']=url+'app.js' in links and not any('[broken' in u for u in links)
            scan.add_url(url+'app.js')
            discovery(scan)
            result['malformed_js']=url+'api/valid' in scan.urls and not any('[broken' in u for u in scan.urls)
            scan=worker('tls',tls)
            run_tool(scan,'finalrecon')
            result['finalrecon_tls']=any(json.loads(f['evidence']).get('version')=='v3' for f in scan.findings)
            scan=worker('scope',url)
            with python_context(scan,'snallygaster',['127.0.0.1',f'127.0.0.1:{sites[0].server_port}',
                                '--nowww','--nohttps','--jsonl','--tests','openmonit,git_dir']):
                run_script(ROOT/'vendor/snallygaster/snallygaster')
            log=scan.folder/'snallygaster.log'
            result['snallygaster_scope']='Пропуск вне области:' in log.read_text(encoding='utf-8') and bool(json_objects(log))
            scan=worker('timeout',url)
            scan.deadline=time.monotonic()+0.5
            before={t.ident for t in threading.enumerate()}
            try:run_tool(scan,'arjun');result['arjun_timeout']=False
            except StageTimeout:result['arjun_timeout']=True
            result['arjun_threads_joined']=not any(t.ident not in before and t.name.startswith('ThreadPoolExecutor') for t in threading.enumerate())
            if binary('katana',native_dir):
                scan=worker('https-crawl',tls)
                scan.config.update(depth=1,max_urls=10)
                scan.deadline=time.monotonic()+20
                proxy,scan.proxy_url=start_proxy(scan.scope)
                try:
                    run_tool(scan,'katana')
                    result['katana_https']=bool(json_objects(scan.folder/'katana.log'))
                finally:proxy.shutdown();proxy.server_close()
        finally:
            for site in sites:site.shutdown();site.server_close()
    return result
