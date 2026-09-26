"""Offline boot/parity checks on installed Android and packaged desktop builds."""
from pathlib import Path
import runpy
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .adapters import inventory, binary, python_context, ROOT, run_tool, run_script
from .model import atomic_json, validate_config, Scope, NATIVE_TOOLS
from .worker import Run, StageTimeout
from .proxy import start as start_proxy
from . import builtin

def run(native_dir=""):
    from .healthchecks import run as regression_checks
    result = {"inventory": inventory(native_dir), "native": {}, "python": {}, "http": False}
    result['regressions']=regression_checks(native_dir)
    for name in NATIVE_TOOLS:
        flag = "--help" if name in ("gau", "dalfox") else "-h"
        try:
            p = subprocess.run([binary(name, native_dir), flag], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, timeout=45)
            result["native"][name] = {"code": p.returncode, "bytes": len(p.stdout)}
        except Exception as exc:
            result["native"][name] = {"error": str(exc)}
    with tempfile.TemporaryDirectory() as folder:
        atomic_json(Path(folder)/"config.json", validate_config({"target": "http://127.0.0.1/"}))
        worker = Run(folder)
        for name, module in (("arjun", "arjun.__main__"), ("ghauri", "ghauri.scripts.ghauri"), ("snallygaster", None)):
            try:
                with python_context(worker, name, ["--help"]):
                    try:
                        if module: runpy.run_module(module, run_name="__main__")
                        else: run_script(ROOT/"vendor/snallygaster/snallygaster")
                    except SystemExit as exc:
                        if exc.code not in (None, 0): raise RuntimeError(str(exc.code))
                result["python"][name] = True
            except Exception as exc:
                result["python"][name] = str(exc)
        try:
            with python_context(worker, "finalrecon", []):
                import sys, types
                settings = types.ModuleType("settings")
                settings.log_file_path = str(Path(folder)/"finalrecon.log")
                sys.modules["settings"] = settings
                import modules.headers, modules.dns, modules.sslinfo
            result["python"]["finalrecon"] = True
        except Exception as exc: result["python"]["finalrecon"] = str(exc)
    requests_seen = []
    exposed = [True]
    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            requests_seen.append(self.path)
            if self.path in ('/xyro-redirect', '/xyro-outside'):
                self.send_response(302)
                self.send_header('Location', '/xyro-session' if self.path == '/xyro-redirect' else 'https://outside.invalid/')
                self.end_headers()
                return
            if self.path == '/xyro-session':
                self.send_response(200 if self.headers.get('X-XYRO-Test') == 'redirect-session' else 401)
                self.end_headers()
                return
            is_git = self.path.split('?')[0] == '/.git/config'
            self.send_response(404 if is_git and not exposed[0] else 200)
            self.send_header("Content-Type", "text/plain" if is_git else "text/html")
            self.end_headers()
            try:
                self.wfile.write((b'[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = https://example.invalid/local-fixture.git\n' if exposed[0] else b'not found') if is_git else b'<html><title>XYRO fixture</title><body><form><input name="q"></form>XYRO fixture</body></html>')
            except (BrokenPipeError, ConnectionResetError): pass
    site = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    try:
        url = "http://127.0.0.1:" + str(site.server_port) + "/"
        findings = []
        builtin.run(Scope(url), {"max_urls":1,"rps":20}, findings.append, lambda _:None, lambda:None)
        result["http"] = any(f["title"] == "Нет content-security-policy" for f in findings)
        redirected = builtin.request(Scope(url), url+'xyro-redirect', headers={'X-XYRO-Test': 'redirect-session'})
        result['redirect_headers'] = redirected[0] == 200 and redirected[3] == url+'xyro-session'
        redirect_findings, redirect_urls = [], []
        builtin.run(Scope(url+'xyro-outside', targets=[url]), {'max_urls': 2, 'rps': 20},
                    redirect_findings.append, redirect_urls.append, lambda: None)
        result['redirect_scope'] = (url in redirect_urls and
            any(f.get('redirect_url') == 'https://outside.invalid/' and f['severity'] == 'info' for f in redirect_findings))
        # Run the actual adapter arguments against our own fixture. Help-only checks
        # cannot detect CLI drift or Android networking/execution failures.
        result["probes"] = {}
        with tempfile.TemporaryDirectory() as folder:
            config = validate_config({"target": url + "?q=test", "profile": "audit",
                                      "max_urls": 10, "depth": 1, "rps": 20, "stage_timeout": 15, "nuclei_ids": ["git-config"]})
            atomic_json(Path(folder)/"config.json", config)
            worker = Run(folder, native_dir)
            proxy, worker.proxy_url = start_proxy(worker.scope)
            try:
                for name in ("katana", "cariddi", "dalfox", "snallygaster", "arjun", "ghauri", "finalrecon", "nuclei"):
                    before = len(requests_seen)
                    worker.deadline = time.monotonic() + (60 if name == "nuclei" else config["stage_timeout"])
                    probe = {"status": "completed"}
                    try: run_tool(worker, name)
                    except StageTimeout: probe["status"] = "budget"
                    except (Exception, SystemExit) as exc: probe.update(status="error", error=str(exc))
                    probe["requests"] = len(requests_seen) - before
                    if probe["status"] == "error":
                        log = Path(folder)/(name+".log")
                        if log.exists(): probe["log"] = log.read_text(encoding="utf-8", errors="replace")[-2500:]
                    result["probes"][name] = probe
                result["nuclei_positive"] = any(f.get("template_id") == "git-config" for f in worker.findings)
                result['nuclei_ignore_clean']='nuclei-ignore' not in (worker.folder/'nuclei.log').read_text(encoding='utf-8',errors='replace')
                exposed[0] = False
                worker.findings.clear(); worker.ids.clear()
                for old in Path(folder).glob("nuclei-*.jsonl"): old.unlink()
                worker.deadline = time.monotonic() + 60
                try:
                    run_tool(worker, "nuclei")
                    result["nuclei_negative"] = not any(f.get("template_id") == "git-config" for f in worker.findings)
                except (Exception, StageTimeout) as exc:
                    result["nuclei_negative"] = False
                    result["nuclei_negative_error"] = str(exc)
                worker.deadline = time.monotonic() + 15
                run_tool(worker, "subfinder")  # IP input: no passive-provider request.
            finally:
                proxy.shutdown(); proxy.server_close()
    finally: site.shutdown(); site.server_close()
    result["ok"] = (all(t["ready"] for t in result["inventory"].values())
                    and all(t is True for t in result['regressions'].values())
                    and len(result["native"]) == len(NATIVE_TOOLS)
                    and all(t.get("code") == 0 and t.get("bytes",0)>0 for t in result["native"].values())
                    and all(t is True for t in result["python"].values()) and result["http"]
                    and result.get('redirect_headers') is True and result.get('redirect_scope') is True
                    and result.get("nuclei_positive") is True and result.get("nuclei_negative") is True
                    and result.get('nuclei_ignore_clean') is True
                    and all(t["status"] != "error" and t["requests"] > 0 for t in result["probes"].values()))
    return result
