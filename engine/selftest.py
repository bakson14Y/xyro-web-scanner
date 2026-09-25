"""Offline boot/parity checks on installed Android and packaged desktop builds."""
from pathlib import Path
import runpy
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .adapters import inventory, binary, python_context, ROOT, run_tool, run_script
from .model import atomic_json, validate_config, Scope
from .worker import Run, StageTimeout
from .proxy import start as start_proxy
from . import builtin

def run(native_dir=""):
    result = {"inventory": inventory(native_dir), "native": {}, "python": {}, "http": False}
    for name, flag in (("katana", "-h"), ("cariddi", "-h"), ("gau", "--help"), ("dalfox", "--help")):
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
    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            requests_seen.append(self.path)
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            try:
                self.wfile.write(b'<html><title>XYRO fixture</title><body><form><input name="q"></form>XYRO fixture</body></html>')
            except (BrokenPipeError, ConnectionResetError): pass
    site = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    try:
        url = "http://127.0.0.1:" + str(site.server_port) + "/"
        findings = []
        builtin.run(Scope(url), {"max_urls":1,"rps":20}, findings.append, lambda _:None, lambda:None)
        result["http"] = any(f["title"] == "Нет content-security-policy" for f in findings)
        # Run the actual adapter arguments against our own fixture. Help-only checks
        # cannot detect CLI drift or Android networking/execution failures.
        result["probes"] = {}
        with tempfile.TemporaryDirectory() as folder:
            config = validate_config({"target": url + "?q=test", "profile": "audit",
                                      "max_urls": 1, "depth": 1, "rps": 20, "stage_timeout": 15})
            atomic_json(Path(folder)/"config.json", config)
            worker = Run(folder, native_dir)
            proxy, worker.proxy_url = start_proxy(worker.scope)
            try:
                for name in ("katana", "cariddi", "dalfox", "snallygaster", "arjun", "ghauri", "finalrecon"):
                    before = len(requests_seen)
                    worker.deadline = time.monotonic() + config["stage_timeout"]
                    probe = {"status": "completed"}
                    try: run_tool(worker, name)
                    except StageTimeout: probe["status"] = "budget"
                    except (Exception, SystemExit) as exc: probe.update(status="error", error=str(exc))
                    probe["requests"] = len(requests_seen) - before
                    if probe["status"] == "error":
                        log = Path(folder)/(name+".log")
                        if log.exists(): probe["log"] = log.read_text(encoding="utf-8", errors="replace")[-2500:]
                    result["probes"][name] = probe
            finally:
                proxy.shutdown(); proxy.server_close()
    finally: site.shutdown(); site.server_close()
    result["ok"] = (all(t["ready"] for t in result["inventory"].values())
                    and len(result["native"]) == 4
                    and all(t.get("code") == 0 and t.get("bytes",0)>0 for t in result["native"].values())
                    and all(t is True for t in result["python"].values()) and result["http"]
                    and all(t["status"] != "error" and t["requests"] > 0 for t in result["probes"].values()))
    return result
