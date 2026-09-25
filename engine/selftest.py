"""Offline boot/parity checks on installed Android and packaged desktop builds."""
from pathlib import Path
import runpy
import subprocess
import tempfile
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from .adapters import inventory, binary, python_context, ROOT
from .model import atomic_json, validate_config, Scope
from .worker import Run
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
                        else: runpy.run_path(str(ROOT/"vendor/snallygaster/snallygaster"), run_name="__main__")
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
    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b"<html>XYRO fixture</html>")
    site = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=site.serve_forever, daemon=True).start()
    try:
        url = "http://127.0.0.1:" + str(site.server_port) + "/"
        findings = []
        builtin.run(Scope(url), {"max_urls":1,"rps":20}, findings.append, lambda _:None, lambda:None)
        result["http"] = any(f["title"] == "Нет content-security-policy" for f in findings)
    finally: site.shutdown(); site.server_close()
    result["ok"] = (all(t["ready"] for t in result["inventory"].values())
                    and len(result["native"]) == 4
                    and all(t.get("code") == 0 and t.get("bytes",0)>0 for t in result["native"].values())
                    and all(t is True for t in result["python"].values()) and result["http"])
    return result
