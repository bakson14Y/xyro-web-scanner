import json
from pathlib import Path
import vendor  # triggers extraction of vendored Python files on Chaquopy
from .server import Manager, serve

_manager = None
_server = None
_url = None

def start(context, native_dir):
    global _manager, _server, _url
    if _url:
        return _url
    from java import jclass
    Intent = jclass("android.content.Intent")
    def launch(folder, native):
        intent = Intent(context, jclass("dev.xyro.scanner.WorkerService"))
        intent.putExtra("folder", folder)
        intent.putExtra("native", native)
        context.startForegroundService(intent)
    data = str(context.getFilesDir().getAbsolutePath()) + "/scans"
    _manager = Manager(data, native_dir, launch)
    _server, url = serve(_manager)
    _url = url
    return url

def export_job(job):
    path = _manager.path(job) / "XYRO-report.zip"
    # Avoid including a previous copy of this ZIP in a later export.
    path.unlink(missing_ok=True)
    path.write_bytes(_manager.export(job))
    return str(path)

def smoke(folder, native_dir):
    from .selftest import run
    from .model import atomic_json
    result = run(native_dir)
    # Exercise the same Java foreground service used by the Start button.
    # This debug-only entry always targets an in-app loopback fixture.
    import threading
    import time
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    class Fixture(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.end_headers()
            self.wfile.write(b'[core]\nrepositoryformatversion = 0\n[remote "origin"]\nurl = https://example.invalid/fixture.git\n' if self.path == '/.git/config' else b"<html><title>XYRO local fixture</title>Local service test</html>")
    fixture = ThreadingHTTPServer(("127.0.0.1", 0), Fixture)
    threading.Thread(target=fixture.serve_forever, daemon=True).start()
    job = None
    try:
        job = _manager.create({"target": "http://127.0.0.1:" + str(fixture.server_port) + "/",
                               "profile": "custom", "max_urls": 10, "depth": 1,
                               "tools": ["recon", "dns", "ports", "webprobe", "katana", "cariddi", "finalrecon", "nuclei"],
                               "nuclei_ids": ["git-config"], "rps": 20, "stage_timeout": 60})
        deadline = time.monotonic() + 180
        report = _manager.report(job)
        while report["status"] in ("queued", "running") and time.monotonic() < deadline:
            time.sleep(1)
            report = _manager.report(job)
        result["worker"] = {"status": report["status"], "stages": report["stages"],
                            "findings": len(report["findings"]), "nuclei_detected": any(f.get("template_id") == "git-config" for f in report["findings"])}
        result["ok"] = (result["ok"] and report["status"] in ("completed", "partial")
                        and len(report["stages"]) == 8 and result["worker"]["nuclei_detected"] and all(
                            stage["status"] == "completed" for stage in report["stages"]))
    except Exception as exc:
        result.update(ok=False, worker={"error": str(exc)})
    finally:
        if job: _manager.cancel(job)
        fixture.shutdown(); fixture.server_close()
    atomic_json(Path(folder) / "smoke.json", result)
    return json.dumps(result)
