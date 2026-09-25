import html
import io
import json
import os
from pathlib import Path
import re
import secrets
import subprocess
import sys
import threading
import time
import zipfile
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit
from .adapters import ROOT, inventory
from .model import LABELS, PROFILES, VERSION, atomic_json, validate_config, public_config
from .reports import render_html, csv_report, sarif_report

class Manager:
    def __init__(self, data_dir, native_dir="", launcher=None):
        self.data = Path(data_dir).resolve()
        self.data.mkdir(parents=True, exist_ok=True)
        self.native_dir, self.launcher = native_dir, launcher
        self.mutex = threading.Lock()
        self.children = []

    def path(self, job):
        if not re.fullmatch(r"[0-9a-f]{24}", job): raise ValueError("Некорректный ID")
        path = self.data / job
        if not path.is_dir(): raise FileNotFoundError(job)
        return path

    def report(self, job):
        file = self.path(job) / "report.json"
        result = json.loads(file.read_text(encoding="utf-8"))
        if result["status"] in ("running", "queued") and time.time() - result.get("heartbeat", result["created"]) > 120:
            result["status"] = "interrupted"
            result["interruption"] = "Исполнитель не обновляет состояние. Перезапустите проверку."
        return result

    def list(self):
        result = []
        for path in sorted(self.data.glob("*/report.json"), reverse=True):
            try:
                row = self.report(path.parent.name)
                result.append({k: row[k] for k in ("id", "status", "target", "created")})
            except (OSError, ValueError): continue
        return sorted(result, key=lambda x: x["created"], reverse=True)

    def create(self, raw):
        config = validate_config(raw)
        with self.mutex:
            if any(x["status"] in ("running", "queued") for x in self.list()):
                raise ValueError("Дождитесь завершения текущей проверки или остановите её")
            job = secrets.token_hex(12)
            folder = self.data / job
            folder.mkdir(mode=0o700)
            atomic_json(folder / "config.json", config)
            atomic_json(folder / "report.json", {"id": job, "target": config["target"], "created": time.time(),
                        "status": "queued", "stages": [], "findings": [], "urls": [], "assets": [], "config": public_config(config)})
            try:
                if self.launcher:
                    self.launcher(str(folder), self.native_dir)
                else:
                    args = ([sys.executable, "--worker"] if getattr(sys, "frozen", False)
                            else [sys.executable, str(ROOT / "desktop.py"), "--worker"])
                    with (folder / "worker.log").open("wb") as log:
                        child = subprocess.Popen(args + [str(folder), self.native_dir], cwd=ROOT,
                            stdout=log, stderr=subprocess.STDOUT, start_new_session=os.name != "nt")
                        self.children.append(child)
            except Exception as exc:
                report = self.report(job)
                report.update(status="error", error=str(exc))
                atomic_json(folder / "report.json", report)
                raise
            return job

    def resume(self, job):
        with self.mutex:
            if any(x["status"] in ("running", "queued") for x in self.list()):
                raise ValueError("Дождитесь завершения активной проверки")
            folder = self.path(job)
            report = self.report(job)
            if report["status"] not in ("partial", "cancelled", "interrupted", "error"):
                raise ValueError("Продолжение доступно для незавершённых проверок")
            config = json.loads((folder/"config.json").read_text(encoding="utf-8"))
            config["_resume"] = True
            atomic_json(folder/"config.json", config)
            (folder/"cancel").unlink(missing_ok=True)
            report.update(status="queued", heartbeat=time.time())
            atomic_json(folder/"report.json", report)
            try:
                if self.launcher: self.launcher(str(folder), self.native_dir)
                else:
                    args = ([sys.executable,"--worker"] if getattr(sys,"frozen",False) else [sys.executable,str(ROOT/"desktop.py"),"--worker"])
                    with (folder/"worker.log").open("ab") as log:
                        self.children.append(subprocess.Popen(args+[str(folder),self.native_dir],cwd=ROOT,stdout=log,stderr=subprocess.STDOUT,start_new_session=os.name!="nt"))
            except Exception as exc:
                report.update(status="error",error=str(exc));atomic_json(folder/"report.json",report);raise
        return job

    def cancel(self, job):
        (self.path(job) / "cancel").touch()

    def export(self, job):
        output = io.BytesIO()
        folder = self.path(job)
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
            report = self.report(job)
            config = json.loads((folder/'config.json').read_text(encoding='utf-8'))
            for path in folder.iterdir():
                if path.is_file() and path.suffix in ('.json','.jsonl','.log','.txt') and path.name != 'config.json':
                    content = path.read_text(encoding='utf-8', errors='replace')
                    for secret in config.get('headers',{}).values():
                        if len(secret) >= 4: content = content.replace(secret, '[скрыто]')
                    z.writestr(path.name, content)
            z.writestr('config.json', json.dumps(public_config(config), ensure_ascii=False, indent=2))
            z.writestr('report.html', render_html(report))
            z.writestr('findings.csv', csv_report(report))
            z.writestr('report.sarif', json.dumps(sarif_report(report), ensure_ascii=False, indent=2))
        return output.getvalue()


def serve(manager):
    token = secrets.token_urlsafe(32)
    assets = Path(__file__).parent / "web"
    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args): pass
        def reply(self, status, body, mime="application/json; charset=utf-8"):
            data = body if isinstance(body, bytes) else (body if isinstance(body, str) else json.dumps(body, ensure_ascii=False)).encode()
            self.send_response(status)
            self.send_header("Content-Type", mime)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'")
            self.end_headers()
            self.wfile.write(data)

        def authorized(self):
            host = f"127.0.0.1:{self.server.server_port}"
            return (self.headers.get("Host") == host and
                    self.headers.get("Origin", "http://" + host) == "http://" + host and
                    secrets.compare_digest(self.headers.get("Authorization", ""), "Bearer " + token))

        def do_GET(self):
            path = urlsplit(self.path).path
            if path in ("/", "/app.js", "/style.css"):
                if self.headers.get("Host") != f"127.0.0.1:{self.server.server_port}":
                    self.reply(403, {"error": "Invalid host"}); return
                filename = "index.html" if path == "/" else path[1:]
                mime = {"index.html": "text/html; charset=utf-8", "app.js": "text/javascript; charset=utf-8", "style.css": "text/css; charset=utf-8"}[filename]
                self.reply(200, (assets / filename).read_bytes(), mime)
                return
            if not self.authorized(): self.reply(401, {"error": "Требуется локальная сессия"}); return
            try:
                if path == "/api/info":
                    self.reply(200, {"version": VERSION, "tools": inventory(manager.native_dir), "labels": LABELS,
                                     "profiles": PROFILES, "platform": "android" if manager.native_dir else sys.platform})
                elif path == "/api/jobs": self.reply(200, manager.list())
                elif path.startswith("/api/job/"): self.reply(200, manager.report(path.rsplit("/", 1)[1]))
                elif path.startswith("/api/export/"):
                    self.reply(200, manager.export(path.rsplit("/", 1)[1]), "application/zip")
                elif path.startswith("/api/log/"):
                    _, _, _, job, tool = path.split("/")
                    if tool not in LABELS: raise ValueError("Unknown tool")
                    file = manager.path(job) / (tool + ".log")
                    data = file.read_bytes()[-64000:].decode("utf-8", "replace") if file.exists() else "Журнал пока пуст"
                    self.reply(200, {"text": data})
                else: self.reply(404, {"error": "Not found"})
            except (ValueError, OSError) as exc:
                self.reply(400, {"error": str(exc)})

        def do_POST(self):
            if not self.authorized(): self.reply(401, {"error": "Требуется локальная сессия"}); return
            try:
                length = int(self.headers.get("Content-Length", 0))
                if not 0 < length <= 64000: raise ValueError("Некорректный размер запроса")
                data = json.loads(self.rfile.read(length))
                if self.path == "/api/jobs": self.reply(201, {"id": manager.create(data)})
                elif self.path.startswith("/api/resume/"):
                    self.reply(200, {"id":manager.resume(self.path.rsplit("/",1)[1])})
                elif self.path.startswith("/api/cancel/"):
                    manager.cancel(self.path.rsplit("/", 1)[1]); self.reply(200, {"ok": True})
                else: self.reply(404, {"error": "Not found"})
            except (ValueError, TypeError, OSError) as exc:
                self.reply(400, {"error": str(exc)})
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}/#" + token
