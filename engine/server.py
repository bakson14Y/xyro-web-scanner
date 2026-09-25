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
from .model import LABELS, PROFILES, atomic_json, validate_config

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
                        "status": "queued", "stages": [], "findings": [], "urls": [], "config": config})
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

    def cancel(self, job):
        (self.path(job) / "cancel").touch()

    def export(self, job):
        output = io.BytesIO()
        folder = self.path(job)
        with zipfile.ZipFile(output, "w", zipfile.ZIP_DEFLATED) as z:
            for path in folder.iterdir():
                if path.is_file() and path.name != "cancel" and not path.name.endswith(".tmp"):
                    z.write(path, path.name)
            z.writestr("report.html", render_html(self.report(job)))
        return output.getvalue()

def render_html(report):
    e = html.escape
    rows = "".join("<tr>" + "".join("<td>" + e(str(f.get(k, ""))) + "</td>" for k in
                   ("severity", "tool", "title", "url", "confidence", "evidence")) + "</tr>" for f in report["findings"])
    stages = " · ".join(e(s["tool"] + ": " + s["status"]) for s in report["stages"])
    return ("<!doctype html><html lang='ru'><meta charset='utf-8'><title>XYRO · Отчёт</title>"
            "<style>body{font:15px system-ui;margin:40px;background:#f7f8fa;color:#172027}table{border-collapse:collapse;width:100%}"
            "td,th{border:1px solid #ccd3d7;padding:12px;text-align:left;vertical-align:top;overflow-wrap:anywhere}h1{font-size:40px}</style>"
            "<h1>XYRO / Отчёт</h1><p>" + e(report["target"]) + "</p><p>Состояние: " + e(report["status"]) + "</p><p>" + stages +
            "</p><p>Кандидаты требуют проверки. Отсутствие находок не доказывает безопасность сайта.</p>"
            "<table><tr><th>Уровень<th>Модуль<th>Находка<th>URL<th>Статус доказательства<th>Данные</tr>" + rows + "</table></html>")

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
                    self.reply(200, {"version": "0.1.0", "tools": inventory(manager.native_dir), "labels": LABELS,
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
                if not 0 < length <= 8192: raise ValueError("Некорректный размер запроса")
                data = json.loads(self.rfile.read(length))
                if self.path == "/api/jobs": self.reply(201, {"id": manager.create(data)})
                elif self.path.startswith("/api/cancel/"):
                    manager.cancel(self.path.rsplit("/", 1)[1]); self.reply(200, {"ok": True})
                else: self.reply(404, {"error": "Not found"})
            except (ValueError, TypeError, OSError) as exc:
                self.reply(400, {"error": str(exc)})
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server, f"http://127.0.0.1:{server.server_port}/#" + token
