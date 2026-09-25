import json
import os
from pathlib import Path
import sys
import threading
import time
import traceback
from . import builtin
from .adapters import inventory, run_tool
from .model import Scope, PROFILES, atomic_json, canonical_url, plain
from .proxy import start as start_proxy

class Cancelled(BaseException): pass
class StageTimeout(BaseException): pass

class Run:
    def __init__(self, folder, native_dir=""):
        self.folder = Path(folder).resolve()
        self.config = json.loads((self.folder / "config.json").read_text(encoding="utf-8"))
        self.scope = Scope(self.config["target"])
        self.native_dir = native_dir
        self.urls = [self.scope.target]
        self.findings = []
        self.ids = set()
        self.lock = threading.RLock()
        self.deadline = float("inf")
        self.state = {"id": self.folder.name, "status": "running", "created": time.time(),
                      "target": self.scope.target, "config": self.config, "stages": [], "findings": [], "urls": []}
        self.done = threading.Event()

    def persist(self):
        with self.lock:
            self.state.update(findings=self.findings, urls=self.urls, heartbeat=time.time())
            atomic_json(self.folder / "report.json", self.state)

    def heartbeat(self):
        while not self.done.wait(3): self.persist()

    def check(self):
        if (self.folder / "cancel").exists(): raise Cancelled()
        if time.monotonic() > self.deadline: raise StageTimeout()

    def add_url(self, url):
        if self.scope.contains(url):
            value = canonical_url(url)
            if value not in self.urls and len(self.urls) < self.config["max_urls"]:
                self.urls.append(value)

    def add(self, item):
        with self.lock:
            if item["id"] not in self.ids:
                self.ids.add(item["id"])
                self.findings.append(item)

    def log(self, tool, line):
        path = self.folder / (tool + ".log")
        with self.lock:
            if not path.exists() or path.stat().st_size < 10 * 1024 * 1024:
                with path.open("a", encoding="utf-8") as file:
                    file.write(plain(line)[:16000] + "\n")

    def execute(self):
        server, self.proxy_url = start_proxy(self.scope)
        threading.Thread(target=self.heartbeat, daemon=True).start()
        available = inventory(self.native_dir)
        self.state["inventory"] = available
        try:
            for tool in PROFILES[self.config["profile"]]:
                stage = {"tool": tool, "status": "running", "started": time.time()}
                self.state["stages"].append(stage)
                self.persist()
                self.deadline = time.monotonic() + self.config["stage_timeout"]
                try:
                    self.check()
                    if not available[tool]["ready"]:
                        stage.update(status="missing", error="Модуль не установлен")
                        continue
                    if tool == "recon":
                        builtin.run(self.scope, self.config, self.add, self.add_url, self.check)
                    else:
                        run_tool(self, tool)
                    stage["status"] = "completed"
                except Cancelled:
                    stage["status"] = "cancelled"
                    self.state["status"] = "cancelled"
                    break
                except StageTimeout:
                    stage.update(status="timeout", error="Достигнут бюджет этапа; результаты частичные")
                except (Exception, SystemExit) as exc:
                    stage.update(status="error", error=str(exc)[:1800])
                    self.log(tool, traceback.format_exc())
                finally:
                    stage["finished"] = time.time()
                    self.persist()
            else:
                self.state["status"] = "completed" if all(s["status"] == "completed" for s in self.state["stages"]) else "partial"
        finally:
            self.done.set()
            server.shutdown()
            server.server_close()
            self.state["finished"] = time.time()
            self.persist()
        return self.state

def run(folder, native_dir=""):
    return Run(folder, native_dir).execute()

if __name__ == "__main__":
    run(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else "")
