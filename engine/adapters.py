import contextlib
import importlib
import importlib.util
import io
import json
import math
import os
from pathlib import Path
import re
import runpy
import subprocess
import sys
import threading
import time
import types
from urllib.parse import urlsplit, urlunsplit, urlencode
from .model import finding, plain

ROOT = Path(__file__).resolve().parent.parent

def binary(name, native_dir=""):
    candidates = ([Path(native_dir) / ("lib" + name + ".so")] if native_dir else [])
    candidates += [ROOT / "bin" / (name + (".exe" if os.name == "nt" else ""))]
    return next((str(x) for x in candidates if x.is_file()), None)

def inventory(native_dir=""):
    result = {"recon": {"ready": True, "kind": "builtin"}}
    dependencies = {"arjun": ["requests", "dicttoxml", "ratelimit"],
                    "ghauri": ["requests", "tldextract", "colorama", "chardet", "ua_generator"],
                    "snallygaster": ["urllib3", "lxml", "dns"],
                    "finalrecon": ["requests", "dns", "cryptography"]}
    for tool in ("katana", "cariddi", "gau", "dalfox"):
        result[tool] = {"ready": bool(binary(tool, native_dir)), "kind": "native"}
    for tool, deps in dependencies.items():
        missing = [x for x in deps if importlib.util.find_spec(x) is None]
        if not (ROOT / "vendor" / tool).is_dir(): missing.append("source")
        result[tool] = {"ready": not missing, "kind": "python", "missing": missing}
    return result

class LogWriter(io.TextIOBase):
    def __init__(self, run, tool):
        self.run, self.tool, self.buffer = run, tool, ""
    def writable(self): return True
    def isatty(self): return False
    @property
    def encoding(self): return "utf-8"
    def write(self, text):
        self.buffer += text.replace("\r", "\n")
        while "\n" in self.buffer:
            line, self.buffer = self.buffer.split("\n", 1)
            if line.strip(): self.run.log(self.tool, plain(line))
        if len(self.buffer) > 4096:
            self.run.log(self.tool, plain(self.buffer))
            self.buffer = ""
        return len(text)
    def flush(self):
        if self.buffer:
            self.run.log(self.tool, plain(self.buffer))
            self.buffer = ""

@contextlib.contextmanager
def python_context(run, tool, argv):
    """Single worker per scan. Never invoked in the UI/server process."""
    import urllib3.connectionpool
    import requests.sessions
    original_session_init = requests.sessions.Session.__init__
    def session_init(session, *args, **kwargs):
        original_session_init(session, *args, **kwargs)
        session.trust_env = False
    original_urlopen = urllib3.connectionpool.HTTPConnectionPool.urlopen
    original_argv, original_path = sys.argv[:], sys.path[:]
    original_hook = sys.excepthook
    original_trace, thread_trace = sys.gettrace(), threading.gettrace()
    original_normalizable = getattr(urllib3.util.url, "NORMALIZABLE_SCHEMES", None)
    network_lock = threading.Lock()
    last_request = [0.0]
    def guarded(pool, method, url, *args, **kwargs):
        absolute = url if str(url).startswith(("http://", "https://")) else (
            ("https" if isinstance(pool, urllib3.connectionpool.HTTPSConnectionPool) else "http")
            + "://" + ("[" + pool.host + "]" if ":" in pool.host else pool.host)
            + ":" + str(pool.port or (443 if isinstance(pool, urllib3.connectionpool.HTTPSConnectionPool) else 80)) + url)
        run.scope.require(absolute)
        run.check()
        with network_lock:
            wait = 1 / run.config["rps"] - (time.monotonic() - last_request[0])
            if wait > 0: time.sleep(wait)
            last_request[0] = time.monotonic()
        # Bound otherwise-unbounded upstream network waits, including retries.
        kwargs["timeout"] = urllib3.Timeout(connect=10, read=10)
        kwargs["retries"] = False
        return original_urlopen(pool, method, url, *args, **kwargs)
    def trace(frame, event, arg):
        if event == "line" and "/vendor/" in frame.f_code.co_filename.replace("\\", "/"):
            run.check()
        return trace
    prefixes = {"arjun": ("arjun",), "ghauri": ("ghauri",),
                "finalrecon": ("modules", "settings"), "snallygaster": ()}[tool]
    for module in list(sys.modules):
        if any(module == p or module.startswith(p + ".") for p in prefixes):
            del sys.modules[module]
    sys.argv = [tool] + argv
    sys.path.insert(0, str(ROOT / "vendor" / tool))
    urllib3.connectionpool.HTTPConnectionPool.urlopen = guarded
    requests.sessions.Session.__init__ = session_init
    writer = LogWriter(run, tool)
    sys.settrace(trace)
    threading.settrace(trace)
    try:
        with contextlib.redirect_stdout(writer), contextlib.redirect_stderr(writer):
            yield
    finally:
        sys.settrace(original_trace)
        threading.settrace(thread_trace)
        writer.flush()
        urllib3.connectionpool.HTTPConnectionPool.urlopen = original_urlopen
        requests.sessions.Session.__init__ = original_session_init
        if original_normalizable is not None:
            urllib3.util.url.NORMALIZABLE_SCHEMES = original_normalizable
        elif hasattr(urllib3.util.url, "NORMALIZABLE_SCHEMES"):
            del urllib3.util.url.NORMALIZABLE_SCHEMES
        sys.excepthook = original_hook
        sys.argv, sys.path = original_argv, original_path

def native(run, tool, args, stdin=None):
    executable = binary(tool, run.native_dir)
    if not executable: raise FileNotFoundError(tool)
    output = run.folder / (tool + ".log")
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    # Upstream tools must not inherit proxy credentials or opaque proxy routing.
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy"):
            env.pop(key)
    with output.open("wb") as log:
        process = subprocess.Popen([executable] + args, stdin=subprocess.PIPE, stdout=log,
                                   stderr=subprocess.STDOUT, cwd=run.folder, env=env,
                                   start_new_session=os.name != "nt")
        try:
            if stdin: process.stdin.write(stdin.encode())
            process.stdin.close()
            while process.poll() is None:
                run.check()
                if output.stat().st_size > 10 * 1024 * 1024:
                    raise RuntimeError("Лимит журнала 10 MiB; этап остановлен")
                time.sleep(.2)
            if process.returncode not in ((0, 1) if tool == "dalfox" else (0,)):
                tail = output.read_text(errors="replace")[-1600:]
                raise RuntimeError(f"{tool}: exit={process.returncode}; {plain(tail)}")
        finally:
            if process.poll() is None:
                process.terminate()
                try: process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
    return output

def json_objects(path):
    text = path.read_text(encoding="utf-8", errors="replace")
    try:
        value = json.loads(text)
        if isinstance(value, list): return value
        if isinstance(value, dict): return [value]
    except ValueError:
        pass
    result = []
    for line in text.splitlines():
        try:
            value = json.loads(plain(line))
            if isinstance(value, list): result.extend(value)
            elif isinstance(value, dict): result.append(value)
        except ValueError: pass
    return result

def run_tool(run, tool):
    c, url = run.config, run.scope.target
    p = urlsplit(url)
    if tool == "gau":
        file = native(run, tool, [p.hostname, "--threads", "1", "--timeout", "10", "--retries", "1"])
        for line in file.read_text(errors="replace").splitlines(): run.add_url(line.strip())
    elif tool == "katana":
        seeds = run.folder / "seeds.txt"
        seeds.write_text("\n".join(run.urls), encoding="utf-8")
        file = native(run, tool, ["-list", str(seeds), "-d", str(c["depth"]), "-jc", "-fx", "-j",
            "-silent", "-duc", "-dr", "-c", "2", "-p", "1", "-rl", str(c["rps"]),
            "-timeout", "10", "-ct", str(c["stage_timeout"]), "-proxy", run.proxy_url,
            "-cs", "^" + re.escape(urlunsplit((p.scheme, p.netloc, "", "", ""))) + r"(?:/|$)", "-ob", "-or"])
        for row in json_objects(file):
            run.add_url(row.get("request", {}).get("endpoint", ""))
    elif tool == "cariddi":
        file = native(run, tool, ["-s", "-e", "-err", "-json", "-c", "1", "-d", "1", "-t", "10",
                                  "-md", str(c["depth"]), "-proxy", run.proxy_url], url + "\n")
        for row in json_objects(file):
            target = row.get("url", url)
            run.add_url(target)
            if not run.scope.contains(target): continue
            for category in ("secrets", "errors", "infos"):
                for hit in (row.get("matches") or {}).get(category) or []:
                    evidence = str(hit.get("match", ""))
                    if category == "secrets":
                        import hashlib
                        evidence = "Значение скрыто; SHA256=" + hashlib.sha256(evidence.encode()).hexdigest()[:20]
                    run.add(finding(tool, hit.get("name", category), target, evidence,
                                    "medium" if category == "secrets" else "info"))
    elif tool == "dalfox":
        targets = run.folder / "dalfox-targets.txt"
        targets.write_text("\n".join(run.urls), encoding="utf-8")
        result = run.folder / "dalfox.jsonl"
        native(run, tool, ["file", str(targets), "--format", "jsonl", "--output", str(result),
                          "--workers", "2", "--max-concurrent-targets", "1", "--rate-limit", str(c["rps"]),
                          "--timeout", "10", "--scan-timeout", str(c["stage_timeout"]), "--proxy", run.proxy_url,
                          "--insecure=false"])
        if result.exists():
            incomplete = False
            for row in json_objects(result):
                if "meta" in row:
                    if row["meta"].get("incomplete"):
                        incomplete = True
                    continue
                target = row.get("url") or url
                if not run.scope.contains(target): target = url
                # Keep engine assertions as candidates, not automatically confirmed exploits.
                run.add(finding(tool, "XSS: результат Dalfox", target,
                                json.dumps(row, ensure_ascii=False), "medium"))
            if incomplete:
                raise RuntimeError("Dalfox сообщил incomplete; результаты этапа частичные")
    elif tool == "arjun":
        seen = set()
        for candidate in list(run.urls):
            u = urlsplit(candidate)
            route = urlunsplit((u.scheme, u.netloc, u.path, "", ""))
            if route in seen: continue
            seen.add(route)
            output = run.folder / ("arjun-" + str(len(seen)) + ".json")
            with python_context(run, tool, ["-u", route, "-oJ", str(output), "-t", "1", "-T", "10",
                                           "--rate-limit", str(c["rps"]), "--disable-redirects"]):
                try: runpy.run_module("arjun.__main__", run_name="__main__")
                except SystemExit as exc:
                    if exc.code not in (None, 0): raise RuntimeError("arjun: " + str(exc.code))
            if output.exists():
                data = json.loads(output.read_text())
                for target, item in data.items():
                    names = item.get("params", [])
                    run.add(finding(tool, "HTTP-параметры", target, ", ".join(names), confidence="tool-reported"))
                    run.add_url(target + "?" + urlencode({name: "xyro" for name in names}))
    elif tool == "ghauri":
        for candidate in list(run.urls):
            if not urlsplit(candidate).query: continue
            with python_context(run, tool, ["-u", candidate, "--batch", "--level", "1", "--technique", "BE",
                                           "--threads", "1", "--timeout", "10"]):
                from ghauri.scripts.ghauri import main
                session_module = importlib.import_module("ghauri.common.session")
                session_module.expanduser = lambda _: str(run.folder / "ghauri-state")
                try: main()
                except SystemExit as exc:
                    if exc.code not in (None, 0): raise RuntimeError("ghauri: " + str(exc.code))
        log = run.folder / "ghauri.log"
        if log.exists():
            for line in log.read_text(errors="replace").splitlines():
                if re.search(r"(?:is injectable|confirmed.*inject|appears to be.*injectable)", line, re.I):
                    run.add(finding(tool, "Возможная SQL-инъекция", url, line, "high"))
    elif tool == "snallygaster":
        argv = [p.netloc, "--nowww", "--json", "--nohttp" if p.scheme == "https" else "--nohttps"]
        with python_context(run, tool, argv):
            try: runpy.run_path(str(ROOT / "vendor" / tool / "snallygaster"), run_name="__main__")
            except SystemExit as exc:
                if exc.code not in (None, 0): raise RuntimeError("snallygaster: " + str(exc.code))
        log = run.folder / "snallygaster.log"
        if log.exists():
            for row in json_objects(log):
                target = row.get("url", url)
                if run.scope.contains(target):
                    run.add(finding(tool, row.get("cause", "Открытый файл"), target, row.get("misc", "Ответил детектор snallygaster"), "medium"))
    elif tool == "finalrecon":
        with python_context(run, tool, []):
            settings = types.ModuleType("settings")
            settings.log_file_path = str(run.folder / "finalrecon-internal.log")
            sys.modules["settings"] = settings
            from modules.headers import headers
            from modules.dns import dnsrec
            from modules.sslinfo import cert
            data = {}
            out = {"directory": str(run.folder), "format": "txt", "file": str(run.folder / "finalrecon.txt")}
            import ipaddress
            try: ipaddress.ip_address(p.hostname); is_ip = True
            except ValueError: is_ip = False
            checks = [(headers, (url, out, data))]
            if not is_ip:
                checks.append((dnsrec, (p.hostname, "1.1.1.1,8.8.8.8", out, data)))
            if p.scheme == "https": checks.append((cert, (p.hostname, p.port or 443, out, data)))
            errors = []
            try:
                for check, arguments in checks:
                    try: check(*arguments)
                    except Exception as exc:
                        errors.append(check.__name__ + ": " + str(exc))
            finally:
                for name, value in data.items():
                    run.add(finding(tool, name, url, json.dumps(value, ensure_ascii=False), confidence="observed"))
            if errors: raise RuntimeError("; ".join(errors))
    else:
        raise ValueError("Unknown tool: " + tool)
