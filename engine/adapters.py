import contextlib
import importlib
import importlib.util
import io
import json
import logging
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
from .model import finding, plain, BUILTIN_TOOLS, NATIVE_TOOLS, origin, host_url, atomic_json

ROOT = Path(__file__).resolve().parent.parent

def run_script(path):
    """Execute a bundled CLI file without consulting platform import hooks.

    Chaquopy's asset finder treats extensionless paths as import locations,
    which makes runpy.run_path look for a nonexistent __main__ package.
    """
    path = Path(path)
    namespace = {"__name__": "__main__", "__file__": str(path),
                 "__package__": None, "__spec__": None}
    exec(compile(path.read_bytes(), str(path), "exec"), namespace)

def binary(name, native_dir=""):
    candidates = ([Path(native_dir) / ("lib" + name + ".so")] if native_dir else [])
    candidates += [ROOT / "bin" / (name + (".exe" if os.name == "nt" else ""))]
    return next((str(x) for x in candidates if x.is_file()), None)

def inventory(native_dir=""):
    result = {name: {"ready": True, "kind": "builtin"} for name in BUILTIN_TOOLS}
    dependencies = {"arjun": ["requests", "dicttoxml", "ratelimit"],
                    "ghauri": ["requests", "tldextract", "colorama", "chardet", "ua_generator"],
                    "snallygaster": ["urllib3", "lxml", "dns"],
                    "finalrecon": ["requests", "dns", "cryptography"]}
    for tool in NATIVE_TOOLS:
        result[tool] = {"ready": bool(binary(tool, native_dir)), "kind": "native"}
    from .templates import summary
    result['nuclei']['templates'] = summary()
    result['nuclei']['ready'] = result['nuclei']['ready'] and bool(summary().get('count'))
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
    def loggers():
        return [logging.getLogger()] + [item for item in logging.Logger.manager.loggerDict.values()
                                      if isinstance(item, logging.Logger)]
    logger_state = {item: (list(item.handlers), item.level, item.propagate) for item in loggers()}
    original_handlers = {handler for handlers, _, _ in logger_state.values() for handler in handlers}
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
        kwargs['headers'] = {**(kwargs.get('headers') or {}), **run.config.get('headers', {})}
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
        # Upstream modules create FileHandlers. Close their handles before a
        # scan directory is exported/removed (Windows forbids deleting open logs).
        for item in loggers():
            for handler in list(item.handlers):
                if handler not in original_handlers:
                    item.removeHandler(handler)
                    handler.close()
        for item, (handlers, level, propagate) in logger_state.items():
            item.handlers = handlers
            item.setLevel(level)
            item.propagate = propagate
        urllib3.connectionpool.HTTPConnectionPool.urlopen = original_urlopen
        requests.sessions.Session.__init__ = original_session_init
        if original_normalizable is not None:
            urllib3.util.url.NORMALIZABLE_SCHEMES = original_normalizable
        elif hasattr(urllib3.util.url, "NORMALIZABLE_SCHEMES"):
            del urllib3.util.url.NORMALIZABLE_SCHEMES
        sys.excepthook = original_hook
        sys.argv, sys.path = original_argv, original_path

def native(run, tool, args, stdin=None, append=False, extra_env=None):
    executable = binary(tool, run.native_dir)
    if not executable: raise FileNotFoundError(tool)
    output = run.folder / (tool + ".log")
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env['GOMEMLIMIT'] = '384MiB'
    env['GOMAXPROCS'] = str(run.config.get('concurrency', 3))
    # Upstream tools must not inherit proxy credentials or opaque proxy routing.
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", 'pdcp_api_key', 'nuclei_args'):
            env.pop(key)
    cache = run.folder.parent.parent/'runtime'
    cache.mkdir(parents=True, exist_ok=True)
    env.update(NUCLEI_CONFIG_DIR=str(cache/'nuclei-config'), XDG_CONFIG_HOME=str(cache/'config'),
               SUBFINDER_CONFIG=str(cache/'subfinder-config.yaml'), SUBFINDER_PROVIDER_CONFIG=str(cache/'subfinder-providers.yaml'))
    for provider in ('PUBLIC', 'GITHUB', 'GITLAB', 'AWS', 'AZURE'):
        env['DISABLE_NUCLEI_TEMPLATES_'+provider+'_DOWNLOAD'] = 'true'
    if extra_env: env.update(extra_env)
    if tool in ('katana', 'nuclei', 'dalfox'):
        flag = '--headers' if tool == 'dalfox' else '-H'
        for key, value in run.config.get('headers', {}).items(): args += [flag, key+': '+value]
    elif tool == 'cariddi' and run.config.get('headers'):
        args += ['-headers', ';;'.join(k+': '+v for k,v in run.config['headers'].items())]
    with output.open('ab' if append else 'wb') as log:
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
                tail = output.read_text(encoding="utf-8", errors="replace")[-1600:]
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
    if tool == "nuclei":
        nuclei(run)
    elif tool == "subfinder":
        subfinder(run)
    elif tool == "gau":
        file = run.folder / (tool + ".log")
        try:
            native(run, tool, ["--threads", "1", "--timeout", "10", "--retries", "1"], "\n".join(sorted(run.scope.hosts))+"\n")
        finally:
            if file.exists():
                for line in file.read_text(encoding="utf-8", errors="replace").splitlines(): run.add_url(line.strip())
    elif tool == "katana":
        seeds = run.folder / "seeds.txt"
        seeds.write_text("\n".join(run.urls), encoding="utf-8")
        file = run.folder / (tool + ".log")
        try:
            native(run, tool, ["-list", str(seeds), "-d", str(c["depth"]), "-jc", "-fx", "-j",
                "-silent", "-duc", "-dr", "-c", "2", "-p", "1", "-rl", str(c["rps"]),
                "-timeout", "10", "-ct", str(c["stage_timeout"]), "-proxy", run.proxy_url,
                "-cs", run.scope.regex(), "-ob", "-or"])
        finally:
            if file.exists():
                for row in json_objects(file):
                    run.add_url(row.get("request", {}).get("endpoint", ""))
    elif tool == "cariddi":
        file = run.folder / (tool + ".log")
        try:
            native(run, tool, ["-s", "-e", "-err", "-json", "-c", "1", "-d", "1", "-t", "10",
                                      "-md", str(c["depth"]), "-proxy", run.proxy_url], "\n".join(run.scope.targets) + "\n")
        finally:
            if file.exists():
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
        try:
            native(run, tool, ["file", str(targets), "--format", "jsonl", "--output", str(result),
                              "--workers", "2", "--max-concurrent-targets", "1", "--rate-limit", str(c["rps"]),
                              "--timeout", "10", "--scan-timeout", str(c["stage_timeout"]), "--proxy", run.proxy_url,
                              "--insecure=false"])
        finally:
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
        for candidate in sorted(list(run.urls), key=lambda u: not bool(urlsplit(u).query)):
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
                data = json.loads(output.read_text(encoding="utf-8"))
                for target, item in data.items():
                    names = item.get("params", [])
                    run.add(finding(tool, "HTTP-параметры", target, ", ".join(names), confidence="tool-reported"))
                    run.add_url(target + "?" + urlencode({name: "xyro" for name in names}))
    elif tool == "ghauri":
        for candidate in sorted(list(run.urls), key=lambda u: not bool(urlsplit(u).query)):
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
            for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
                if re.search(r"(?:is injectable|confirmed.*inject|appears to be.*injectable)", line, re.I):
                    run.add(finding(tool, "Возможная SQL-инъекция", url, line, "high"))
    elif tool == "snallygaster":
        argv = [p.netloc, "--nowww", "--json", "--nohttp" if p.scheme == "https" else "--nohttps"]
        with python_context(run, tool, argv):
            try: run_script(ROOT / "vendor" / tool / "snallygaster")
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


def nuclei(run):
    from . import templates
    config=run.config
    selected=templates.select(config)
    if not selected:
        run.progress(templates_total=0,templates_done=0,detail='Нет шаблонов для выбранных фильтров');return
    root=templates.materialize(run.folder.parent.parent/'runtime')
    checkpoint=run.folder/'nuclei-progress.json'
    completed=set()
    if config.get('_resume') and checkpoint.exists():
        saved=json.loads(checkpoint.read_text(encoding='utf-8'))
        if saved.get('snapshot')==templates.manifest()['commit']:completed=set(saved.get('completed',[]))
    targets=list(dict.fromkeys(list(run.scope.targets)+[a['url'] for a in run.assets if a['kind']=='web']))[:config.get('max_hosts',40)]
    seeds=run.folder/'nuclei-targets.txt';seeds.write_text('\n'.join(targets),encoding='utf-8')
    pending=[row for row in selected if row['id'] not in completed]
    run.progress(templates_total=len(selected),templates_done=len(completed.intersection(r['id'] for r in selected)))
    def consume(result):
        if not result.exists():return
        for row in json_objects(result):
            target=row.get('matched-at') or row.get('url') or row.get('host') or run.scope.target
            if not run.scope.contains(target):continue
            info=row.get('info',{})
            classification=info.get('classification') or {}
            evidence='; '.join(filter(None,[row.get('matcher-name',''),str(info.get('description',''))[:2000]])) or 'Совпадение условий официального шаблона'
            extracted=row.get('extracted-results') or []
            if extracted:
                evidence+='; извлечено значений: '+str(len(extracted))+'; SHA256='+__import__('hashlib').sha256(json.dumps(extracted).encode()).hexdigest()[:20]
            run.add(finding('nuclei',info.get('name',row.get('template-id','Nuclei')),target,evidence,
                    info.get('severity','info'),'template-match',template_id=row.get('template-id',''),
                    cve=classification.get('cve-id',[]),cwe=classification.get('cwe-id',[]),
                    cvss=classification.get('cvss-score'),references=info.get('reference',[]),
                    remediation=info.get('remediation','Проверьте условия шаблона и рекомендации производителя.')))
    for offset in range(0,len(pending),64):
        run.check()
        batch=pending[offset:offset+64]
        fingerprint=__import__('hashlib').sha256('\n'.join(r['id'] for r in batch).encode()).hexdigest()[:16]
        result=run.folder/('nuclei-'+fingerprint+'.jsonl')
        args=['-l',str(seeds),'-t',','.join(str(root/r['path']) for r in batch),
              '-jle',str(result),'-nc','-duc','-ni','-dut','-pt','http','-dr','-nh','-no-stdin',
              '-or','-ot','-c',str(config.get('concurrency',3)),'-bs','1','-pc','1',
              '-rl',str(config['rps']),'-timeout','8','-retries','0','-rsr','1048576','-p',run.proxy_url]
        try:native(run,'nuclei',args,append=True,extra_env={'NUCLEI_TEMPLATES_DIR':str(root)})
        finally:consume(result)
        completed.update(r['id'] for r in batch)
        atomic_json(checkpoint,{'completed':sorted(completed),'snapshot':templates.manifest()['commit']})
        run.progress(templates_done=len(completed.intersection(r['id'] for r in selected)))
        run.persist()


def subfinder(run):
    import ipaddress
    roots=[]
    for host in run.scope.hosts:
        try:ipaddress.ip_address(host)
        except ValueError:roots.append(host)
    if not roots:
        run.progress(detail='IP-цель: пассивный поиск поддоменов не применяется');return
    output=run.folder/'subfinder.log'
    try:
        native(run,'subfinder',['-d',','.join(roots),'-silent','-oJ','-cs','-duc','-timeout','8',
                               '-max-time',str(max(1,math.ceil(run.config['stage_timeout']/60))),
                               '-max-results',str(run.config.get('max_hosts',40)*5),'-rl',str(run.config['rps'])])
    finally:
        if output.exists():
            for row in json_objects(output):run.add_host(row.get('host',''),','.join(row.get('sources') or [row.get('source','subfinder')]))
