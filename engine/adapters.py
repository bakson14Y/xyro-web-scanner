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
    try: exec(compile(path.read_bytes(), str(path), "exec"), namespace)
    finally:
        pool=namespace.get('pool')
        if pool is not None and hasattr(pool,'clear'):pool.clear()

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
    for mode in ('dast','tls'):
        result[mode]={'ready':result['nuclei']['ready'],'kind':'nuclei'}
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
    blocked = set()
    def guarded(pool, method, url, *args, **kwargs):
        absolute = url if str(url).startswith(("http://", "https://")) else (
            ("https" if isinstance(pool, urllib3.connectionpool.HTTPSConnectionPool) else "http")
            + "://" + ("[" + pool.host + "]" if ":" in pool.host else pool.host)
            + ":" + str(pool.port or (443 if isinstance(pool, urllib3.connectionpool.HTTPSConnectionPool) else 80)) + url)
        run.check()
        try: run.scope.require(absolute)
        except ValueError:
            if tool != 'snallygaster': raise
            if absolute not in blocked:
                blocked.add(absolute)
                run.log(tool, 'Пропуск вне области: '+absolute)
            # Snallygaster handles urllib3 network errors per detector; a plain
            # ValueError aborts its entire suite on hard-coded service ports.
            raise urllib3.exceptions.HTTPError('Вне заданной области: '+absolute) from None
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

def runtime_dir(run):
    if hasattr(run,'cache_dir'):return run.cache_dir
    # Application jobs share a cache under their owned scans directory.
    # Standalone/test jobs keep it inside their own writable directory;
    # walking two parents up from /tmp/job would otherwise select /runtime.
    parent = run.folder.parent if run.folder.parent.name == 'scans' else run.folder
    return parent / 'runtime'

def native(run, tool, args, stdin=None, append=False, extra_env=None, log_name=None, include_headers=True):
    executable = binary(tool, run.native_dir)
    if not executable: raise FileNotFoundError(tool)
    output = run.folder / ((log_name or tool) + ".log")
    env = os.environ.copy()
    env["NO_COLOR"] = "1"
    env['GOMEMLIMIT'] = '384MiB'
    env['GOMAXPROCS'] = str(run.config.get('concurrency', 3))
    # Upstream tools must not inherit proxy credentials or opaque proxy routing.
    for key in list(env):
        if key.lower() in ("http_proxy", "https_proxy", "all_proxy", "no_proxy", 'pdcp_api_key', 'nuclei_args'):
            env.pop(key)
    cache = runtime_dir(run)
    cache.mkdir(parents=True, exist_ok=True)
    env.update(NUCLEI_CONFIG_DIR=str(cache/'nuclei-config'), XDG_CONFIG_HOME=str(cache/'config'),
               SUBFINDER_CONFIG=str(cache/'subfinder-config.yaml'), SUBFINDER_PROVIDER_CONFIG=str(cache/'subfinder-providers.yaml'))
    for provider in ('PUBLIC', 'GITHUB', 'GITLAB', 'AWS', 'AZURE'):
        env['DISABLE_NUCLEI_TEMPLATES_'+provider+'_DOWNLOAD'] = 'true'
    if extra_env: env.update(extra_env)
    if include_headers and tool in ('katana', 'nuclei', 'dalfox'):
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
    if tool in ('nuclei','dast','tls'):
        nuclei(run,mode=tool)
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
        # A seed starts a whole crawl: do not re-crawl every URL found by gau.
        seeds.write_text("\n".join(run.scope.targets), encoding="utf-8")
        file = run.folder / (tool + ".log")
        try:
            native(run, tool, ["-list", str(seeds), "-d", str(c["depth"]), "-jc", "-fx", "-j",
                "-silent", "-duc", "-dr", "-c", str(c.get('concurrency',3)), "-p", "1", "-rl", str(c["rps"]),
                "-retry", "0", "-s", "breadth-first", "-iqp", "-mdp", str(c['max_urls']),
                "-timeout", "10", "-proxy", run.proxy_url,
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
        from .workflow import dynamic_urls
        targets = run.folder / "dalfox-targets.txt"
        selected=dynamic_urls(run)
        targets.write_text("\n".join(selected), encoding="utf-8")
        if not selected:
            run.progress(status='skipped',detail='Нет динамических URL для Dalfox');return
        result = run.folder / "dalfox.jsonl"
        incomplete=False
        try:
            native(run, tool, ["file", str(targets), "--format", "jsonl", "--output", str(result),
                              "--workers", "2", "--max-concurrent-targets", "1", "--rate-limit", str(c["rps"]),
                              "--timeout", "10", "--scan-timeout", str(c["stage_timeout"]), "--proxy", run.proxy_url,
                              "--max-targets-per-host",str(len(selected)),"--insecure=false"])
        finally:
            if result.exists():
                for row in json_objects(result):
                    if "meta" in row:
                        if row["meta"].get("incomplete"):
                            incomplete = True
                        continue
                    target = row.get("url") or url
                    if not run.scope.contains(target): continue
                    # Keep engine assertions as candidates, not automatically confirmed exploits.
                    run.add(finding(tool, "XSS: результат Dalfox", target,
                                    json.dumps(row, ensure_ascii=False), "medium",categories=['xss']))
        if incomplete:
            raise RuntimeError("Dalfox сообщил incomplete; результаты этапа частичные")
    elif tool == "arjun":
        arjun(run)
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
        argv = [p.netloc, "--nowww", "--jsonl", "--nohttp" if p.scheme == "https" else "--nohttps"]
        log = run.folder / "snallygaster.log"
        try:
            with python_context(run, tool, argv):
                try: run_script(ROOT / "vendor" / tool / "snallygaster")
                except SystemExit as exc:
                    if exc.code not in (None, 0): raise RuntimeError("snallygaster: " + str(exc.code))
        finally:
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
                    run.add(finding(tool, name, url, json.dumps(value, ensure_ascii=False, default=str), confidence="observed"))
            if errors: raise RuntimeError("; ".join(errors))
    else:
        raise ValueError("Unknown tool: " + tool)


STATIC_SUFFIXES = {'.css','.js','.mjs','.cjs','.map','.ico','.png','.jpg','.jpeg','.gif','.webp','.svg',
                   '.woff','.woff2','.ttf','.eot','.mp3','.mp4','.webm','.pdf','.zip','.gz','.br'}

def parameter_targets(run):
    routes=[]
    candidates=sorted(run.urls, key=lambda u: (not bool(urlsplit(u).query), u not in run.scope.targets))
    for candidate in candidates:
        u=urlsplit(candidate)
        if Path(u.path).suffix.lower() in STATIC_SUFFIXES:continue
        route=urlunsplit((u.scheme,u.netloc,u.path,'',''))
        if run.scope.contains(route) and route not in routes:routes.append(route)
    return routes

def arjun(run):
    routes=parameter_targets(run)
    checkpoint=run.folder/'arjun-progress.json'
    completed=set()
    if run.config.get('_resume') and checkpoint.exists():
        completed=set(json.loads(checkpoint.read_text(encoding='utf-8')).get('completed',[]))
    completed.intersection_update(routes)
    errors=[]
    run.progress(targets_total=len(routes),targets_done=len(completed))
    for route in routes:
        if route in completed:continue
        run.check()
        output=run.folder/('arjun-'+__import__('hashlib').sha256(route.encode()).hexdigest()[:16]+'.json')
        namespace={}
        run.progress(current_target=route)
        run.log('arjun',f'Адрес {len(completed)+1}/{len(routes)}: {route}')
        try:
            with python_context(run, 'arjun', ['-u',route,'-oJ',str(output),'-t','1','-T','10',
                                              '--rate-limit',str(run.config['rps']),'--disable-redirects']):
                namespace=runpy.run_module('arjun.__main__',run_name='__main__')
        finally:
            if output.exists():
                for target,item in json.loads(output.read_text(encoding='utf-8')).items():
                    if not run.scope.contains(target):continue
                    names=item.get('params',[])
                    run.add(finding('arjun','HTTP-параметры',target,', '.join(names),confidence='tool-reported'))
                    run.add_url(target+'?'+urlencode({name:'xyro' for name in names}))
            run.persist()
        if namespace.get('xyro_completed'):
            completed.add(route)
            atomic_json(checkpoint,{'completed':sorted(completed)})
        else:errors.append(route)
        run.progress(targets_done=len(completed),targets_failed=len(errors))
        run.persist()
    if errors:raise RuntimeError(f'Arjun не завершил {len(errors)} адресов; результаты остальных сохранены. '
                                'Причина в журнале; продолжение повторит незавершённые адреса.')

def nuclei(run,mode='nuclei'):
    from .nuclei_runner import run as execute
    return execute(run,mode)


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
