import os
from pathlib import Path
import sys
import time
import webbrowser

def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--selftest":
        from engine.selftest import run
        import json
        result = run()
        print(json.dumps(result, indent=2))
        raise SystemExit(0 if result["ok"] else 1)
    if len(sys.argv) > 1 and sys.argv[1] == "--worker":
        from engine.worker import run
        run(sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else "")
        return
    from engine.server import Manager, serve
    data = Path(os.environ.get("LOCALAPPDATA", str(Path.home() / ".local" / "share"))) / "XYRO" / "scans"
    manager = Manager(data)
    server, url = serve(manager)
    print("XYRO запущен. Локальная ссылка:", url, flush=True)
    webbrowser.open(url)
    try:
        while True: time.sleep(1)
    except KeyboardInterrupt:
        for job in manager.list():
            if job["status"] in ("running", "queued"): manager.cancel(job["id"])
        server.shutdown()

if __name__ == "__main__": main()
