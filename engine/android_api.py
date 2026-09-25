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
    atomic_json(Path(folder) / "smoke.json", result)
    return json.dumps(result)
