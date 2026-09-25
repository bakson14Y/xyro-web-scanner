import json
from pathlib import Path
import subprocess
import time

subprocess.run(["adb","install","-r","android/app/build/outputs/apk/debug/app-debug.apk"],check=True)
subprocess.run(["adb","shell","am","start","-n","dev.xyro.scanner/.MainActivity","--ez","smoke","true"],check=True)
deadline=time.monotonic()+240
result=None
while time.monotonic()<deadline:
    response=subprocess.run(["adb","exec-out","run-as","dev.xyro.scanner","cat","files/smoke.json"],capture_output=True,text=True)
    if response.returncode==0:
        try:result=json.loads(response.stdout);break
        except ValueError:pass
    time.sleep(2)
Path("test-results").mkdir(exist_ok=True)
Path("test-results/android-smoke.json").write_text(json.dumps(result,indent=2))
if not result or not result.get("ok"):
    subprocess.run(["adb","logcat","-d","-t","400"],check=False)
    raise SystemExit("Android runtime smoke/parity check failed")
print(json.dumps(result,indent=2))
