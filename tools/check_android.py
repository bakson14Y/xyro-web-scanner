import json
from pathlib import Path
import subprocess
import time

subprocess.run(["adb","install","-r","android/app/build/outputs/apk/debug/app-debug.apk"],check=True)
subprocess.run(["adb","shell","pm","grant","dev.xyro.scanner","android.permission.POST_NOTIFICATIONS"],check=True)
subprocess.run(["adb","shell","am","start","-n","dev.xyro.scanner/.MainActivity","--ez","smoke","true"],check=True)
deadline=time.monotonic()+600
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
ui_deadline=time.monotonic()+45
ui=""
while time.monotonic()<ui_deadline:
    subprocess.run(["adb","shell","uiautomator","dump","/sdcard/xyro-ui.xml"],capture_output=True)
    ui=subprocess.run(["adb","exec-out","cat","/sdcard/xyro-ui.xml"],capture_output=True,text=True).stdout
    if "20 / 20 МОДУЛЕЙ" in ui: break
    time.sleep(2)
Path("test-results/android-ui.xml").write_text(ui)
shot=subprocess.run(["adb","exec-out","screencap","-p"],capture_output=True,check=True)
Path("test-results/android-screen.png").write_bytes(shot.stdout)
if "20 / 20 МОДУЛЕЙ" not in ui:
    raise SystemExit("Android interface did not connect to all twenty modules")
print(json.dumps(result,indent=2))
