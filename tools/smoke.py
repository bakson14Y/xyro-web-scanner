import json
from pathlib import Path
import subprocess
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent.parent))
from engine.adapters import inventory,binary

def main():
    result={'inventory':inventory(),'native':{}}
    for name,flag in (('katana','-h'),('cariddi','-h'),('gau','--help'),('dalfox','--help')):
        executable=binary(name)
        if executable:
            p=subprocess.run([executable,flag],capture_output=True,timeout=60)
            result['native'][name]={'code':p.returncode}
    print(json.dumps(result,indent=2))
    if not all(t['ready'] for t in result['inventory'].values()):raise SystemExit('Incomplete tool inventory')
    if len(result['native'])!=4 or any(t['code']!=0 for t in result['native'].values()):raise SystemExit('Native smoke test failed')

if __name__=='__main__':main()
