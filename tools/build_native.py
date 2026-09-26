"""Build the exact same revisions for desktop and Android. No prebuilt mystery binaries."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from patch_native import dalfox as patch_dalfox

ROOT = Path(__file__).resolve().parent.parent

def command(args, cwd=None, env=None):
    print('+', ' '.join(map(str, args)), flush=True)
    subprocess.run(list(map(str, args)), cwd=cwd, env=env, check=True)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--android', choices=['arm64-v8a', 'x86_64'])
    parser.add_argument('--ndk')
    parser.add_argument('--only', nargs='*')
    args = parser.parse_args()
    lock = json.loads((ROOT/'tools.lock.json').read_text())
    dest = (ROOT/'android/app/src/main/jniLibs'/args.android) if args.android else ROOT/'bin'
    dest.mkdir(parents=True, exist_ok=True)
    for name, item in lock.items():
        if item['kind'] == 'python': continue
        if args.only and name not in args.only: continue
        source = ROOT/'build/upstream'/name
        if not (source/'.git').exists():
            source.mkdir(parents=True, exist_ok=True)
            command(['git', 'init', source])
            command(['git', 'remote', 'add', 'origin', item['repository']], cwd=source)
        command(['git', 'fetch', '--depth', '1', 'origin', item['commit']], cwd=source)
        command(['git', 'checkout', '--detach', item['commit']], cwd=source)
        actual = subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()
        if actual != item['commit']: raise RuntimeError('Revision mismatch: '+name)
        if name == 'dalfox':
            # Reset only our generated, pinned upstream checkout on rebuild.
            command(['git','restore','src/target_parser/mod.rs','src/oob/interactsh/mod.rs',
                     'src/payload/remote.rs','src/lib.rs'],cwd=source)
            patch_dalfox(source)
        env = os.environ.copy()
        env.setdefault('GOMAXPROCS', '2')
        output = dest / (('lib'+name+'.so') if args.android else (name + ('.exe' if os.name=='nt' else '')))
        target = None
        if args.android:
            if not args.ndk: parser.error('--android requires --ndk')
            llvm = Path(args.ndk)/'toolchains/llvm/prebuilt/linux-x86_64/bin'
            arch, triple, target = ('arm64','aarch64-linux-android','aarch64-linux-android') if args.android=='arm64-v8a' else ('amd64','x86_64-linux-android','x86_64-linux-android')
            cc = str(llvm/(triple+'26-clang'))
            env.update(GOOS='android', GOARCH=arch, CGO_ENABLED='1', CC=cc,
                       CXX=str(llvm/(triple+'26-clang++')))
            key = target.replace('-','_')
            env['CARGO_TARGET_'+key.upper()+'_LINKER'] = cc
            env['CC_'+key] = cc
            env['AR_'+key] = str(llvm/'llvm-ar')
            env['RUSTFLAGS'] = '-C link-arg=-Wl,-z,max-page-size=16384'
        if item['kind']=='go':
            cmd = ['go','build','-p','2','-trimpath']
            if args.android:
                cmd += ['-buildmode=pie','-ldflags=-s -w -extldflags=-Wl,-z,max-page-size=16384']
            else: cmd += ['-ldflags=-s -w']
            command(cmd+['-o',output,item['entry']],cwd=source,env=env)
        else:
            # Dalfox is both a library and a binary. Retain Rust metadata during
            # compilation; upstream strip/LTO settings broke rustc 1.98 builds.
            env.setdefault('CARGO_PROFILE_RELEASE_STRIP', 'none')
            env.setdefault('CARGO_PROFILE_RELEASE_LTO', 'false')
            env.setdefault('CARGO_BUILD_JOBS', '2')
            cmd = ['cargo','build','--release','--locked']
            if target:
                command(['rustup','target','add',target])
                cmd += ['--target',target]
            command(cmd,cwd=source,env=env)
            built = source/'target'
            if target: built /= target
            built = built/'release'/('dalfox.exe' if os.name=='nt' else 'dalfox')
            shutil.copy2(built,output)
        if os.name!='nt': output.chmod(0o755)
        print('Built', output, flush=True)

if __name__=='__main__': main()
