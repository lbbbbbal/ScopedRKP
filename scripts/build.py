"""Build and package the ARM64 module. Requires Python 3.10+ and NDK r29+."""
from pathlib import Path
import argparse,hashlib,json,os,platform,shutil,stat,subprocess,sys,zipfile
ROOT=Path(__file__).resolve().parents[1]
def main():
    p=argparse.ArgumentParser();p.add_argument('--ndk',default=os.environ.get('ANDROID_NDK_HOME') or os.environ.get('ANDROID_NDK_ROOT'))
    p.add_argument('--tests',action='store_true');a=p.parse_args()
    if not a.ndk:p.error('Set ANDROID_NDK_HOME or pass --ndk')
    ndk=Path(a.ndk).resolve()
    host={'Windows':'windows-x86_64','Linux':'linux-x86_64','Darwin':'darwin-x86_64'}[platform.system()]
    suffix='.exe' if os.name=='nt' else ''
    compiler=ndk/'toolchains/llvm/prebuilt'/host/'bin'/('clang++'+suffix)
    out=ROOT/'build';out.mkdir(exist_ok=True)
    env=os.environ.copy();tmp=out/'tmp';tmp.mkdir(exist_ok=True)
    for key in ['TMP','TEMP','TMPDIR']:env[key]=str(tmp)
    flags=['--target=aarch64-linux-android31','-std=c++20','-Oz','-flto','-fPIC','-fvisibility=hidden',
           '-fstack-protector-strong','-mbranch-protection=standard','-ffunction-sections','-fdata-sections',
           '-I'+str(ROOT/'src'),'-I'+str(ROOT/'src/injector')]
    link=['-static-libstdc++','-Wl,-z,relro,-z,now,-z,noexecstack,-z,max-page-size=16384,--gc-sections,--exclude-libs,ALL,-s']
    def compile(name,sources,extra=()):
        cmd=[str(compiler),*flags,*extra,*(str(ROOT/s) for s in sources),*link,'-ldl','-o',str(out/name)]
        result=subprocess.run(cmd,env=env,capture_output=True,text=True,encoding='utf-8',errors='replace')
        if result.returncode:print(result.stdout+result.stderr);raise SystemExit(result.returncode)
        print(name+': built',flush=True)
    compile('libscoped_rkp.so',['src/payload.cpp'],['-shared','-llog'])
    compile('srkp_engine',['src/injector/main.cpp','src/injector/utils.cpp'])
    if a.tests:
        compile('libsrkp_fixture.so',['src/payload.cpp'],['-shared','-llog','-DSRKP_FIXTURE=1'])
        compile('srkp_fixture',['tests/fixture.cpp'],['-Wl,--export-dynamic'])
        compile('srkp_inject_test',['tests/injector_test.cpp','src/injector/main.cpp','src/injector/utils.cpp'],['-DSRKP_INJECT_LIBRARY_ONLY=1'])
    properties=dict(line.split('=',1) for line in (ROOT/'module/module.prop').read_text().splitlines() if '=' in line)
    version=properties['version'];dist=ROOT/'dist';dist.mkdir(exist_ok=True)
    target=dist/f'ScopedRKP-{version}-arm64.zip'
    files={x.relative_to(ROOT/'module').as_posix():x.read_bytes() for x in (ROOT/'module').rglob('*') if x.is_file()}
    files.update({'bin/srkp_engine':(out/'srkp_engine').read_bytes(),'lib/libscoped_rkp.so':(out/'libscoped_rkp.so').read_bytes(),
                  'LICENSE':(ROOT/'LICENSE').read_bytes(),'NOTICE':(ROOT/'NOTICE').read_bytes()})
    executable={'bin/srkp_engine','bin/scoped-rkpctl','boot-completed.sh','action.sh','uninstall.sh','customize.sh'}
    with zipfile.ZipFile(target,'w',compression=zipfile.ZIP_DEFLATED,compresslevel=9) as z:
        for name,data in sorted(files.items()):
            info=zipfile.ZipInfo(name,(2026,1,1,0,0,0));info.create_system=3
            info.external_attr=(stat.S_IFREG | (0o755 if name in executable else 0o644))<<16
            info.compress_type=zipfile.ZIP_DEFLATED;z.writestr(info,data)
    with zipfile.ZipFile(target) as z:assert z.testzip() is None
    sha=hashlib.sha256(target.read_bytes()).hexdigest()
    (dist/(target.name+'.sha256')).write_text(f'{sha}  {target.name}\n',encoding='ascii')
    report={'version':version,'zip':target.name,'bytes':target.stat().st_size,'sha256':sha,
            'installed_native_files':{n:len(files[n]) for n in ['bin/srkp_engine','lib/libscoped_rkp.so']},
            'installed_files':sorted(files),'device_binding':False,'runtime_symbol_lookup':True}
    (out/'manifest.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
    print(json.dumps(report,indent=2))
if __name__=='__main__':main()
