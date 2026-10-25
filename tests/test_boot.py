"""Exercise the installed controller with mocked Android providers and loader."""
from pathlib import Path
import json, os, shutil, subprocess, time
ROOT = Path(__file__).resolve().parents[1]
def posix(p):
    s=p.resolve().as_posix()
    return '/'+s[0].lower()+s[2:] if os.name=='nt' else s

def main():
    shell=shutil.which('sh'); assert shell
    source=(ROOT/'module/bin/scoped-rkpctl').read_text(encoding='utf-8')
    cases=['success','disabled','removed','previous_failure','engine_failure','already_loaded','empty_scope','not_cn','busy']
    rows=[]
    run_root=ROOT/'build'/('boot-tests-'+str(time.time_ns()))
    for case in cases:
        root=run_root/case
        for sub in ['bin','config','state','providers']:(root/sub).mkdir(parents=True,exist_ok=True)
        (root/'config/autostart').write_text('0\n' if case=='disabled' else '1\n')
        (root/'config/scope.txt').write_text('' if case=='empty_scope' else 'com.example.app\n')
        if case=='removed':(root/'remove').write_text('')
        if case=='previous_failure':(root/'state/startup.failed').write_text('previous attempt\n')
        base=posix(root)
        script=root/'bin/scoped-rkpctl'
        text=source.replace('[ "$MODDIR" = /data/adb/modules/scoped_rkp ]','[ "$MODDIR" = "'+base+'" ]')
        for command in ['pidof','flock','getprop','am','cmd']:
            text=text.replace('/system/bin/'+command,'"'+posix(root/'providers'/command)+'"')
        text=text.replace('set -eu','set -eu\nPATH="'+posix(root/'providers')+':/usr/bin:/bin:$PATH"')
        script.write_text(text,encoding='utf-8',newline='\n')
        providers={
          'id':'echo 0', 'pidof':'echo 1234', 'sync':':',
          'flock':'exit 1' if case=='busy' else 'exit 0',
          'getprop':'case "$1" in sys.boot_completed) echo 1;; ro.boot.hwc) echo '+('GLOBAL' if case=='not_cn' else 'CN')+';; esac',
          'am':'echo RUNNING_UNLOCKED',
          'cmd':'echo package:com.example.app uid:10001',
        }
        for name,body in providers.items():
            p=root/'providers'/name;p.write_text('#!/bin/sh\n'+body+'\n',newline='\n');p.chmod(0o755)
        loaded='true' if case=='already_loaded' else 'false'
        engine=root/'bin/srkp_engine'
        engine.write_text('#!/bin/sh\ncase "$1" in\nstatus) echo \'{"loaded":'+loaded+',"compatible":true}\';;\n'
          'enable|disable) echo "$1" >> "'+base+'/calls"; '+('exit 8' if case=='engine_failure' else 'exit 0')+';;\nesac\n',newline='\n')
        engine.chmod(0o755)
        p=subprocess.run([shell,posix(script),'boot'],capture_output=True,text=True)
        expected=1 if case=='engine_failure' else 0
        assert p.returncode==expected,(case,p.returncode,p.stderr)
        calls=(root/'calls').read_text().splitlines() if (root/'calls').exists() else []
        want=['enable'] if case in ['success','engine_failure'] else (['disable'] if case=='empty_scope' else [])
        assert calls==want,(case,calls)
        assert (root/'state/startup.failed').exists()==(case in ['previous_failure','engine_failure'])
        if case=='engine_failure':
            again=subprocess.run([shell,posix(script),'boot'],capture_output=True,text=True)
            assert again.returncode==0 and (root/'calls').read_text().splitlines()==['enable']
        rows.append({'case':case,'ok':True})
    (ROOT/'build/boot-tests.json').write_text(json.dumps(rows,indent=2)+'\n')
    print(json.dumps({'ok':True,'boot_cases':len(rows),'real_loader_used':False}))
if __name__=='__main__':main()
