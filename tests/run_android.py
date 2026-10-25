"""Opt-in tests against self-owned processes only. Never installs the module."""
from pathlib import Path
import argparse, hashlib, json, shlex, shutil, subprocess, uuid
ROOT = Path(__file__).resolve().parents[1]
def main():
    p = argparse.ArgumentParser(); p.add_argument('--adb', default=shutil.which('adb')); p.add_argument('--serial')
    a = p.parse_args()
    if not a.adb: p.error('Pass --adb')
    prefix = [a.adb]+(['-s', a.serial] if a.serial else [])
    rows = []
    def run(args, label):
        r = subprocess.run([*prefix, *args], capture_output=True, text=True, encoding='utf-8', errors='replace', timeout=45)
        rows.append({'label': label, 'exit': r.returncode, 'stdout': r.stdout, 'stderr': r.stderr})
        (ROOT/'build/android-tests.json').write_text(json.dumps(rows, indent=2)+'\n', encoding='utf-8')
        if r.returncode: raise SystemExit(label+' failed: '+r.stdout+r.stderr)
        print(label+': OK', flush=True); return r.stdout
    assert run(['get-state'], 'ADB ready').strip() == 'device'
    remote = '/data/local/tmp/scopedrkp_fixture_'+uuid.uuid4().hex[:12]
    run(['shell', 'mkdir '+remote], 'own temporary directory')
    names = ['libsrkp_fixture.so', 'srkp_fixture', 'srkp_inject_test']
    for n in names: run(['push', str(ROOT/'build'/n), remote+'/'+n], 'push '+n)
    hashes = run(['shell', 'cd '+remote+' && sha256sum '+' '.join(names)], 'verify copied fixture files')
    for n in names: assert hashlib.sha256((ROOT/'build'/n).read_bytes()).hexdigest()+'  '+n in hashes
    run(['shell', 'chmod 700 '+remote+'/srkp_fixture '+remote+'/srkp_inject_test'], 'owned executable permissions')
    local = run(['shell', remote+'/srkp_fixture --local-test '+remote+'/libsrkp_fixture.so'], 'local property GOT fixture')
    child = run(['shell', 'su', '-c', shlex.quote(remote+'/srkp_inject_test '+remote)], 'owned fork-child loader fixture')
    assert '"ok":true' in local and '"owned_child_injector_test":true' in child
    print(json.dumps({'ok': True, 'module_installed': False, 'system_service_touched': False, 'remote_files_retained': remote}))
if __name__ == '__main__': main()
