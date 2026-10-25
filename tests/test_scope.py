"""Mocked PackageManager tests. No ADB, root, or device writes."""
from pathlib import Path
import json, os, shutil, subprocess
ROOT = Path(__file__).resolve().parents[1]
def posix(p):
    s = p.resolve().as_posix()
    return '/'+s[0].lower()+s[2:] if os.name == 'nt' else s

def main():
    shell = shutil.which('sh'); assert shell, 'POSIX shell required'
    source = (ROOT/'module/bin/scoped-rkpctl').read_text(encoding='utf-8')
    body = 'resolve_scope() {'+source.split('resolve_scope() {', 1)[1].split('\n}\n', 1)[0]+'\n}\n'
    body = body.replace('/system/bin/cmd package list packages -U --user', 'fake_pm')
    tmp = ROOT/'build/scope-tests'; (tmp/'config').mkdir(parents=True, exist_ok=True)
    mock = '''fake_pm() {
case "$2" in
 com.missing.app) return 0;;
 com.fail.query) echo 'mock transaction failed'; return 2;;
esac
printf 'package:com.example.app uid:%s\\n' "$((10001 + $1 * 100000))"
printf 'package:com.shared.app uid:%s\\n' "$((10001 + $1 * 100000))"
printf 'package:com.example.app.extra uid:54321\\n'
}
'''
    script = tmp/'run.sh'
    script.write_text('PATH=/usr/bin:/bin:$PATH\nMODDIR="'+posix(tmp)+'"\n'+mock+body+'resolve_scope\n', encoding='utf-8', newline='\n')
    cases = [('single', 'com.example.app\n', 0, '10001'), ('multiuser', 'com.example.app 10\n', 0, '1010001'),
             ('shared', 'com.example.app\ncom.shared.app\n', 0, '10001'), ('legacy', 'com.example.app 0 99999\n', 0, '10001'),
             ('missing', 'com.missing.app\n', 0, ''), ('empty', '# no packages\n', 0, ''),
             ('reject_shell', 'com.example.app;whoami\n', 1, ''), ('query_error', 'com.fail.query\n', 1, '')]
    rows = []
    for name, scope, code, want in cases:
        (tmp/'config/scope.txt').write_text(scope, encoding='utf-8', newline='\n')
        p = subprocess.run([shell, posix(script)], capture_output=True, text=True, encoding='utf-8')
        assert p.returncode == code and p.stdout.strip() == want, (name, p.returncode, p.stdout, p.stderr)
        rows.append({'case': name, 'ok': True})
    for path in [*sorted((ROOT/'module').glob('*.sh')), ROOT/'module/bin/scoped-rkpctl']:
        p = subprocess.run([shell, '-n', posix(path)], capture_output=True, text=True)
        assert p.returncode == 0, p.stderr
    (ROOT/'build/scope-tests.json').write_text(json.dumps(rows, indent=2)+'\n', encoding='utf-8')
    print(json.dumps({'ok': True, 'scope_cases': len(rows), 'all_shell_syntax': True}))
if __name__ == '__main__': main()
