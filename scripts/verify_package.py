"""Validate distributable contents and ELF properties without external packages."""
from pathlib import Path
import json, struct, zipfile
ROOT = Path(__file__).resolve().parents[1]
def elf(data):
    assert data[:6] == b'\x7fELF\x02\x01'
    assert struct.unpack_from('<H', data, 18)[0] == 183
    phoff, shoff = struct.unpack_from('<QQ', data, 32)
    phsize, phnum, shsize, shnum = struct.unpack_from('<HHHH', data, 54)
    assert phsize == 56 and shsize == 64
    stack = False
    for i in range(phnum):
        kind, flags, off, va, pa, fs, ms, align = struct.unpack_from('<IIQQQQQQ', data, phoff+i*phsize)
        if kind == 1: assert flags & 3 != 3 and align >= 16384
        if kind == 0x6474e551: stack = True; assert not flags & 1
    assert stack
    sections = [struct.unpack_from('<IIQQQQIIQQ', data, shoff+i*shsize) for i in range(shnum)]
    imports, exports = set(), set()
    for s in sections:
        if s[1] != 11: continue
        strings = sections[s[6]]; table = data[strings[4]:strings[4]+strings[5]]
        for at in range(s[4], s[4]+s[5], s[9]):
            name, info, other, index, value, size = struct.unpack_from('<IBBHQQ', data, at)
            end = table.find(b'\0', name); assert end >= name
            name = table[name:end].decode()
            if index == 0: imports.add(name)
            elif info >> 4 in [1, 2]: exports.add(name)
    forbidden = {'__system_property_set', 'property_set', 'setxattr', 'fsetxattr', 'mount', 'umount2', 'reboot',
                 'init_module', 'finit_module', 'delete_module', 'execve', 'system', 'popen', 'setns'}
    assert not imports & forbidden, imports & forbidden
    return imports, exports

def main():
    manifest = json.loads((ROOT/'build/manifest.json').read_text())
    path = ROOT/'dist'/manifest['zip']
    with zipfile.ZipFile(path) as z:
        assert z.testzip() is None
        names = z.namelist(); assert len(set(names)) == len(names)
        assert len(names) == 13, names
        for n in names:
            assert not n.startswith('/') and '..' not in n.split('/')
            assert not any(t in n for t in ['test', 'fixture', 'evidence', 'source/', 'profile.h', 'sepolicy', 'system.prop'])
        for n in ['lib/libscoped_rkp.so', 'bin/srkp_engine']:
            imports, exports = elf(z.read(n))
            if n.startswith('lib/'):
                assert {s for s in exports if s.startswith('srkp_')} == {'srkp_state', 'srkp_enable', 'srkp_disable'}
                assert not imports & {'ptrace', 'process_vm_writev'}
            raw = z.read(n)
            for token in [b'srkp_observe', b'srkp_test_', b'--approved-live-service-test', b'OS4.0.4.0']:
                assert token not in raw, (n, token)
    print(json.dumps({'ok': True, 'zip_entries': len(names), 'native_components': 2, 'device_profile': False}))
if __name__ == '__main__': main()
