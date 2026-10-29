import sqlite3, os, sys, json
sys.path.insert(0, '/sessions/vigilant-laughing-darwin/mnt/openssl/.clown/symbols')
import symuse
area = sys.argv[1]
c = sqlite3.connect('/tmp/m.db')
syms = {r[0] for r in c.execute("select name from symbol where origin='libcrypto'")}
hit = {}
for dp, dn, fn in os.walk(os.path.join('/tmp/full', area)):
    for f in fn:
        if os.path.splitext(f)[1] not in ('.c', '.h', '.inc'): continue
        p = os.path.join(dp, f)
        t = symuse.NOISE_RE.sub(' ', open(p, errors='replace').read())
        for i in set(symuse.IDENT_RE.findall(t)) & syms:
            hit.setdefault(i, []).append(os.path.relpath(p, '/tmp/full'))
json.dump(hit, open('/tmp/work/use_%s.json' % area, 'w'))
print(area, len(hit))
