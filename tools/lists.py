import json, sqlite3, csv, re, collections
OUT = '/sessions/vigilant-laughing-darwin/mnt/openssl/.clown/removal/'
U = {a: json.load(open('/tmp/work/use_%s.json' % a)) for a in ('ssl','apps','test','providers','fuzz')}
c = sqlite3.connect('/tmp/m.db')
rows = c.execute("""select s.name, s.conditions, su.users, coalesce(su.user_list,''), coalesce(i.introduced,'')
 from symbol s join symbol_users su on su.symbol=s.name left join symbol_intro i on i.name=s.name
 where s.origin='libcrypto' and s.deprecated=0""").fetchall()
allusers = {r[0]: r[2] for r in c.execute("select symbol, kind, users from symbol_users")}
allusers = {k: v for k, v in c.execute("select symbol, users from symbol_users")}
GUARDS = None
def family(name, cond):
    g = [x for x in (cond or '').split(',') if x and not x.startswith('DEPRECATED')]
    if g: return g[0]
    n = re.sub(r'^(d2i|i2d|i2o|o2i|i2s|s2i|i2v|v2i|i2r|r2i|PEM_read_bio|PEM_write_bio|PEM_read|PEM_write)_', '', name)
    m = re.match(r'(OSSL_[A-Z0-9]+|EVP_[A-Z0-9]+|X509V3|X509v3|[A-Za-z0-9]+)', n)
    f = m.group(1)
    return {'X509v3': 'X509V3'}.get(f, f)
pre3 = lambda v: v in ('1.0.2-or-earlier', '1.1.0', '1.1.1')
def internal(name):
    return ','.join(a for a in ('ssl','apps','providers','fuzz') if name in U[a])
recs = []
for name, cond, users, ul, intro in rows:
    if users > 1: continue
    recs.append(dict(symbol=name, family=family(name, cond), introduced=intro,
                     era='pre-3.0' if pre3(intro) else '3.0+', users=users, user=ul,
                     internal_callers=internal(name), test='y' if name in U['test'] else ''))
# traps: broken pairs
def partner(n):
    for a, b in (('_new', '_free'), ('_free', '_new'), ('_up_ref', '_free')):
        if n.endswith(a): return n[:-len(a)] + b
    return None
for r in recs:
    p = partner(r['symbol'])
    r['pair_used'] = ''
    if p and allusers.get(p, 0) > 1 and r['users'] == 0:
        r['pair_used'] = p
# ASN.1 partial family: d2i_T / i2d_T unused while T_new/T_free or the other direction used
for r in recs:
    r['asn1_partial'] = ''
    m = re.match(r'^(d2i|i2d)_(.+)$', r['symbol'])
    if m and r['users'] == 0:
        t = m.group(2)
        used = [x for x in (t + '_new', t + '_free', 'd2i_' + t, 'i2d_' + t) if allusers.get(x, 0) > 0]
        if used: r['asn1_partial'] = ' '.join(used)
cols = ['symbol','family','introduced','era','users','user','internal_callers','test','pair_used','asn1_partial']
def dump(fn, rs):
    with open(OUT + fn, 'w', newline='') as fh:
        w = csv.DictWriter(fh, cols); w.writeheader(); [w.writerow(r) for r in rs]
clean = lambda r: not r['internal_callers'] and not r['pair_used'] and not r['asn1_partial']
unused = [r for r in recs if r['users'] == 0]
single = [r for r in recs if r['users'] == 1]
A = sorted([r for r in unused if clean(r)], key=lambda r: (r['era'] != 'pre-3.0', r['family'], r['symbol']))
B = sorted([r for r in unused if not clean(r)], key=lambda r: (r['family'], r['symbol']))
C = sorted([r for r in single if not r['internal_callers']], key=lambda r: (r['user'], r['symbol']))
D = sorted([r for r in single if r['internal_callers']], key=lambda r: (r['user'], r['symbol']))
dump('A-unused-clean.csv', A); dump('B-unused-with-caveat.csv', B)
dump('C-single-user.csv', C); dump('D-single-user-internal-caller.csv', D)
def fam(rs):
    k = collections.Counter(r['family'] for r in rs); return k
tot = collections.Counter(family(n, cd) for n, cd, u, ul, i in rows)
print('A clean unused', len(A), 'pre3', sum(r['era']=='pre-3.0' for r in A), '3.0+', sum(r['era']!='pre-3.0' for r in A))
print('B unused w/ caveat', len(B), 'internal', sum(bool(r['internal_callers']) for r in B),
      'pair', sum(bool(r['pair_used']) for r in B), 'asn1', sum(bool(r['asn1_partial']) for r in B))
print('C single clean', len(C), 'D single internal', len(D))
print('C projects', len({r['user'] for r in C}))
print('--- A pre-3.0 by family (clean-unused / family-total-live)')
fa = fam([r for r in A if r['era']=='pre-3.0'])
for f, n in fa.most_common(45): print(f'{f:16}{n:5}/{tot[f]}')
print('--- A 3.0+ by family')
for f, n in fam([r for r in A if r['era']!='pre-3.0']).most_common(30): print(f'{f:16}{n:5}/{tot[f]}')
print('--- C by project (top)')
for p, n in collections.Counter(r['user'] for r in C).most_common(30): print(p, n)
json.dump(dict(tot), open('/tmp/work/famtot.json','w'))
