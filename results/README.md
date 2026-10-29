# libcrypto removal candidates (OpenSSL 5) / deprecation (4.2)

Produced by `tools/removal.py`, `tools/legacy.py` and
`tools/libssl_split.py` from `data/symuse.db`.

- Surface: OpenSSL upstream/master 4d885b16eb (26 Oct 2026).
- Usage: brew 443 + Debian 473 + OpenBSD 113 projects (out of all projects in those ports collections), rescanned 29 Oct 2026 with wolfSSL treated as a TLS library (skipped, bundled copies pruned)
- A project counts as a user of a function when it names the function,
  or names a public header macro whose expansion reaches it (table
  `macro_calls`): `EVP_CIPHER_CTX_iv_length` credits
  `EVP_CIPHER_CTX_get_iv_length`, `sk_X509_pop` credits `OPENSSL_sk_pop`,
  `ERR_raise` credits `ERR_new`.
- Scope: libcrypto functions with 0 or 1 outside users.
- In-tree callers: ssl/, apps/, providers/, fuzz/ block a candidate;
  test/ is reported but does not block (tests can use internal headers).
- `extracted-symbols.txt`: the 407 symbols the libcmp and libcms
  extraction branches deprecate (CMP 151, CRMF 74, CMS 138, their
  d2i/i2d, and the CMS PEM/SMIME/BIO helpers). Moved out of the other
  lists into extracted.csv.

Columns:

- `family`: feature guard from the ordinals if any, else name prefix
  (d2i_/i2d_/PEM_ stripped first).
- `introduced`: first release whose ordinals list the symbol.
- `era`: pre-3.0 or 3.0+.
- `users`, `user`: outside users (bindings excluded).
- `internal_callers`: ssl / apps / providers / fuzz.
- `test`: y if test/ names it.
- `pair_used`: an unused _new/_free/_up_ref whose partner has 2+ users;
  likely reached through a macro, so probably not really unused.
- `asn1_partial`: an unused d2i_/i2d_ whose type's other functions are
  used; removing it means splitting a DECLARE_ASN1_* macro.
- `successor`: evidence the function is a documented replacement for
  something deprecated (an OSSL_DEPRECATEDIN_*_FOR("use X()") hint, a
  POD paragraph naming it beside a deprecated function, an _ex/_exN
  form, or a get0_/get1_/set1_ rename of a deprecated name or of a
  macro that now expands to it). Such a function is waiting to be
  adopted, not dead. Detects explicit replacements only: most unused
  functions from 3.0 on are new API with no such marker (211 of the
  601 dead), so treat era 3.0+ as adoption-pending by default.
- `crypto_files` (libssl-exports only): crypto/*.c files naming it;
  1 means only the definition.

## plan.csv — the whole plan in one list

`plan.csv` (2,267 rows, from `tools/plan.py`) is every public symbol the
4.2/5.0 plan changes, one row each: `in_4_2` (deprecate, or already
deprecated in X), `in_5_0` (remove, make internal, make private, move
to libapps, or move to libcmp/libcms/libx509pmi), with `users`, `user_list` (when 10
or fewer) and `introduced`. Where several decisions cover a symbol the
first wins: extraction, families, TS partial, PKCS7/TS to libcms,
libc, legacy low-level,
libssl plumbing, app only, unused-dead pool, unused-internal (make
internal), whole unused ASN.1 types, in-tree-only callers,
already deprecated and unused.

| group | rows | in 5.0 |
|---|---|---|
| extraction: libcmp, libcms | 407 | API lives in the new library |
| attribute certificates (preferred option, see `note`) | 248 | libx509pmi (tentative name) |
| CT (libcrypto and libssl) | 73 | remove |
| RFC 3779 | 59 | remove |
| ADMISSIONS | 46 | libx509pmi (tentative name) |
| ARIA | 27 | remove |
| Netscape certificate sequence | 9 | remove |
| Netscape SPKI/SPKAC (incl. NETSCAPE_SPKAC) | 17 | remove |
| TS config, TS printers | 24 | move to libapps / remove |
| PKCS7 to libcms (plausible plan, see `note`) | 124 | API lives in libcms |
| TS to libcms (plausible plan) | 158 | API lives in libcms |
| PKCS12 functions typed with PKCS7 (plausible plan) | 11 | remove; DER-based replacements |
| libc replacement | 20 | make internal or remove |
| legacy low-level API (deprecated 3.0) | 104 | remove (libdecrepit undecided) |
| libssl plumbing | 21 | make private |
| app only | 19 | move to libapps |
| unused, pre-3.0 (unused-dead pool) | 290 | remove |
| unused, pre-3.0, used inside libcrypto (unused-internal) | 289 | make internal |
| unused ASN.1 types, pre-3.0 (34 whole types; `_it` kept exported) | 89 | remove functions; template stays |
| providers/fuzz-only callers | 46 | make internal |
| already deprecated, unused | 186 | remove (or make internal) |

Not symbols, so not rows: ignoring nsCertType in v3_purp.c; the
default-provider ARIA ciphers and ARIA TLS suites; `openssl nseq`;
the libssl CT validation hooks' behaviour (SSL_CTX_new's log store);
X509_verify_cert's RFC 3779 path validation.

## The individual lists

| File | Count | Meaning |
|---|---|---|
| unused-dead.csv | 601 | Not deprecated, no users, no ssl/apps/providers/fuzz caller, no trap, and never referenced in crypto/ outside CMP/CRMF/CMS: dead code. 374 pre-3.0. |
| unused-internal.csv | 576 | As above, but referenced elsewhere in crypto/ (`crypto_refs` names the files): would become internal, not deleted. 392 pre-3.0. |
| unused-generated.csv | 479 | As above, but macro-generated (ASN.1 families, cipher getters): never written out, so not classified. 301 pre-3.0. |
| unused-with-caveat.csv | 547 | Not deprecated, no users, but an in-tree caller, a used partner, or a partial ASN.1 family. |
| single-user.csv | 303 | Not deprecated, one outside user, no in-tree caller. 85 projects. |
| single-user-internal-caller.csv | 125 | Not deprecated, one outside user and an in-tree caller. |
| extracted.csv | 366 | Rows of the lists above covered by the extraction branches; `list` says which. |
| libssl-exports.csv | 123 | Rows of the lists above that libssl calls. 71 are called only by libssl and defined in a single crypto/ file: public only to serve libssl. |
| libssl-copy.csv | 100 | libssl-exports rows libssl could carry a private copy of (`share`: copy 35, copy-layout 58, copy-generated 7). |
| libssl-private-export.csv | 23 | libssl-exports rows that reach libcrypto state, so libcrypto must keep exporting them, privately. |
| deprecated-unused.csv | 223 | Already deprecated, no users. `crypto_status`: 146 dead, 62 internal, 15 generated. 198 deprecated in 3.0. |
| deprecated-single-user.csv | 112 | Already deprecated, one user. 45 dead, 48 internal, 19 generated. qatengine (27), net-snmp (14) and shim (12) are the largest. |

`unused-dead.csv` also has `plan`:

- `deprecate 4.2, remove 5.0` (329): from before 3.0, not a successor,
  not in a decided family. The general deprecation pool.
- `CT: …` (16), `RFC 3779: …` (4), `ADMISSIONS: deprecate 4.2, move to libx509pmi` (26), and
  `Netscape: …` for any NETSCAPE_* row (none in this list): deprecate
  4.2, remove 5.0, through their own family changes.
- `attribute certificates: deprecate 4.2, move to libx509pmi` (19).
  Family membership for ADMISSIONS and attribute certificates is by
  source file (functions defined in, and ASN.1 types defined by,
  v3_admis.c and the attribute-certificate files).
- `keep: 3.0 or later, awaiting adoption` (191).
- `keep: replacement for deprecated API` (16): has a `successor`.

`libssl-exports.csv` (and the two files split from it) has `plan`:
`deprecate 4.2, make private` for 21 functions decided to be libssl's
plumbing (LIBSSL_PRIVATE in removal.py: conf_ssl_*, OSSL_ERR_STATE_*,
ERR_count_to_mark, ERR_vset_error, the poll-descriptor and SCTP BIO
helpers, X509_STORE_CTX_init_rpk, the X509_VERIFY_PARAM peername pair,
X509_chain_check_suiteb, OBJ_add_sigid, BUF_reverse) — 14 of them can
be a private copy in libssl, 7 need a private export; `CT: …` for the
16 CT rows; blank: stays public.

`libssl-copy.csv` and `libssl-private-export.csv` (from
`tools/libssl_split.py`) add `share`, `reason` and `source`. Each
function's definition is followed through its static helpers and the
internal functions it calls:

- `copy`: stateless; a SHARED_SOURCE copy in libssl would do.
- `copy-layout`: stateless, but reads libcrypto struct fields, so a copy
  bakes in libcrypto's private layout. Fine when the type moves with it
  (HPKE, CT, COMP) or libssl and libcrypto always come from one build.
- `copy-generated`: not written out (generated ASN.1, or OPENSSL_DIR_*
  in an #included .c); stateless.
- `private-export`: reaches thread locals, the error stack, library
  context data, locks, RUN_ONCE or mutable file-scope variables.

`legacy-algorithms.csv` (158, from `tools/legacy.py`): every libcrypto
function under one of the legacy provider's algorithm guards (BF, CAST,
DES, IDEA, RC2, RC4, RC5, SEED, MD2, MD4, MDC2, RMD160, WHIRLPOOL).
`api` is `low-level` (104, all deprecated in 3.0) or `evp-getter` (54,
EVP_bf_cbc() and the like, none deprecated). `user_list` is filled when
there are 10 users or fewer. The DES getters include triple-DES
(EVP_des_ede*), which the default provider implements, not legacy.

`apps-only.csv` (257): libcrypto functions, deprecated or not, with no
outside users whose only callers outside crypto/ are in apps/ (fuzz/
and test/ allowed; nothing in ssl/, providers/ or engines/). Candidates
for moving into the apps library. Columns:

- `apps_files`: the apps/ files that call it. 95 are named only by
  apps/list.c (the `openssl list` introspection: EVP_*_do_all_provided,
  names_do_all and the like).
- `crypto_callers`: function@file for each reference inside crypto/
  (CMP/CRMF/CMS excluded). The enclosing function is the last column-0
  line containing IDENT( before the reference; "(file scope)" is a
  table outside any function.
- `movable`: y when every crypto/ caller is itself a movable row, so
  the set can leave libcrypto together (160; 158 have no crypto/
  caller at all).
- `blocking_callers`: the crypto/ functions that keep it in libcrypto.
  Static helpers count as blockers even when only movable functions
  call them, so this errs toward "not movable".
- `plan`: `Netscape: deprecate 4.2, remove 5.0` for the 4
  NETSCAPE_CERT_SEQUENCE rows; `deprecate 4.2, move to libapps` for the
  36 movable functions decided to be the app's own (MOVE_TO_LIBAPPS in
  removal.py: the TS_CONF_* setters, ASN1_PCTX_*, the X509
  trust/reject setters, the *_name_hash_old pair, test and print
  helpers, X509_STORE_CTX_print_verify_cb, X509_load_http and a few
  more). Blank: stays public (including the 57 apps/list.c-only
  provider enumeration functions).

The deprecated lists add `deprecated_in` (from the DEPRECATEDIN_
condition) and `crypto_status`: `dead` (no reference anywhere in the
tree), `internal` (referenced elsewhere in crypto/, see `crypto_refs`,
or called from ssl/apps/providers/fuzz, see `internal_callers`), or
`generated` (macro-generated, not classified).

Regenerate:

    tools/removal.py data/symuse.db <built-openssl-tree> results \
        --extracted results/extracted-symbols.txt \
        --extracted-dir crypto/cmp --extracted-dir crypto/crmf \
        --extracted-dir crypto/cms
    tools/legacy.py data/symuse.db results/legacy-algorithms.csv
    tools/libssl_split.py <built-openssl-tree> data/symuse.db \
        results/libssl-exports.csv results
    tools/plan.py data/symuse.db <built-openssl-tree> results

A crypto/ line beginning in column 0 that contains NAME( and does not
end in ';' counts as the definition; any other mention is a reference.
Lexical, so a function-pointer table entry counts as a reference.
