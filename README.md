# ossl-public-symbol-use

Which free-software projects use which 'OpenSSL' public symbol,
counting code written for forks that share the same API.

`data/symuse.db` is an SQLite database. For any
libcrypto or libssl export, or public header macro, it names the
projects whose source mentions it.

## Layout

    tools/symuse.py     surface / scan / classify / diagnose / report
    tools/fetch.py      corpus fetcher: brew, debian, list
    tools/obsd_urls.py  OpenBSD ports tree -> URL list
    tools/refresh.py    update the surface to a newer OpenSSL tree and
                        date each export by first release
    tools/removal.py    removal / deprecation candidate lists
    data/symuse.db      the database
    data/obsd-urls.txt  OpenBSD port distfile URLs used for the corpus
    data/obsd-unresolved.txt  ports whose distfile did not resolve
    results/            candidate lists; see results/README.md

## Database

Tables:

- `symbol`: name, kind (function, macro_func, macro_obj), origin
  (libcrypto, libssl or header file), conditions (deprecation and
  feature guards from the ordinals), deprecated.
- `symbol_intro`: first release listing each libcrypto/libssl export.
- `project`: one row per scanned project; `is_binding` marks projects
  that bind the API wholesale (excluded from user counts).
- `usage`: symbol x project, with hit and file counts.
- `meta`: provenance (surface commit, scan dates, corpus manifests).

Views: `symbol_users` (users and user list per symbol, bindings
excluded), `symbol_unseen`, `deprecated_in_use`.

Unused libcrypto functions, split by deprecated or not:

    sqlite3 -box data/symuse.db "SELECT su.deprecated, count(*) FROM symbol_users su JOIN symbol s ON s.name = su.symbol WHERE s.origin = 'libcrypto' AND su.users = 0 GROUP BY 1"

## Method and limits

- The scan is lexical: identifiers in C/C++/ObjC sources, comments and
  string literals stripped, every #ifdef branch counted. Nothing is
  built.
- Name collisions inflate usage, never hide it; the Linux kernel's own
  MD5, SHA256, MDC2 and similar names are the known case.
- Vendored OpenSSL/LibreSSL/BoringSSL trees are pruned, and
  `boringssl_prefix_symbols.h` is excluded by name.
- `conditions` comes only from the ordinals files, so header macros
  carry no feature guard.
- Corpora are Unix packaging only (Homebrew, Debian stable, OpenBSD
  ports). Windows, embedded and proprietary code are out of scope.

## Rebuilding

    tools/fetch.py brew   ~/corpus/brew
    tools/fetch.py debian ~/corpus/debian
    tools/fetch.py list   ~/corpus/openbsd data/obsd-urls.txt
    tools/symuse.py surface data/symuse.db <openssl-tree>
    tools/symuse.py scan data/symuse.db ~/corpus/brew --corpus brew
    tools/symuse.py scan data/symuse.db ~/corpus/debian --corpus debian
    tools/symuse.py scan data/symuse.db ~/corpus/openbsd --corpus openbsd
    sqlite3 data/symuse.db "UPDATE project SET is_binding = 1 WHERE name = 'dlang-openssl'"
    tools/refresh.py data/symuse.db <built-openssl-tree> <openssl-git-dir>
