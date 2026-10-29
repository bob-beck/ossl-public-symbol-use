#!/usr/bin/env python3
"""refresh -- bring a symuse database's API surface up to an OpenSSL tree.

Replaces the symbol table with the surface of a built OpenSSL tree
(built at least as far as `make build_generated`, so the generated
public headers exist), drops symbols the tree no longer has along with
their usage rows, and fills symbol_intro with the release that first
listed each libcrypto/libssl export.  The corpora are not rescanned:
symbols added since the last scan carry no usage.

Usage:
    refresh.py <db> <built-openssl-tree> <openssl-git-dir> [--commit TEXT]

<openssl-git-dir> is any clone with the release tags; the ordinals of
OpenSSL_1_0_2 (libeay.num), OpenSSL_1_1_0, OpenSSL_1_1_1, openssl-3.6.0,
openssl-4.0.0 and openssl-4.1.0 are read from it with `git show`.
"""

import argparse
import os
import sqlite3
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import symuse  # noqa: E402

# Releases in order, with the ordinals file each one used.  For
# openssl-3.6.0 the version column dates 3.x additions; every other
# release renumbered, so presence is all that is used.
RELEASES = (
    ("1.0.2-or-earlier", "OpenSSL_1_0_2", "util/libeay.num"),
    ("1.1.0", "OpenSSL_1_1_0", "util/libcrypto.num"),
    ("1.1.1", "OpenSSL_1_1_1", "util/libcrypto.num"),
    ("3.x", "openssl-3.6.0", "util/libcrypto.num"),
    ("4.0.0", "openssl-4.0.0", "util/libcrypto.num"),
    ("4.1.0", "openssl-4.1.0", "util/libcrypto.num"),
)


def git_show(gitdir, tag, path):
    out = subprocess.run(
        ["git", "--no-optional-locks", "-C", gitdir, "show",
         "%s:%s" % (tag, path)],
        capture_output=True, text=True, check=True)
    return out.stdout


def release_names(text):
    """name -> version column (or "" when the file has none)."""
    names = {}
    for line in text.splitlines():
        parts = line.split()
        if len(parts) >= 4 and not parts[3].startswith("NOEXIST"):
            names[parts[0]] = parts[2]
        elif len(parts) == 3 and not parts[2].startswith("NOEXIST"):
            names[parts[0]] = ""
    return names


def introduced(name, releases):
    for label, names in releases:
        if name in names:
            if label == "3.x":
                return names[name].replace("_", ".")
            return label
    return "master"


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("db")
    ap.add_argument("tree")
    ap.add_argument("gitdir")
    ap.add_argument("--commit", help="text recorded as surface_tree_commit")
    args = ap.parse_args()

    db = sqlite3.connect(args.db)
    rows = []
    rows += symuse.read_num(
        os.path.join(args.tree, "util", "libcrypto.num"), "libcrypto")
    rows += symuse.read_num(
        os.path.join(args.tree, "util", "libssl.num"), "libssl")
    rows += symuse.read_headers(os.path.join(args.tree, "include", "openssl"))
    surface = {}
    for row in rows:
        surface.setdefault(row[0], row)

    old = {r[0] for r in db.execute("SELECT name FROM symbol")}
    old_dep = {r[0] for r in
               db.execute("SELECT name FROM symbol WHERE deprecated = 1")}
    gone = old - set(surface)
    db.executemany("DELETE FROM symbol WHERE name = ?", [(n,) for n in gone])
    db.executemany(
        "INSERT OR REPLACE INTO symbol"
        " (name, kind, origin, version, conditions, deprecated)"
        " VALUES (?, ?, ?, ?, ?, ?)", list(surface.values()))
    db.execute("DELETE FROM usage WHERE symbol NOT IN (SELECT name FROM symbol)")
    pairs = symuse.store_macro_calls(
        db, os.path.join(args.tree, "include", "openssl"))
    new_dep = {r[0] for r in
               db.execute("SELECT name FROM symbol WHERE deprecated = 1")}

    releases = [(label, release_names(git_show(args.gitdir, tag, path)))
                for label, tag, path in RELEASES]
    db.execute("DROP TABLE IF EXISTS symbol_intro")
    db.execute("CREATE TABLE symbol_intro"
               " (name TEXT PRIMARY KEY, introduced TEXT)")
    exports = [r[0] for r in db.execute(
        "SELECT name FROM symbol WHERE origin IN ('libcrypto', 'libssl')")]
    db.executemany("INSERT INTO symbol_intro VALUES (?, ?)",
                   [(n, introduced(n, releases)) for n in exports])

    symuse.set_meta(db, "surface_tree_commit",
                    args.commit or symuse.tree_commit(args.tree))
    symuse.set_meta(db, "surface_built", symuse.now())
    symuse.set_meta(db, "surface_note",
                    "surface refreshed without rescanning corpora; symbols"
                    " added since the scan dates carry no usage")
    db.commit()

    print("removed %d, added %d, newly deprecated %d, %d macro expansions"
          % (len(gone), len(set(surface) - old), len(new_dep - old_dep),
             pairs))
    for name in sorted(new_dep - old_dep):
        print("  deprecated: %s" % name)


if __name__ == "__main__":
    main()
