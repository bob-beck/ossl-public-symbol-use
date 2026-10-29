#!/usr/bin/env python3
"""symuse -- who uses which OpenSSL public symbol.

Builds a queryable SQLite database from two ingredients:

  surface   the OpenSSL public API surface, read out of an OpenSSL
            source tree (the ordinals files and the public headers).

  scan      identifier hits for those names across a corpus of
            extracted third-party source trees.

The scan is purely lexical.  Nothing is configured, preprocessed or
built: every #ifdef branch counts, because code guarded by
LIBRESSL_VERSION_NUMBER or OPENSSL_IS_BORINGSSL is real usage of the
API even where that branch would never be compiled in a given build.

The resulting database is the deliverable.  It is meant to be published
and queried by other people, so every table carries enough provenance to
interpret a number without having been present when it was produced.

Usage:
    symuse.py surface <db> <openssl-tree>
    symuse.py scan    <db> <corpus-dir> --corpus NAME
    symuse.py report  <db> [symbol ...]
"""

import argparse
import datetime
import os
import re
import sqlite3
import subprocess
import sys

TOOL_VERSION = "0.1"

# ---------------------------------------------------------------- schema

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key         TEXT PRIMARY KEY,
    value       TEXT
);

CREATE TABLE IF NOT EXISTS symbol (
    name        TEXT PRIMARY KEY,
    kind        TEXT NOT NULL,   -- function | macro_func | macro_obj
    origin      TEXT,            -- libcrypto | libssl | header file name
    version     TEXT,            -- version the export appeared in
    conditions  TEXT,            -- DEPRECATEDIN_3_0, feature guards, ...
    deprecated  INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS project (
    id          INTEGER PRIMARY KEY,
    name        TEXT NOT NULL,
    version     TEXT,
    corpus      TEXT,            -- which index this project came from
    path        TEXT,
    is_binding  INTEGER NOT NULL DEFAULT 0,  -- binds the API wholesale
    symbols_used INTEGER NOT NULL DEFAULT 0, -- distinct names of any kind
    functions_used INTEGER NOT NULL DEFAULT 0, -- distinct exported functions
    sees_boring INTEGER NOT NULL DEFAULT 0,  -- mentions OPENSSL_IS_BORINGSSL
    sees_libre  INTEGER NOT NULL DEFAULT 0,  -- mentions LIBRESSL_VERSION_NUMBER
    UNIQUE (name, version, corpus)
);

CREATE TABLE IF NOT EXISTS usage (
    symbol      TEXT NOT NULL,
    project_id  INTEGER NOT NULL,
    hits        INTEGER NOT NULL,
    files       INTEGER NOT NULL,
    PRIMARY KEY (symbol, project_id)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS usage_by_project ON usage(project_id);

-- Public header macros and the symbols their expansion names, closed
-- transitively: a project that writes the macro uses each of these.
-- EVP_CIPHER_CTX_iv_length expands to EVP_CIPHER_CTX_get_iv_length,
-- sk_X509_pop to OPENSSL_sk_pop, ERR_raise to ERR_new and friends.
CREATE TABLE IF NOT EXISTS macro_calls (
    macro       TEXT NOT NULL,
    symbol      TEXT NOT NULL,
    PRIMARY KEY (macro, symbol)
) WITHOUT ROWID;

CREATE INDEX IF NOT EXISTS macro_calls_by_symbol ON macro_calls(symbol);

-- Headline view: each symbol with the projects that use it, directly
-- or through a public header macro that expands to it.  Bindings are
-- excluded, because a binding layer binds nearly the whole API and
-- would otherwise make every symbol look used.
CREATE VIEW IF NOT EXISTS symbol_users AS
WITH credit(symbol, project_id) AS (
    SELECT symbol, project_id FROM usage
    UNION
    SELECT mc.symbol, u.project_id
    FROM macro_calls mc JOIN usage u ON u.symbol = mc.macro
)
SELECT s.name                        AS symbol,
       s.kind                        AS kind,
       s.deprecated                  AS deprecated,
       COUNT(DISTINCT p.name)        AS users,
       GROUP_CONCAT(DISTINCT p.name) AS user_list
FROM symbol s
LEFT JOIN credit c  ON c.symbol = s.name
LEFT JOIN project p ON p.id = c.project_id AND p.is_binding = 0
GROUP BY s.name;

-- Symbols no project in the corpus mentions.  This is a lower bound on
-- obscurity, never proof of disuse: proprietary, embedded, Windows and
-- in-house code is not in any corpus here.
CREATE VIEW IF NOT EXISTS symbol_unseen AS
SELECT symbol, kind, deprecated FROM symbol_users WHERE users = 0;

-- Deprecated API that is still being called, which is the interesting
-- direction of travel.
CREATE VIEW IF NOT EXISTS deprecated_in_use AS
SELECT * FROM symbol_users WHERE deprecated = 1 AND users > 0
ORDER BY users DESC;
"""

# --------------------------------------------------------------- surface

NUM_RE = re.compile(
    r"^(?P<name>\S+)\s+(?P<ordinal>\d+)\s+(?P<version>\S+)\s+(?P<info>\S+)")
FUNC_MACRO_RE = re.compile(r"^\s*#\s*define\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\(")
OBJ_MACRO_RE = re.compile(r"^\s*#\s*define\s+(?P<name>[A-Za-z_][A-Za-z0-9_]*)\s+\S")


def read_num(path, origin):
    """Rows from a util/*.num ordinals file."""
    rows = []
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            if not line.strip() or line.startswith("#"):
                continue
            m = NUM_RE.match(line)
            if m is None:
                continue
            parts = m.group("info").split(":")
            if parts and parts[0].startswith("NOEXIST"):
                continue
            kind = parts[2].lower() if len(parts) > 2 and parts[2] else "function"
            conds = parts[3] if len(parts) > 3 else ""
            rows.append((m.group("name"), kind, origin, m.group("version"),
                         conds, 1 if "DEPRECATEDIN" in conds else 0))
    return rows


def read_headers(incdir):
    """Rows for macros defined in the public headers.

    A large part of the API as callers actually write it is macros, so
    leaving them out would miss what people type even when the call is
    ultimately a ctrl.
    """
    rows = []
    for entry in sorted(os.listdir(incdir)):
        if not (entry.endswith(".h") or entry.endswith(".h.in")):
            continue
        with open(os.path.join(incdir, entry), encoding="utf-8",
                  errors="replace") as fh:
            for line in fh:
                m = FUNC_MACRO_RE.match(line)
                if m is not None:
                    rows.append((m.group("name"), "macro_func", entry, "", "", 0))
                    continue
                m = OBJ_MACRO_RE.match(line)
                if m is not None:
                    rows.append((m.group("name"), "macro_obj", entry, "", "", 0))
    return rows


DEFINE_RE = re.compile(
    r"^[ \t]*#[ \t]*define[ \t]+([A-Za-z_][A-Za-z0-9_]*)(\([^)]*\))?"
    r"((?:[^\n\\]|\\\n|\\)*)", re.M)


def read_macro_calls(incdir, names):
    """(macro, symbol) pairs: each public header macro and the surface
    names its expansion mentions, followed through macros that expand
    to other macros."""
    direct = {}
    for entry in sorted(os.listdir(incdir)):
        if not (entry.endswith(".h") or entry.endswith(".h.in")):
            continue
        with open(os.path.join(incdir, entry), encoding="utf-8",
                  errors="replace") as fh:
            text = NOISE_RE.sub(" ", fh.read())
        for m in DEFINE_RE.finditer(text):
            macro = m.group(1)
            body = set(IDENT_RE.findall(m.group(3))) & names
            body.discard(macro)
            if body:
                direct.setdefault(macro, set()).update(body)
    pairs = set()
    for macro in direct:
        seen = set()
        todo = list(direct[macro])
        while todo:
            name = todo.pop()
            if name in seen or name == macro:
                continue
            seen.add(name)
            todo.extend(direct.get(name, ()))
        pairs.update((macro, name) for name in seen)
    return sorted(pairs)


def store_macro_calls(db, incdir):
    """Replace macro_calls from the headers in incdir, and recreate the
    views so a database made before macro_calls existed credits them."""
    names = {r[0] for r in db.execute("SELECT name FROM symbol")}
    for view in ("deprecated_in_use", "symbol_unseen", "symbol_users"):
        db.execute("DROP VIEW IF EXISTS %s" % view)
    db.executescript(SCHEMA)
    db.execute("DELETE FROM macro_calls")
    pairs = read_macro_calls(incdir, names)
    db.executemany("INSERT INTO macro_calls (macro, symbol) VALUES (?, ?)",
                   pairs)
    return len(pairs)


def tree_commit(tree):
    try:
        out = subprocess.run(
            ["git", "--no-optional-locks", "-C", tree, "rev-parse", "HEAD"],
            capture_output=True, text=True, timeout=30)
        return out.stdout.strip() or "unknown"
    except Exception:
        return "unknown"


def cmd_surface(db, args):
    tree = args.tree
    rows = []
    rows += read_num(os.path.join(tree, "util", "libcrypto.num"), "libcrypto")
    rows += read_num(os.path.join(tree, "util", "libssl.num"), "libssl")
    rows += read_headers(os.path.join(tree, "include", "openssl"))

    # Ordinals entries win over a macro of the same name: they carry the
    # version and condition metadata.
    seen = {}
    for row in rows:
        seen.setdefault(row[0], row)

    db.executemany(
        "INSERT OR REPLACE INTO symbol"
        " (name, kind, origin, version, conditions, deprecated)"
        " VALUES (?, ?, ?, ?, ?, ?)", list(seen.values()))
    pairs = store_macro_calls(db, os.path.join(tree, "include", "openssl"))
    set_meta(db, "surface_tree_commit", tree_commit(tree))
    set_meta(db, "surface_built", now())
    set_meta(db, "tool_version", TOOL_VERSION)
    db.commit()
    print("surface: %d symbols, %d macro expansions" % (len(seen), pairs),
          file=sys.stderr)


# ------------------------------------------------------------------ scan

SOURCE_EXT = {".c", ".h", ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx",
              ".m", ".mm", ".inc"}

# Comments and literals, stripped before identifiers are counted so that
# prose and error strings do not register as API use.
NOISE_RE = re.compile(
    r'"(?:\\.|[^"\\])*"'
    r"|'(?:\\.|[^'\\])*'"
    r"|/\*.*?\*/"
    r"|//[^\n]*",
    re.S)

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")


# Files excluded by name, added one at a time when found.  Nothing here
# is a class of file; each entry is a specific file someone looked at
# and decided about.  The diagnose subcommand lists the files naming
# the most symbols, which is how candidates turn up.
#
#   boringssl_prefix_symbols.h  BoringSSL's symbol prefixing header:
#       four thousand #defines, one per exported symbol, no calls.
#       Found in grpc, and in Chromium by way of its vendored grpc.
EXCLUDED_FILES = frozenset((
    "boringssl_prefix_symbols.h",
))
INCLUDE_RE = re.compile(r'#\s*include\s*[<"]openssl/')

def is_tls_library(root):
    """True if this directory is itself OpenSSL, LibreSSL, BoringSSL or
    wolfSSL.

    Such a tree names most of the API by definition and is not a
    consumer of it.  The marker is shipping the public headers next to
    an implementation of them; a distribution's package unpacks to
    exactly this, one level down or not at all.  wolfSSL keeps its
    OpenSSL compatibility headers in wolfssl/openssl and its
    implementation in wolfcrypt.
    """
    for base in (root,) + tuple(
            os.path.join(root, d) for d in _shallow_dirs(root)):
        if is_wolfssl_tree(base):
            return True
        if not os.path.isdir(os.path.join(base, "include", "openssl")):
            continue
        if (os.path.isdir(os.path.join(base, "crypto"))
                or os.path.isdir(os.path.join(base, "ssl"))):
            return True
    return False


def is_wolfssl_tree(base):
    """True if this directory is a wolfSSL source tree."""
    return (os.path.isdir(os.path.join(base, "wolfssl", "openssl"))
            and os.path.isdir(os.path.join(base, "wolfcrypt")))


def _shallow_dirs(root):
    """Immediate subdirectories, since tarballs unpack one level down."""
    try:
        return [d for d in os.listdir(root)
                if os.path.isdir(os.path.join(root, d))]
    except OSError:
        return []


def is_openssl_headers(dirpath):
    """True if this directory is a copy of the public OpenSSL headers.

    Bundled headers are the single most damaging thing to scan: they
    define the whole API, so reading one copy credits a project with
    nearly every symbol in the surface and empties the unused list.
    They also turn up in directories with arbitrary names -- vendored
    under third_party, deps, or a platform-specific include tree -- so
    the test is the directory's own contents rather than its parent's
    name.
    """
    if os.path.basename(dirpath).lower() != "openssl":
        return False
    # wolfSSL's compatibility headers: they define the OpenSSL names as
    # macros over wolfSSL's own functions.
    if os.path.basename(os.path.dirname(dirpath)).lower() == "wolfssl":
        return True
    try:
        names = set(os.listdir(dirpath))
    except OSError:
        return False
    return "opensslv.h" in names or {"ssl.h", "evp.h", "crypto.h"} <= names


VENDOR_MARKERS = ("openssl", "boringssl", "libressl", "wolfssl")


def is_vendored_source(dirpath):
    """True if this directory is a bundled TLS library's source tree.

    Vendored copies do not always keep their headers next to their
    sources -- shim carries Cryptlib/Include/openssl alongside
    Cryptlib/OpenSSL/crypto -- so the header test alone lets the
    library's own implementation through, and the project gets credited
    with OpenSSL's use of itself.  A directory named after one of the
    libraries and containing its crypto tree is that library.
    """
    if os.path.basename(dirpath).lower() not in VENDOR_MARKERS:
        return False
    return (os.path.isdir(os.path.join(dirpath, "crypto"))
            or os.path.isdir(os.path.join(dirpath, "wolfcrypt")))


def is_vendored_tls(dirpath, dirnames):
    """True if this directory holds a bundled copy of a TLS library.

    A project that vendors OpenSSL, BoringSSL, LibreSSL or wolfSSL would
    otherwise report the bundled library's own use of the API as its
    own.
    """
    return (is_openssl_headers(dirpath) or is_vendored_source(dirpath)
            or is_tls_library(dirpath))


def scan_project(root, surface):
    """Return (hits, files, saw_include, sees_boring, sees_libre)."""
    hits = {}
    files = {}
    saw_include = False
    sees_boring = False
    sees_libre = False

    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames
                       if d not in (".git", ".svn", ".hg")]
        if is_vendored_tls(dirpath, dirnames):
            dirnames[:] = []
            continue
        for fn in filenames:
            if os.path.splitext(fn)[1].lower() not in SOURCE_EXT:
                continue
            if fn in EXCLUDED_FILES:
                continue
            path = os.path.join(dirpath, fn)
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = fh.read()
            except OSError:
                continue
            if INCLUDE_RE.search(text):
                saw_include = True
            if "OPENSSL_IS_BORINGSSL" in text:
                sees_boring = True
            if "LIBRESSL_VERSION_NUMBER" in text:
                sees_libre = True

            code = NOISE_RE.sub(" ", text)
            local = set()
            for ident in IDENT_RE.findall(code):
                if ident in surface:
                    hits[ident] = hits.get(ident, 0) + 1
                    local.add(ident)
            for ident in local:
                files[ident] = files.get(ident, 0) + 1

    return hits, files, saw_include, sees_boring, sees_libre


def split_name_version(dirname):
    """Split 'curl-8.7.1' into ('curl', '8.7.1'); tolerate no version."""
    m = re.match(r"^(?P<name>.+?)[-_](?P<version>v?\d[\w.+~-]*)$", dirname)
    if m:
        return m.group("name"), m.group("version")
    return dirname, ""


def cmd_scan(db, args):
    surface = {r[0] for r in db.execute("SELECT name FROM symbol")}
    if not surface:
        sys.exit("scan: symbol surface is empty; run 'surface' first")

    entries = sorted(d for d in os.listdir(args.corpus)
                     if os.path.isdir(os.path.join(args.corpus, d)))

    # Carry the fetcher's manifest into the database, so a published
    # copy records which index the projects came from.
    manifest = os.path.join(args.corpus, ".symuse-fetch.json")
    if os.path.exists(manifest):
        try:
            with open(manifest, encoding="utf-8") as fh:
                set_meta(db, "corpus_%s_provenance" % args.corpus_name,
                         fh.read())
        except OSError:
            pass
    scanned = 0
    skipped_libraries = 0
    for i, entry in enumerate(entries, 1):
        root = os.path.join(args.corpus, entry)
        if is_tls_library(root):
            # OpenSSL, LibreSSL, BoringSSL or wolfSSL themselves.  They
            # name most of the surface and are not consumers of it.
            skipped_libraries += 1
            continue
        hits, files, saw_include, boring, libre = scan_project(root, surface)
        if not saw_include:
            # Nothing in the tree includes an openssl header, so any
            # identifier collisions here are noise, not API use.
            continue
        name, version = split_name_version(entry)
        cur = db.execute(
            "INSERT OR IGNORE INTO project"
            " (name, version, corpus, path, sees_boring, sees_libre)"
            " VALUES (?, ?, ?, ?, ?, ?)",
            (name, version, args.corpus_name, root,
             1 if boring else 0, 1 if libre else 0))
        pid = cur.lastrowid
        if not pid:
            pid = db.execute(
                "SELECT id FROM project WHERE name=? AND version=? AND corpus=?",
                (name, version, args.corpus_name)).fetchone()[0]
        db.executemany(
            "INSERT OR REPLACE INTO usage (symbol, project_id, hits, files)"
            " VALUES (?, ?, ?, ?)",
            [(s, pid, n, files.get(s, 0)) for s, n in hits.items()])
        scanned += 1
        if i % 50 == 0:
            db.commit()
            print("  %d/%d dirs, %d with openssl includes"
                  % (i, len(entries), scanned), file=sys.stderr)

    set_meta(db, "scan_%s_date" % args.corpus_name, now())
    set_meta(db, "scan_%s_projects" % args.corpus_name, str(scanned))
    db.execute(
        "UPDATE project SET symbols_used ="
        " (SELECT count(*) FROM usage WHERE usage.project_id = project.id)")
    db.commit()
    print("scan: %d projects recorded out of %d directories"
          " (%d were a TLS library itself)"
          % (scanned, len(entries), skipped_libraries), file=sys.stderr)


# -------------------------------------------------------------- diagnose

def cmd_diagnose(db, args):
    """List the individual files naming the most distinct API symbols.

    Generated tables -- bundled headers, symbol prefix maps, error code
    lists -- name a large part of the API in one file without calling
    any of it, and credit their project accordingly.  This walks the
    corpus a second time and reports per file rather than per project,
    so what such a file looks like next to hand-written source can be
    read off the data rather than assumed.
    """
    surface = dict(db.execute("SELECT name, kind FROM symbol"))
    if not surface:
        sys.exit("diagnose: symbol surface is empty; run 'surface' first")

    rows = []
    entries = sorted(d for d in os.listdir(args.corpus)
                     if os.path.isdir(os.path.join(args.corpus, d)))
    for i, entry in enumerate(entries, 1):
        root = os.path.join(args.corpus, entry)
        if is_tls_library(root):
            continue
        for dirpath, dirnames, filenames in os.walk(root):
            dirnames[:] = [d for d in dirnames
                           if d not in (".git", ".svn", ".hg")]
            if is_vendored_tls(dirpath, dirnames):
                dirnames[:] = []
                continue
            for fn in filenames:
                if os.path.splitext(fn)[1].lower() not in SOURCE_EXT:
                    continue
                path = os.path.join(dirpath, fn)
                try:
                    with open(path, encoding="utf-8", errors="replace") as fh:
                        code = NOISE_RE.sub(" ", fh.read())
                except OSError:
                    continue
                found = {ident for ident in IDENT_RE.findall(code)
                         if ident in surface}
                if not found:
                    continue
                funcs = sum(1 for f in found if surface[f] == "function")
                rows.append((len(found), funcs, entry,
                             os.path.relpath(path, root)))
        if i % 50 == 0:
            print("  %d/%d" % (i, len(entries)), file=sys.stderr)

    rows.sort(reverse=True)
    print("%7s %7s  %s" % ("symbols", "of which", ""))
    print("%7s %7s  %s" % ("named", "funcs", "project / file"))
    for total, funcs, project, path in rows[:args.top]:
        print("%7d %7d  %s / %s" % (total, funcs, project, path))


# -------------------------------------------------------------- classify

def cmd_classify(db, args):
    """Mark projects that name so much of the API they are not evidence.

    A language binding exposes the whole library to another runtime, so
    it names thousands of symbols and would give every one of them a
    user.  Real consumers name a few hundred at most, and the gap
    between the two is close to an order of magnitude, so a threshold
    separates them without anyone having to keep a list of names up to
    date.

    Classification is deliberately a separate step from scanning: the
    threshold can be revised, or an individual project corrected by
    hand, without rescanning the corpus.
    """
    rows = db.execute(
        "SELECT name, version, corpus, symbols_used FROM project"
        " ORDER BY symbols_used DESC").fetchall()
    if not rows:
        sys.exit("classify: no projects; run 'scan' first")

    if args.threshold is None:
        print("distinct symbols named, highest first -- look for the knee")
        for name, version, corpus, used in rows[:args.show]:
            print("  %6d  %s %s [%s]" % (used, name, version or "", corpus))
        print("\nthen: symuse.py classify %s --threshold N" % args.db)
        return

    db.execute("UPDATE project SET is_binding = (symbols_used >= ?)",
               (args.threshold,))
    db.commit()
    flagged = db.execute(
        "SELECT name, symbols_used FROM project WHERE is_binding = 1"
        " ORDER BY symbols_used DESC").fetchall()
    print("%d projects at or above %d symbols, now excluded from counts:"
          % (len(flagged), args.threshold), file=sys.stderr)
    for name, used in flagged:
        print("  %6d  %s" % (used, name), file=sys.stderr)


# ---------------------------------------------------------------- report

def cmd_report(db, args):
    if args.symbols:
        rows = db.execute(
            "SELECT symbol, kind, deprecated, users, user_list"
            " FROM symbol_users WHERE symbol IN (%s)"
            % ",".join("?" * len(args.symbols)), args.symbols).fetchall()
    else:
        rows = db.execute(
            "SELECT symbol, kind, deprecated, users, user_list"
            " FROM symbol_users ORDER BY users DESC, symbol LIMIT ?",
            (args.limit,)).fetchall()
    for symbol, kind, deprecated, users, user_list in rows:
        flag = " [deprecated]" if deprecated else ""
        print("%-44s %-10s %4d%s  %s"
              % (symbol, kind, users, flag, user_list or ""))


# ------------------------------------------------------------------ util

def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(
        timespec="seconds")


def set_meta(db, key, value):
    db.execute("INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)",
               (key, value))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("surface", help="load the API surface from a tree")
    p.add_argument("db", help="SQLite database to create or update")
    p.add_argument("tree", help="root of an OpenSSL source tree")
    p.set_defaults(func=cmd_surface)

    p = sub.add_parser("scan", help="scan a corpus of extracted sources")
    p.add_argument("db", help="SQLite database to create or update")
    p.add_argument("corpus",
                   help="directory holding one subdirectory per project")
    p.add_argument("--corpus", dest="corpus_name", default="unnamed",
                   metavar="NAME",
                   help="label recorded against these projects, so several"
                        " indexes can share one database")
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("diagnose",
                       help="list the files naming the most symbols")
    p.add_argument("db", help="SQLite database holding the symbol surface")
    p.add_argument("corpus",
                   help="directory holding one subdirectory per project")
    p.add_argument("--top", type=int, default=50, metavar="N",
                   help="how many files to list (default 50)")
    p.set_defaults(func=cmd_diagnose)

    p = sub.add_parser("classify",
                       help="flag projects that name too much of the API")
    p.add_argument("db", help="SQLite database to update")
    p.add_argument("--threshold", type=int, metavar="N",
                   help="mark every project naming N or more distinct"
                        " symbols as a binding, excluding it from the"
                        " counts.  With no threshold, print the"
                        " distribution instead so you can choose one")
    p.add_argument("--show", type=int, default=40, metavar="N",
                   help="rows of the distribution to print (default 40)")
    p.set_defaults(func=cmd_classify)

    p = sub.add_parser("report", help="print symbol -> users")
    p.add_argument("db", help="SQLite database to read")
    p.add_argument("symbols", nargs="*",
                   help="symbols to report on; with none, the most used")
    p.add_argument("--limit", type=int, default=50, metavar="N",
                   help="how many rows to print when no symbols are named"
                        " (default 50); ignored if symbols are given")
    p.set_defaults(func=cmd_report)

    args = ap.parse_args()
    db = sqlite3.connect(args.db)
    db.executescript(SCHEMA)
    args.func(db, args)
    db.close()


if __name__ == "__main__":
    main()
