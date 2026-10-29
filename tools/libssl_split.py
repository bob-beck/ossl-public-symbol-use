#!/usr/bin/env python3
"""libssl_split -- split libssl-exports.csv by how libssl could keep them.

For each libcrypto function in libssl-exports.csv (public only, or
mostly, to serve libssl), follow its definition in crypto/ through the
static helpers and internal (non-exported) functions it calls, and
decide whether libssl could carry its own private copy:

    copy            stateless; nothing in the closure touches libcrypto
                    state.  A SHARED_SOURCE copy in libssl would do.
    copy-layout     stateless, but reads or writes fields of libcrypto
                    structures, so a copy bakes in libcrypto's private
                    struct layout.  Fine when the type moves with it or
                    libssl and libcrypto always come from one build.
    copy-generated  definition not found as written: macro-generated
                    ASN.1 functions, or a definition in an #included .c.
    private-export  the closure reaches libcrypto state (thread locals,
                    the error stack, library context data, locks,
                    RUN_ONCE, mutable file-scope variables).  A second
                    copy would have its own state, so libcrypto must
                    keep exporting it, privately.

Lexical, like everything here: a definition is a column-0 line holding
NAME( and not ending in ';'; the closure follows calls by name.

Usage:
    libssl_split.py <openssl-tree> <db> <libssl-exports.csv> <outdir>

Writes libssl-copy.csv and libssl-private-export.csv in <outdir>.
"""

import argparse
import collections
import csv
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import symuse  # noqa: E402

IDENT_RE = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]*)\s*\(")
KEYWORDS = frozenset(
    "if while for switch return sizeof defined case do else goto typeof"
    " __attribute__ __typeof__ va_arg offsetof".split())
TYPE_MACROS = frozenset(("STACK_OF", "LHASH_OF", "ossl_inline",
                         "ossl_unused"))
STATE_RE = re.compile(
    r"\b(ossl_lib_ctx_get_\w+|ossl_err_get_state_int|err_get_state"
    r"|ERR_STATE|CRYPTO_THREAD_\w+|RUN_ONCE\w*|__thread|_Thread_local"
    r"|ossl_init_thread\w*|CRYPTO_atomic_\w+|OPENSSL_init_crypto"
    r"|ossl_rcu_\w+)\b")
# OSSL_PARAM is a public structure: reading its fields is not layout
# coupling.
PUBLIC_STRUCT_FILES = frozenset(("crypto/params.c",))


def strip(text):
    """Remove comments and literals, keeping line structure."""
    return symuse.NOISE_RE.sub(
        lambda m: "\n" * m.group(0).count("\n") or " ", text)


def functions(text):
    """name -> (body, is_static) for each column-0 definition."""
    out = {}
    lines = text.split("\n")
    starts = [0]
    for line in lines:
        starts.append(starts[-1] + len(line) + 1)
    for i, line in enumerate(lines):
        if (not line or line[0] in " \t#{}" or "(" not in line
                or line.rstrip().endswith(";")):
            continue
        names = [n for n in CALL_RE.findall(line) if n not in TYPE_MACROS]
        if not names:
            continue
        brace = text.find("{", starts[i])
        semi = text.find(";", starts[i])
        if brace < 0 or 0 <= semi < brace:
            continue
        depth = 0
        end = brace
        while end < len(text):
            if text[end] == "{":
                depth += 1
            elif text[end] == "}":
                depth -= 1
                if depth == 0:
                    break
            end += 1
        out.setdefault(names[0], (text[brace:end + 1],
                                  line.lstrip().startswith("static")))
    return out


def mutable_globals(text):
    """File-scope variables that are not const."""
    found = set()
    depth = 0
    for line in text.split("\n"):
        if (depth == 0 and line and line[0] not in " \t#}"
                and line.rstrip().endswith(";")
                and "(" not in line.split("=")[0]
                and "typedef" not in line and "extern" not in line):
            decl = line.split("=")[0].rstrip().rstrip(";")
            if "const" in decl.split("*")[0] and "*" not in decl:
                pass
            else:
                m = re.findall(r"([A-Za-z_]\w*)\s*(\[[^\]]*\])?\s*$", decl)
                if m and len(decl.split()) >= 2:
                    found.add(m[0][0])
        depth += line.count("{") - line.count("}")
    return found


class Crypto:
    """Definitions, globals and internal functions of crypto/."""

    def __init__(self, tree):
        self.defs = {}        # name or (file, static name) -> (file, body)
        self.globals = {}     # file -> mutable file-scope variables
        self.internal = set()  # non-static function names
        for dirpath, _, filenames in os.walk(os.path.join(tree, "crypto")):
            for fn in filenames:
                if not fn.endswith(".c"):
                    continue
                path = os.path.join(dirpath, fn)
                rel = os.path.relpath(path, tree)
                with open(path, encoding="utf-8", errors="replace") as fh:
                    text = strip(fh.read())
                self.globals[rel] = mutable_globals(text)
                for name, (body, static) in functions(text).items():
                    key = (rel, name) if static else name
                    self.defs.setdefault(key, (rel, body))
                    if not static:
                        self.internal.add(name)

    def closure(self, name, public):
        """Follow a definition through helpers and internal calls."""
        if name not in self.defs:
            return None
        rel, body = self.defs[name]
        seen = set()
        todo = [(rel, name, body)]
        result = dict(file=rel, internal=set(), state=set(), fields=0)
        while todo:
            f, n, b = todo.pop()
            if (f, n) in seen:
                continue
            seen.add((f, n))
            result["fields"] += b.count("->")
            result["state"].update(STATE_RE.findall(b))
            result["state"].update(
                "%s@%s" % (v, f)
                for v in set(IDENT_RE.findall(b)) & self.globals.get(f, ()))
            for call in set(CALL_RE.findall(b)) - KEYWORDS:
                if (f, call) in self.defs:
                    todo.append((f, call, self.defs[(f, call)][1]))
                elif call in public or call == n:
                    continue
                elif call in self.internal and call in self.defs:
                    result["internal"].add(call)
                    g = self.defs[call]
                    todo.append((g[0], call, g[1]))
        result["size"] = len(seen)
        return result


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("tree")
    ap.add_argument("db")
    ap.add_argument("exports")
    ap.add_argument("outdir")
    args = ap.parse_args()

    with open(args.exports) as fh:
        rows = list(csv.DictReader(fh))
    db = sqlite3.connect(args.db)
    # Functions on the list are leaving the public API, so a call to one
    # of them is followed like an internal call.
    public = ({r[0] for r in db.execute("SELECT name FROM symbol")}
              - {r["symbol"] for r in rows})
    crypto = Crypto(args.tree)

    out = {"copy": [], "private": []}
    for row in rows:
        c = crypto.closure(row["symbol"], public)
        if c is None:
            share = "copy-generated"
            reason = ("not written out: macro-generated (ASN.1 functions"
                      " call the public ASN1_item_* with an exported"
                      " ITEM) or defined in an #included .c")
            source = ""
        else:
            source = c["file"]
            internal = " ".join(sorted(c["internal"])[:6])
            if c["state"]:
                share = "private-export"
                reason = "state: " + " ".join(sorted(c["state"])[:6])
            elif c["fields"] and source not in PUBLIC_STRUCT_FILES:
                share = "copy-layout"
                reason = "stateless, %d functions, reads libcrypto struct" \
                         " fields; internal calls: %s" % (c["size"], internal)
            else:
                share = "copy"
                reason = "stateless, %d functions; internal calls: %s" \
                         % (c["size"], internal)
        key = "private" if share == "private-export" else "copy"
        out[key].append(dict(row, share=share, reason=reason, source=source))

    columns = list(rows[0].keys()) + ["share", "reason", "source"]
    for key, fn in (("copy", "libssl-copy.csv"),
                    ("private", "libssl-private-export.csv")):
        rs = sorted(out[key], key=lambda r: (r["share"], r["source"],
                                             r["symbol"]))
        with open(os.path.join(args.outdir, fn), "w", newline="") as fh:
            w = csv.DictWriter(fh, columns)
            w.writeheader()
            w.writerows(rs)
        print("%-28s %4d  %s" % (fn, len(rs), dict(
            collections.Counter(r["share"] for r in rs))))


if __name__ == "__main__":
    main()
