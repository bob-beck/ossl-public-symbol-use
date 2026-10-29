#!/usr/bin/env python3
"""plan -- one list of every public symbol the 4.2/5.0 plan changes.

Collects the decisions recorded so far into a single CSV, one row per
symbol, each with what happens in 4.2 and what happens in 5.0.  A
symbol covered by several decisions takes the first in this order:

    extraction branches (libcmp, libcms)
    family decisions (attribute certificates, ADMISSIONS, CT, RFC 3779,
        ARIA, Netscape certificate sequences)
    TS partial (TS_CONF_*, unused TS printers)
    PKCS7 and TS to libcms, PKCS12's PKCS7-typed functions (plausible)
    libc replacements
    legacy-algorithm low-level API (already deprecated in 3.0)
    libssl plumbing made private
    app-only functions moved to libapps
    unused-dead general pool
    unused-internal (pre-3.0): make internal
    unused-generated whole ASN.1 types (pre-3.0): functions removed,
        _it kept
    providers-only and fuzz-only rows of unused-with-caveat, and
        deprecated functions with no users

Usage:
    plan.py <db> <openssl-tree> <results-dir> [<out.csv>]

Reads extracted-symbols.txt, unused-dead.csv, unused-with-caveat.csv,
apps-only.csv, libssl-exports.csv and deprecated-unused.csv from
<results-dir> (as written by removal.py).
"""

import argparse
import collections
import csv
import os
import re
import sqlite3
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import removal  # noqa: E402

LEGACY_GUARDS = ("BF", "CAST", "DES", "IDEA", "RC2", "RC4", "RC5", "SEED",
                 "MD2", "MD4", "MDC2", "RMD160", "WHIRLPOOL")
# Decided 29 Oct 2026: public functions external callers can replace
# with the C library.  BIO_snprintf and BIO_vsnprintf are already
# deprecated in 4.1.
LIBC = {
    "OPENSSL_strcasecmp": "strcasecmp (ASCII, not locale: see note)",
    "OPENSSL_strncasecmp": "strncasecmp (ASCII, not locale: see note)",
    "OPENSSL_strnlen": "strnlen",
    "OPENSSL_strlcpy": "strlcpy",
    "OPENSSL_strlcat": "strlcat",
    "OPENSSL_strtoul": "strtoul",
    "OPENSSL_gmtime": "gmtime_r / gmtime_s",
    "OPENSSL_timegm": "timegm",
    "OPENSSL_issetugid": "issetugid / getauxval(AT_SECURE)",
    "OPENSSL_DIR_read": "opendir / readdir",
    "OPENSSL_DIR_end": "closedir",
    "OSSL_sleep": "nanosleep / Sleep",
    "BUF_strdup": "strdup (or OPENSSL_strdup)",
    "BUF_strndup": "strndup (or OPENSSL_strndup)",
    "BUF_memdup": "OPENSSL_memdup",
    "BUF_strlcpy": "strlcpy",
    "BUF_strlcat": "strlcat",
    "BUF_strnlen": "strnlen",
    "BIO_snprintf": "snprintf",
    "BIO_vsnprintf": "vsnprintf",
}
# PKCS12 functions whose signatures carry the PKCS7 type.
PKCS12_PKCS7_TYPED = (
    "PKCS12_pack_p7data", "PKCS12_unpack_p7data", "PKCS12_pack_p7encdata",
    "PKCS12_pack_p7encdata_ex", "PKCS12_unpack_p7encdata",
    "PKCS12_pack_authsafes", "PKCS12_unpack_authsafes", "PKCS12_add_safe",
    "PKCS12_add_safe_ex", "PKCS12_add_safes", "PKCS12_add_safes_ex")
COLUMNS = ["symbol", "kind", "library", "group", "in_4_2", "in_5_0",
           "users", "user_list", "introduced", "note"]
DEPRECATED_RE = re.compile(r"DEPRECATEDIN_([0-9_]+)")
PEM_RE = re.compile(r"^PEM_(?:read|write)(?:_bio)?_")
PRINT_RE = re.compile(r"_print(?:_|$)")


def read_csv(path):
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


ASN1_FUNC_RE = re.compile(r"_(new|free|it|dup|print_ctx)$")
# Types whose fate is decided elsewhere.  (NETSCAPE_SPKAC is included:
# SPKI users go through NETSCAPE_SPKI_* and the public struct fields.)
UNDECIDED_TYPES = frozenset()


def asn1_type(name):
    """The ASN.1 type a generated function belongs to."""
    return ASN1_FUNC_RE.sub("", re.sub(r"^(d2i|i2d)_", "", name))


def file_family(name, families, label):
    """True if name belongs to a removal.decided_families() group."""
    if families.get(name) == label:
        return True
    bare = PEM_RE.sub("", re.sub(r"^(d2i|i2d)_", "", name))
    return any(bare == t or bare.startswith(t + "_")
               for t in families.get("__types__" + label, ()))


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("db")
    ap.add_argument("tree")
    ap.add_argument("results")
    ap.add_argument("out", nargs="?")
    args = ap.parse_args()
    out_path = args.out or os.path.join(args.results, "plan.csv")

    db = sqlite3.connect(args.db)
    symbols = {}
    for name, kind, origin, conditions, deprecated, users, user_list, intro \
            in db.execute(
                "SELECT s.name, s.kind, s.origin, coalesce(s.conditions, ''),"
                "       s.deprecated, su.users, coalesce(su.user_list, ''),"
                "       coalesce(i.introduced, '')"
                " FROM symbol s JOIN symbol_users su ON su.symbol = s.name"
                " LEFT JOIN symbol_intro i ON i.name = s.name"):
        symbols[name] = dict(kind=kind, origin=origin, conditions=conditions,
                             deprecated=deprecated, users=users,
                             user_list=user_list, introduced=intro)
    exports = {n for n, s in symbols.items()
               if s["origin"] in ("libcrypto", "libssl")}

    def guards(name):
        return [g for g in symbols[name]["conditions"].split(",") if g]

    def dep_in(name):
        m = DEPRECATED_RE.search(symbols[name]["conditions"])
        return m.group(1).replace("_", ".") if m else ""

    def already_or(version, name):
        d = dep_in(name)
        return "already deprecated in %s" % d if d else version

    rows = {}

    def add(name, group, in_4_2, in_5_0, note=""):
        if name in rows or name not in symbols:
            return
        rows[name] = dict(symbol=name, group=group, in_4_2=in_4_2,
                          in_5_0=in_5_0, note=note)

    R = args.results
    # 1. Extraction branches.
    with open(os.path.join(R, "extracted-symbols.txt")) as fh:
        for name in fh.read().split():
            lib = ("libcmp" if set(guards(name)) & {"CMP", "CRMF"}
                   else "libcms")
            add(name, "extraction: " + lib, "deprecate (branch says 4.1)",
                "remove; API lives in " + lib,
                "Bob's %s branch" % lib)

    # 2. Family decisions.
    families = removal.decided_families(args.tree)
    for name in sorted(exports):
        if file_family(name, families, removal.ACERT_PLAN):
            add(name, "attribute certificates", already_or("deprecate", name),
                "remove; API lives in libx509pmi (tentative name)",
                "preferred option; moved like libcmp/libcms; the library"
                " registers the extensions"
                " only once 5.0 drops them from standard_exts.h")
    for name in sorted(exports):
        if file_family(name, families, removal.ADMISSIONS_PLAN):
            add(name, "ADMISSIONS", already_or("deprecate", name),
                "remove; API lives in libx509pmi (tentative name)",
                "in use in German healthcare (eHBA) and legal sectors;"
                " not attribute-certificate code, grouped with it")
    for guard, label, note in (
            ("CT", "CT", "libssl CT validation and log store go too"),
            ("RFC3779", "RFC 3779",
             "X509_verify_cert stops RFC 3779 path validation"),
            ("ARIA", "ARIA",
             "also the default-provider ARIA ciphers and the ARIA TLS"
             " suites; NIDs stay")):
        for name in sorted(exports):
            if guard in guards(name):
                add(name, label, already_or("deprecate", name), "remove", note)
    for name in sorted(symbols):
        if "NETSCAPE_CERT_SEQUENCE" in name and (
                name in exports or symbols[name]["kind"] != "macro_obj"):
            add(name, "Netscape certificate sequence",
                already_or("deprecate", name), "remove",
                "with `openssl nseq`")
    for name in sorted(exports):
        if "NETSCAPE_SPKI" in name or "NETSCAPE_SPKAC" in name:
            add(name, "Netscape SPKI/SPKAC", already_or("deprecate", name),
                "remove",
                "with `openssl spkac` and `ca -spkac`; Node, PHP and Ruby"
                " expose it in their own APIs")

    # 3. TS partial.
    for name in sorted(exports):
        if name.startswith("TS_CONF_"):
            add(name, "TS config", already_or("deprecate", name),
                "move to libapps", "only apps/ts.c")
        elif ("TS" in guards(name) and PRINT_RE.search(name)
              and symbols[name]["users"] == 0):
            add(name, "TS printers", already_or("deprecate", name),
                "move to libapps or remove")

    # 3a. PKCS7 and TS into libcms; PKCS12's PKCS7-typed functions get
    # DER-based replacements.  Plausible plan, 29 Oct 2026.
    for name in sorted(exports):
        if "PKCS7" in name and not name.startswith("PKCS12_"):
            add(name, "PKCS7 to libcms", already_or("deprecate", name),
                "remove; API lives in libcms",
                "plausible plan; libcrypto keeps a private ContentInfo /"
                " data / encryptedData copy for PKCS12")
    for name in sorted(exports):
        if "TS" in guards(name):
            add(name, "TS to libcms", already_or("deprecate", name),
                "remove; API lives in libcms",
                "plausible plan; TS is built on PKCS7 signedData")
    for name in PKCS12_PKCS7_TYPED:
        add(name, "PKCS12 PKCS7-typed", already_or("deprecate", name),
            "remove; use the DER-based replacements",
            "plausible plan; replacements: PKCS12_get1_safebags and"
            " DER pack/unpack functions (not yet written)")

    # 4. libc replacements.
    for name, repl in LIBC.items():
        add(name, "libc replacement", already_or("deprecate", name),
            "make internal or remove", "use " + repl)

    # 5. Legacy-algorithm low-level API.
    for name in sorted(exports):
        g = guards(name)
        if (set(g) & set(LEGACY_GUARDS) and not name.startswith("EVP_")
                and symbols[name]["deprecated"]):
            add(name, "legacy low-level API", already_or("", name),
                "remove from libcrypto (libdecrepit undecided)",
                "use EVP with the legacy provider")

    # 6. libssl plumbing.
    for r in read_csv(os.path.join(R, "libssl-exports.csv")):
        if r.get("plan") == removal.LIBSSL_PRIVATE_PLAN:
            add(r["symbol"], "libssl plumbing", "deprecate",
                "make private (libssl keeps a copy or private export)")

    # 7. App-only functions.
    for r in read_csv(os.path.join(R, "apps-only.csv")):
        if r.get("plan") == removal.MOVE_TO_LIBAPPS_PLAN:
            add(r["symbol"], "app only", already_or("deprecate", r["symbol"]),
                "move to libapps", r["apps_files"])

    # 8. General pool.
    for r in read_csv(os.path.join(R, "unused-dead.csv")):
        if r.get("plan") == "deprecate 4.2, remove 5.0":
            add(r["symbol"], "unused, pre-3.0: " + r["family"], "deprecate",
                "remove")

    # 8a. Unused, pre-3.0, but called inside libcrypto: make internal.
    for r in read_csv(os.path.join(R, "unused-internal.csv")):
        if r["era"] == "pre-3.0" and not r["successor"]:
            add(r["symbol"], "unused, pre-3.0, used inside libcrypto: "
                + r["family"], "deprecate", "make internal",
                "called from " + r["crypto_refs"])

    # 8b. Generated ASN.1 types no outside project uses at all: the
    # functions go, the _it template stays exported because third-party
    # templates reach it through token-pasting macros the scan cannot see.
    generated = [r for r in read_csv(os.path.join(R, "unused-generated.csv"))
                 if r["era"] == "pre-3.0" and not r["successor"]]
    by_type = collections.defaultdict(list)
    for r in generated:
        by_type[asn1_type(r["symbol"])].append(r["symbol"])
    for t, names in sorted(by_type.items()):
        if t in UNDECIDED_TYPES:
            continue
        family_members = [x for x in (t + "_new", t + "_free", t + "_it",
                                      "d2i_" + t, "i2d_" + t, t + "_dup")
                          if x in symbols]
        if len(family_members) < 2 or any(symbols[x]["users"]
                                          for x in family_members):
            continue
        for name in names:
            if name.endswith("_it"):
                continue
            add(name, "unused ASN.1 type, pre-3.0: " + t, "deprecate",
                "remove (the type's template stays, internal and as "
                + t + "_it)")

    # 9. In-tree-only callers, and deprecated functions nobody uses.
    for r in read_csv(os.path.join(R, "unused-with-caveat.csv")):
        callers = set(filter(None, r["internal_callers"].split(",")))
        if (r["era"] != "pre-3.0" or r["successor"] or r["pair_used"]
                or r["asn1_partial"] or not callers):
            continue
        if callers <= {"providers", "fuzz"}:
            add(r["symbol"], "unused, pre-3.0, in-tree callers only: "
                + r["family"], "deprecate", "make internal",
                "called from " + ",".join(sorted(callers)))
    for r in read_csv(os.path.join(R, "deprecated-unused.csv")):
        add(r["symbol"], "already deprecated, unused: " + r["family"],
            "already deprecated in " + r["deprecated_in"],
            "remove" if r["crypto_status"] != "internal" else "make internal")

    out = []
    for name, row in rows.items():
        s = symbols[name]
        row.update(kind=s["kind"], library=(
            s["origin"] if s["origin"] in ("libcrypto", "libssl")
            else "header " + s["origin"]),
            users=s["users"],
            user_list=(s["user_list"].replace(",", " ")
                       if s["users"] <= 10 else ""),
            introduced=s["introduced"])
        out.append(row)
    out.sort(key=lambda r: (r["group"],
                            r["symbol"]))
    with open(out_path, "w", newline="") as fh:
        w = csv.DictWriter(fh, COLUMNS)
        w.writeheader()
        w.writerows(out)

    by = collections.Counter(r["group"].split(":")[0] for r in out)
    for group, n in sorted(by.items()):
        print("%-48s %5d" % (group, n))
    print("%-59s %5d" % ("total", len(out)))


if __name__ == "__main__":
    main()
