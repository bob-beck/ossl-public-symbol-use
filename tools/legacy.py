#!/usr/bin/env python3
"""legacy -- libcrypto functions for the legacy provider's algorithms.

Lists every libcrypto export guarded by one of the legacy provider's
algorithm feature guards (BF, CAST, DES, IDEA, RC2, RC4, RC5, SEED,
MD2, MD4, MDC2, RMD160, WHIRLPOOL): the low-level API, and the EVP_*()
getters that return the algorithm's EVP_CIPHER or EVP_MD.

Usage:
    legacy.py <db> <out.csv>
"""

import argparse
import csv
import re
import sqlite3

GUARDS = ("BF", "CAST", "DES", "IDEA", "RC2", "RC4", "RC5", "SEED",
          "MD2", "MD4", "MDC2", "RMD160", "WHIRLPOOL")
DEPRECATED_RE = re.compile(r"DEPRECATEDIN_([0-9_]+)")
COLUMNS = ["symbol", "family", "api", "deprecated_in", "users", "user_list"]


def main():
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("db")
    ap.add_argument("out")
    args = ap.parse_args()

    db = sqlite3.connect(args.db)
    rows = db.execute(
        "SELECT s.name, s.conditions, su.users, coalesce(su.user_list, '')"
        " FROM symbol s JOIN symbol_users su ON su.symbol = s.name"
        " WHERE s.origin = 'libcrypto'").fetchall()
    out = []
    for name, conditions, users, user_list in rows:
        guards = [g for g in (conditions or "").split(",") if g in GUARDS]
        if not guards:
            continue
        m = DEPRECATED_RE.search(conditions or "")
        out.append(dict(
            symbol=name, family=guards[0],
            api="evp-getter" if name.startswith("EVP_") else "low-level",
            deprecated_in=m.group(1).replace("_", ".") if m else "",
            users=users,
            user_list=user_list.replace(",", " ") if users <= 10 else ""))
    out.sort(key=lambda r: (GUARDS.index(r["family"]), r["api"],
                            -r["users"], r["symbol"]))
    with open(args.out, "w", newline="") as fh:
        w = csv.DictWriter(fh, COLUMNS)
        w.writeheader()
        w.writerows(out)

    print("%-10s %-10s %5s %5s %5s %8s"
          % ("family", "api", "funcs", "depr", "used", "projects"))
    for g in GUARDS:
        for api in ("low-level", "evp-getter"):
            rs = [r for r in out if r["family"] == g and r["api"] == api]
            projects = set(db.execute(
                "SELECT DISTINCT p.name FROM usage u"
                " JOIN project p ON p.id = u.project_id"
                " WHERE p.is_binding = 0 AND u.symbol IN (%s)"
                % ",".join("?" * len(rs)), [r["symbol"] for r in rs]))
            print("%-10s %-10s %5d %5d %5d %8d"
                  % (g, api, len(rs), sum(bool(r["deprecated_in"]) for r in rs),
                     sum(r["users"] > 0 for r in rs), len(projects)))


if __name__ == "__main__":
    main()
