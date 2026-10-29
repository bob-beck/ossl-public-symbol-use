#!/usr/bin/env python3
"""obsd_urls -- turn an OpenBSD ports tree into a URL list for fetch.py.

OpenBSD is the odd one out among the indexes: base ships LibreSSL, so a
port that uses the API declares it by naming crypto or ssl in WANTLIB
rather than by depending on a package.  The selection criterion is
therefore different in form but the same in substance -- anything that
links an OpenSSL-family library.

Ports name their distfile but not, reliably, where to get it: only some
carry SITES, the rest inherit it from a module.  That does not matter,
because OpenBSD mirrors every distfile it uses by name, so knowing the
filename is enough.  The mirror is emitted first and any SITES found is
emitted after it as a fallback.

Output is one line per port, tab separated: the first URL names the
directory, the rest are tried in order if it fails.

Usage:
    obsd_urls.py <ports-tree> > urls.txt
"""

import os
import re
import sys

# The CDN first: it is the one built to absorb this kind of traffic.
# ftp.openbsd.org is the project's own machine and stays as the
# fallback behind it.
MIRRORS = ("https://cdn.openbsd.org/pub/OpenBSD/distfiles/",
           "https://ftp.openbsd.org/pub/OpenBSD/distfiles/")

ASSIGN_RE = re.compile(
    r"^(?P<name>[A-Za-z_][A-Za-z0-9_-]*)\s*(?P<op>\+=|\?=|:=|=)\s*"
    r"(?P<value>.*)$")
VAR_REF_RE = re.compile(r"\$[{(]([A-Za-z_][A-Za-z0-9_-]*)[})]")
WANTS_TLS_RE = re.compile(r"(^|[^A-Za-z0-9_/])(crypto|ssl)([^A-Za-z0-9_]|$)")


def read_makefile(path, into):
    """Merge one Makefile's assignments into a variable dictionary.

    Continuation lines are joined first.  Conditional blocks are ignored
    rather than evaluated: taking every branch is fine here, because a
    wrong DISTNAME costs one failed download and a missing one costs a
    port.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            text = fh.read()
    except OSError:
        return into
    text = re.sub(r"\\\n\s*", " ", text)
    for line in text.splitlines():
        line = line.split("#", 1)[0].rstrip()
        if not line or line[0] in " \t.":
            continue
        m = ASSIGN_RE.match(line)
        if m is None:
            continue
        name, op, value = m.group("name"), m.group("op"), m.group("value")
        if op == "+=" and name in into:
            into[name] += " " + value.strip()
        elif op == "?=" and name in into:
            continue
        else:
            into[name] = value.strip()
    return into


def load_port(makefile):
    """Variables for a port, with the inherited Makefile.inc files first."""
    variables = {}
    port_dir = os.path.dirname(makefile)
    category_dir = os.path.dirname(port_dir)
    for inc in (os.path.join(category_dir, "Makefile.inc"),
                os.path.join(port_dir, "Makefile.inc")):
        if os.path.exists(inc):
            read_makefile(inc, variables)
    return read_makefile(makefile, variables)


def expand(value, variables, depth=0):
    """Substitute ${VAR} references, leaving unknown ones alone."""
    if depth > 8 or "$" not in value:
        return value
    def one(m):
        return variables.get(m.group(1), m.group(0))
    return expand(VAR_REF_RE.sub(one, value), variables, depth + 1)


def get(variables, name):
    value = variables.get(name)
    return expand(value, variables).strip() if value else ""


def uses_tls(variables, raw_text):
    """True if the port links an OpenSSL-family library."""
    if "eopenssl" in raw_text:
        return True
    return bool(WANTS_TLS_RE.search(get(variables, "WANTLIB")))


def distfiles_for(variables):
    """Candidate distfile names for a port, best guess first."""
    names = []
    explicit = get(variables, "DISTFILES")
    suffix = get(variables, "EXTRACT_SUFX") or ".tar.gz"
    if explicit:
        # DISTFILES entries may carry a :group tag or a {a,b} rename form.
        for token in explicit.split():
            token = token.split(":")[0]
            token = re.sub(r"\{.*?\}", "", token)
            if token:
                names.append(token)
    distname = get(variables, "DISTNAME")
    if distname:
        names.append(distname + suffix)
    project = get(variables, "GH_PROJECT")
    tag = get(variables, "GH_TAGNAME")
    if project and tag:
        names.append("%s-%s%s" % (project, tag, suffix))
    seen, unique = set(), []
    for n in names:
        if "$" in n or n in seen:
            continue
        seen.add(n)
        unique.append(n)
    return unique


def urls_for(variables):
    """Every URL worth trying for a port, most reliable first."""
    subdir = get(variables, "DIST_SUBDIR")
    urls = []
    for name in distfiles_for(variables):
        path = "%s/%s" % (subdir, name) if subdir else name
        for mirror in MIRRORS:
            urls.append(mirror + path)
        for site in (get(variables, "SITES") or "").split():
            if site.startswith("http"):
                urls.append(site.rstrip("/") + "/" + name)
    account = get(variables, "GH_ACCOUNT")
    project = get(variables, "GH_PROJECT")
    tag = get(variables, "GH_TAGNAME")
    if account and project and tag:
        urls.append("https://github.com/%s/%s/archive/%s.tar.gz"
                    % (account, project, tag))
    # Anything still carrying a $ went through a make construct this
    # parser does not implement -- the :S/./-/g substitution modifiers,
    # typically.  Such a URL is not a guess worth making, it is wrong.
    return [u for u in urls if "$" not in u]


def main():
    if len(sys.argv) != 2:
        sys.exit(__doc__.strip().splitlines()[-1])
    tree = sys.argv[1]

    considered = selected = emitted = 0
    for category in sorted(os.listdir(tree)):
        cat_dir = os.path.join(tree, category)
        if not os.path.isdir(cat_dir) or category.startswith("."):
            continue
        for root, dirnames, filenames in os.walk(cat_dir):
            if "Makefile" not in filenames:
                continue
            makefile = os.path.join(root, "Makefile")
            try:
                with open(makefile, encoding="utf-8", errors="replace") as fh:
                    raw = fh.read()
            except OSError:
                continue
            if "SUBDIR" in raw and "DISTNAME" not in raw:
                continue                       # category or grouping Makefile
            considered += 1
            variables = load_port(makefile)
            if not uses_tls(variables, raw):
                continue
            selected += 1
            urls = urls_for(variables)
            if not urls:
                print("no distfile resolved: %s"
                      % os.path.relpath(makefile, tree), file=sys.stderr)
                continue
            emitted += 1
            print("\t".join(urls))

    print("ports examined %d, link an openssl-family library %d,"
          " resolved to a distfile %d"
          % (considered, selected, emitted), file=sys.stderr)


if __name__ == "__main__":
    main()
