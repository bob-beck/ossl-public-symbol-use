#!/usr/bin/env python3
"""fetch -- assemble a corpus of upstream sources for symuse to scan.

Produces the only thing symuse.py needs: a directory holding one
subdirectory per project, each containing that project's unpacked
source.  Nothing is configured or built, so an unpacked tarball is the
whole requirement, and nesting inside it does not matter -- the scanner
walks recursively.

Three sources.  brew and debian fetch the packages that declare a
dependency on openssl, libressl or boringssl -- any version of any of
them -- and nothing else:

  brew     the Homebrew formula index.  One static JSON file listing
           every formula with a stable source URL and version, skewed
           towards software people actually run, and the least work to
           obtain.

  debian   the Debian source index, ranked by popcon install counts.
           Slower to assemble, but popcon is the only published proxy
           for how widely something is actually deployed.

  list     a file of URLs, one per line, either git repositories or
           source tarballs.  Taken as given, with no filtering.

Everything is idempotent: a project whose directory already exists is
skipped, so an interrupted run resumes by being run again.  Corpus
directories sitting alongside the target are consulted too, so a project
already fetched from one index is not fetched again from another; pass
--no-seen to fetch it anyway.

Usage:
    fetch.py brew   <corpus-dir> [--limit N] [--jobs N] [--no-seen]
    fetch.py debian <corpus-dir> [--limit N] [--jobs N] [--suite stable]
    fetch.py list   <corpus-dir> <urls-file> [--jobs N]
"""

import argparse
import concurrent.futures
import json
import lzma
import os
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
import threading
import urllib.error
import urllib.parse
import urllib.request
import zipfile

USER_AGENT = "symuse-fetch/0.1 (OpenSSL public symbol usage survey)"

BREW_INDEX = "https://formulae.brew.sh/api/formula.json"
DEBIAN_MIRROR = "https://deb.debian.org/debian"
POPCON_BY_INST = "https://popcon.debian.org/by_inst"

ARCHIVE_RE = re.compile(
    r"\.(tar\.(gz|xz|bz2|lz|zst)|tgz|txz|tbz2?|zip|gem|crate|src\.rpm)$", re.I)
GIT_URL_RE = re.compile(r"^git[+:]|\.git$")

# Packages that mean "this builds against an OpenSSL-family library":
# any openssl version, plus the two forks.  Everything else in an index
# is nine tenths of the bytes and none of the answer.
BREW_TLS_RE = re.compile(r"^(openssl(@[\w.]+)?|libressl|boringssl)$")
DEB_TLS_RE = re.compile(
    r"\b(openssl|libssl[\w.]*|libcrypto(?!\+\+)[\w.]*"
    r"|libressl[\w.-]*|boringssl[\w.-]*)\b")


# ------------------------------------------------------------- transport

APACHE_CLOSER_RE = re.compile(
    r"^https?://(?:www\.)?apache\.org/dyn/closer\.(?:lua|cgi)(?P<rest>.*)$")

_log_lock = threading.Lock()


def record_failure(corpus, what, reason):
    """Append a failed fetch to a log beside the corpus.

    A project that silently failed to download is indistinguishable
    afterwards from one that uses no OpenSSL, so the failures need to be
    written down somewhere they will be seen.
    """
    with _log_lock:
        try:
            with open(os.path.join(corpus, ".symuse-failures.txt"), "a",
                      encoding="utf-8") as fh:
                fh.write("%s\t%s\n" % (what, str(reason).replace("\n", " ")))
        except OSError:
            pass


def candidate_urls(url):
    """URLs to try for one source, most likely first.

    Apache's closer.lua is a mirror chooser that serves an HTML page
    rather than the file, so it is rewritten to the real download hosts:
    downloads.apache.org carries current releases and archive.apache.org
    carries everything ever published.
    """
    m = APACHE_CLOSER_RE.match(url)
    if m is None:
        return [url]
    rest = m.group("rest")
    query = urllib.parse.parse_qs(urllib.parse.urlparse(url).query)
    path = (query.get("path") or query.get("filename") or [None])[0]
    if path is None:
        path = rest.split("?")[0]
    path = path.lstrip("/")
    if not path:
        return [url]
    return ["https://downloads.apache.org/" + path,
            "https://archive.apache.org/dist/" + path]


def http_get(url, dest=None, timeout=120, retries=3):
    """Fetch a URL to bytes, or stream it to dest if given."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    last = None
    for attempt in range(retries):
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                if dest is None:
                    return resp.read()
                with open(dest, "wb") as fh:
                    shutil.copyfileobj(resp, fh)
                return None
        except (urllib.error.URLError, OSError, TimeoutError) as exc:
            last = exc
    raise last


def tar_member_filter(member, path):
    """Keep the files and directories, drop everything else.

    Only regular files get read by the scanner, so symlinks, hardlinks
    and devices are of no use here and are simply skipped.  Dropping
    them also sidesteps the standard data filter rejecting an entire
    archive over one link pointing outside the tree, which real release
    tarballs do more often than you would hope.
    """
    if not (member.isfile() or member.isdir()):
        return None
    try:
        return tarfile.data_filter(member, path)
    except tarfile.FilterError:
        return None


def unpack(archive, target):
    """Unpack archive into target, which is created.

    Members are extracted one at a time and a member that fails is
    skipped rather than abandoning the archive.  Release tarballs do
    contain self-inflicted collisions -- the same path appearing as both
    a symlink and a directory, say -- and losing one file from a project
    is much cheaper than losing the project.

    Layout inside does not matter, so no attempt is made to strip a
    leading directory component.
    """
    os.makedirs(target, exist_ok=True)
    extracted = skipped = 0
    try:
        if zipfile.is_zipfile(archive):
            with zipfile.ZipFile(archive) as zf:
                for member in zf.infolist():
                    try:
                        zf.extract(member, target)
                        extracted += 1
                    except Exception:
                        skipped += 1
        else:
            with tarfile.open(archive) as tf:
                for member in tf:
                    try:
                        tf.extract(member, target, filter=tar_member_filter)
                        extracted += 1
                    except TypeError:
                        # Python older than 3.12 has no extraction filters.
                        tf.extract(member, target)
                        extracted += 1
                    except Exception:
                        skipped += 1
    except Exception as exc:
        print("  unpack failed: %s: %s" % (os.path.basename(archive), exc),
              file=sys.stderr)
        shutil.rmtree(target, ignore_errors=True)
        return False
    if skipped:
        print("  %s: %d members skipped, %d extracted"
              % (os.path.basename(archive), skipped, extracted),
              file=sys.stderr)
    if extracted == 0:
        shutil.rmtree(target, ignore_errors=True)
        return False
    return True


def fetch_tarball(url, corpus, dirname):
    """Download and unpack one source archive.  Returns True on success.

    url may be a list, in which case the entries are alternative places
    to find the same source and are tried in order.
    """
    target = os.path.join(corpus, dirname)
    if os.path.isdir(target):
        return None                     # already have it
    urls = [url] if isinstance(url, str) else list(url)
    tmpdir = tempfile.mkdtemp(prefix="symuse-", dir=corpus)
    try:
        attempts = []
        for candidate in [c for u in urls for c in candidate_urls(u)]:
            name = os.path.basename(candidate.split("?")[0]) or "archive"
            archive = os.path.join(tmpdir, name)
            try:
                http_get(candidate, dest=archive)
            except Exception as exc:
                attempts.append((candidate, exc))
                continue
            if unpack(archive, target):
                return True
            attempts.append((candidate, "downloaded but did not unpack"))
        # Every alternative lost.  Report each with the URL that
        # produced it, since the reason usually differs between them.
        print("  fetch failed: %s" % dirname, file=sys.stderr)
        for candidate, why in attempts or [("(none)", "no candidate URL")]:
            print("      %s: %s" % (candidate, why), file=sys.stderr)
            record_failure(corpus, candidate, why)
        return False
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def clone_git(url, corpus, dirname):
    """Shallow-clone a git repository.  Returns True on success."""
    target = os.path.join(corpus, dirname)
    if os.path.isdir(target):
        return None
    try:
        out = subprocess.run(
            ["git", "clone", "--depth", "1", "--quiet", url, target],
            capture_output=True, text=True, timeout=900)
        if out.returncode != 0:
            print("  clone failed: %s: %s" % (url, out.stderr.strip()[:200]),
                  file=sys.stderr)
            record_failure(corpus, url, out.stderr.strip()[:200])
            shutil.rmtree(target, ignore_errors=True)
            return False
        shutil.rmtree(os.path.join(target, ".git"), ignore_errors=True)
        return True
    except Exception as exc:
        print("  clone failed: %s: %s" % (url, exc), file=sys.stderr)
        record_failure(corpus, url, exc)
        shutil.rmtree(target, ignore_errors=True)
        return False


def sibling_corpora(corpus):
    """Other corpus directories sitting alongside this one.

    A directory counts only if it carries the manifest this tool writes,
    so pointing the fetcher somewhere unusual cannot make it treat
    arbitrary neighbouring directories as corpora.
    """
    parent = os.path.dirname(os.path.abspath(corpus.rstrip(os.sep)))
    here = os.path.abspath(corpus.rstrip(os.sep))
    found = []
    try:
        entries = os.listdir(parent)
    except OSError:
        return found
    for e in entries:
        path = os.path.join(parent, e)
        if os.path.abspath(path) == here or not os.path.isdir(path):
            continue
        if os.path.exists(os.path.join(path, ".symuse-fetch.json")):
            found.append(path)
    return found


def drop_seen(entries, name_of, args):
    """Remove entries whose project is already present in another corpus."""
    if args.no_seen:
        return entries
    dirs = list(dict.fromkeys(
        [os.path.abspath(d) for d in (args.seen or ())]
        + sibling_corpora(args.corpus)))
    if not dirs:
        return entries
    keys = already_have(dirs)
    if not keys:
        return entries
    kept = [e for e in entries if project_key(name_of(e)) not in keys]
    print("  %d skipped, already fetched into %s"
          % (len(entries) - len(kept),
             ", ".join(os.path.basename(d) for d in dirs)), file=sys.stderr)
    return kept


def run_jobs(items, worker, jobs):
    """Run worker over items with a thread pool, reporting as it goes."""
    done = skipped = failed = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
        futures = {pool.submit(worker, item): item for item in items}
        for i, fut in enumerate(concurrent.futures.as_completed(futures), 1):
            result = fut.result()
            if result is None:
                skipped += 1
            elif result:
                done += 1
            else:
                failed += 1
            if i % 100 == 0:
                print("  %d/%d  fetched %d, already had %d, failed %d"
                      % (i, len(items), done, skipped, failed), file=sys.stderr)
    print("fetched %d, already had %d, failed %d"
          % (done, skipped, failed), file=sys.stderr)


def safe_dirname(name, version):
    """Directory name the scanner will split back into name and version."""
    name = re.sub(r"[^A-Za-z0-9._+-]", "_", name)
    version = re.sub(r"[^A-Za-z0-9._+~-]", "_", version or "")
    return "%s-%s" % (name, version) if version else name


NAME_VERSION_RE = re.compile(r"^(?P<name>.+?)[-_](?P<version>v?\d[\w.+~-]*)$")
VERSION_SUFFIX_RE = re.compile(r"[_@][0-9][0-9.]*$")


def project_key(dirname):
    """Reduce a corpus directory name to a comparable project name.

    Indexes disagree about naming -- Homebrew's openssl@3 against
    Debian's openssl, python@3.12 against python3.12 -- so the version
    and any trailing version suffix come off before comparing.  Matching
    is therefore partial: a name that fails to match is fetched again,
    which costs bandwidth and nothing else.
    """
    m = NAME_VERSION_RE.match(dirname)
    name = m.group("name") if m else dirname
    return VERSION_SUFFIX_RE.sub("", name.lower())


def already_have(dirs):
    """Project keys present in any of the given corpus directories."""
    keys = set()
    for d in dirs or ():
        try:
            entries = os.listdir(d)
        except OSError:
            print("  --seen: cannot read %s, ignoring it" % d, file=sys.stderr)
            continue
        for e in entries:
            if os.path.isdir(os.path.join(d, e)):
                keys.add(project_key(e))
    return keys


def write_manifest(corpus, source, considered, selected):
    """Record which index a corpus came from, next to the corpus itself."""
    manifest = {
        "source": source,
        "considered": considered,
        "selected": selected,
    }
    path = os.path.join(corpus, ".symuse-fetch.json")
    existing = []
    if os.path.exists(path):
        try:
            with open(path, encoding="utf-8") as fh:
                existing = json.load(fh)
        except Exception:
            existing = []
    existing.append(manifest)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(existing, fh, indent=2)


# ------------------------------------------------------------------ brew

def brew_uses_tls(formula):
    """True if a Homebrew formula declares an OpenSSL-family dependency.

    Every dependency class is consulted, including optional and
    build-only ones.
    """
    names = []
    for field in ("dependencies", "build_dependencies", "test_dependencies",
                  "recommended_dependencies", "optional_dependencies"):
        names += formula.get(field) or []
    for dep in formula.get("uses_from_macos") or []:
        names.append(dep if isinstance(dep, str) else next(iter(dep), ""))
    return any(BREW_TLS_RE.match(str(n)) for n in names)


def cmd_brew(args):
    print("fetching the Homebrew formula index", file=sys.stderr)
    index = json.loads(http_get(BREW_INDEX))
    print("  %d formulae" % len(index), file=sys.stderr)

    entries = []
    for f in index:
        name = f.get("name")
        version = (f.get("versions") or {}).get("stable") or ""
        url = ((f.get("urls") or {}).get("stable") or {}).get("url")
        if not name or not url:
            continue
        if not brew_uses_tls(f):
            continue
        entries.append((name, version, url))
    considered = len(index)
    print("  %d declare an openssl-family dependency" % len(entries),
          file=sys.stderr)
    entries = drop_seen(entries, lambda e: e[0], args)
    if args.limit:
        entries = entries[:args.limit]

    os.makedirs(args.corpus, exist_ok=True)
    write_manifest(args.corpus, "homebrew", considered, len(entries))

    def worker(entry):
        name, version, url = entry
        dirname = safe_dirname(name, version)
        if url.endswith(".git") or url.startswith("git+"):
            return clone_git(url.removeprefix("git+"), args.corpus, dirname)
        return fetch_tarball(url, args.corpus, dirname)

    run_jobs(entries, worker, args.jobs)


# ---------------------------------------------------------------- debian

def parse_control(text):
    """Yield paragraphs of an RFC822-style Debian index as dicts.

    Continuation lines (those starting with whitespace) are folded into
    the preceding field, which is how the multi-line Files field is
    carried.
    """
    para = {}
    field = None
    for line in text.splitlines():
        if not line.strip():
            if para:
                yield para
                para, field = {}, None
            continue
        if line[0] in " \t":
            if field:
                para[field] += "\n" + line.strip()
            continue
        if ":" in line:
            field, _, value = line.partition(":")
            para[field] = value.strip()
    if para:
        yield para


def upstream_version(version):
    """Strip a Debian epoch and revision to get the upstream version."""
    version = version.split(":", 1)[-1]
    return version.rsplit("-", 1)[0] if "-" in version else version


def pick_source_archive(para):
    """Choose the upstream tarball from a Sources paragraph."""
    files = para.get("Checksums-Sha256") or para.get("Files") or ""
    names = [line.split()[-1] for line in files.splitlines() if line.split()]
    for pattern in (r"\.orig\.tar\.(gz|xz|bz2)$", r"\.tar\.(gz|xz|bz2)$"):
        for name in names:
            if re.search(pattern, name):
                return name
    return None


def deb_uses_tls(para):
    """True if a Sources paragraph build-depends on an OpenSSL family library."""
    deps = " ".join(para.get(f, "") for f in
                    ("Build-Depends", "Build-Depends-Indep",
                     "Build-Depends-Arch"))
    return bool(DEB_TLS_RE.search(deps))


def load_popcon(text):
    """Map package name to install count from popcon's by_inst table.

    popcon ranks binary packages while the Sources index lists source
    packages, and the two names agree only most of the time.  Building
    the exact mapping means pulling the Packages index as well; since
    this is only used to decide what to download first, the direct name
    match is close enough and unmatched entries simply sort last.
    """
    counts = {}
    for line in text.splitlines():
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        parts = line.split()
        if len(parts) < 3 or not parts[0].isdigit():
            continue
        try:
            counts[parts[1]] = int(parts[2])
        except ValueError:
            continue
    return counts


def cmd_debian(args):
    url = "%s/dists/%s/main/source/Sources.xz" % (DEBIAN_MIRROR, args.suite)
    print("fetching %s" % url, file=sys.stderr)
    sources = lzma.decompress(http_get(url, timeout=300)).decode(
        "utf-8", "replace")

    print("fetching popcon rankings", file=sys.stderr)
    try:
        popcon = load_popcon(http_get(POPCON_BY_INST, timeout=300).decode(
            "utf-8", "replace"))
    except Exception as exc:
        print("  popcon unavailable (%s); proceeding unranked" % exc,
              file=sys.stderr)
        popcon = {}

    entries = []
    considered = 0
    for para in parse_control(sources):
        pkg = para.get("Package")
        directory = para.get("Directory")
        version = para.get("Version", "")
        if not pkg or not directory:
            continue
        considered += 1
        if not deb_uses_tls(para):
            continue
        archive = pick_source_archive(para)
        if archive is None:
            continue
        entries.append((popcon.get(pkg, 0), pkg, upstream_version(version),
                        "%s/%s/%s" % (DEBIAN_MIRROR, directory, archive)))

    entries.sort(key=lambda e: (-e[0], e[1]))
    print("  %d of %d source packages declare an openssl-family build-dep,"
          " %d of those with a popcon ranking"
          % (len(entries), considered, sum(1 for e in entries if e[0])),
          file=sys.stderr)
    entries = drop_seen(entries, lambda e: e[1], args)
    if args.limit:
        entries = entries[:args.limit]

    os.makedirs(args.corpus, exist_ok=True)
    write_manifest(args.corpus, "debian/%s" % args.suite, considered,
                   len(entries))

    def worker(entry):
        _, name, version, url = entry
        return fetch_tarball(url, args.corpus, safe_dirname(name, version))

    run_jobs(entries, worker, args.jobs)


# ------------------------------------------------------------------ list

def cmd_list(args):
    """Fetch a hand-written or generated list of URLs.

    A line may hold several whitespace-separated URLs.  They are treated
    as alternative locations for the same source, tried in order, and
    the first one names the directory -- which is how the OpenBSD
    generator offers a mirror with the upstream site behind it.
    """
    entries = []
    with open(args.urls, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            entries.append(line.split())
    entries = drop_seen(
        entries,
        lambda e: ARCHIVE_RE.sub(
            "", os.path.basename(e[0].rstrip("/").split("?")[0])),
        args)
    os.makedirs(args.corpus, exist_ok=True)
    write_manifest(args.corpus, os.path.basename(args.urls),
                   len(entries), len(entries))

    def worker(urls):
        base = os.path.basename(urls[0].rstrip("/").split("?")[0])
        # Clone only what is unmistakably a repository.  Judging by "not
        # a recognised archive suffix" instead sends .gem, .tbz, .src.rpm
        # and every other unusual packaging to git, which then fails in a
        # way that has nothing to do with the actual problem.
        if GIT_URL_RE.search(urls[0]):
            return clone_git(urls[0], args.corpus,
                             safe_dirname(base.removesuffix(".git"), ""))
        return fetch_tarball(urls, args.corpus,
                             safe_dirname(ARCHIVE_RE.sub("", base), ""))

    run_jobs(entries, worker, args.jobs)


# ------------------------------------------------------------------ main

def main():
    # --jobs is shared, and accepted either side of the subcommand so
    # that the obvious command line works whichever way round it is
    # written.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--jobs", type=int, default=8,
                        help="parallel downloads (default 8)")
    common.add_argument("--seen", action="append", metavar="DIR",
                        help="also treat DIR as already fetched; may be"
                             " repeated.  Corpus directories alongside the"
                             " target are used automatically")
    common.add_argument("--no-seen", action="store_true",
                        help="fetch everything, even projects another"
                             " corpus already has")

    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0],
                                 parents=[common])
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("brew", parents=[common],
                       help="fetch from the Homebrew formula index")
    p.add_argument("corpus", help="directory to unpack projects into")
    p.add_argument("--limit", type=int, default=0, metavar="N",
                   help="stop after N projects; 0 (the default) means all"
                        " of them.  Index order, which is alphabetical, so"
                        " this is for sizing a trial run rather than for"
                        " picking the interesting ones")
    p.set_defaults(func=cmd_brew)

    p = sub.add_parser("debian", parents=[common],
                       help="fetch Debian sources, popcon ranked")
    p.add_argument("corpus", help="directory to unpack projects into")
    p.add_argument("--limit", type=int, default=0, metavar="N",
                   help="stop after N projects; 0 (the default) means all"
                        " of them.  Ordered by popcon install count, so a"
                        " limit here takes the most widely installed N")
    p.add_argument("--suite", default="stable", metavar="SUITE",
                   help="Debian suite to read the source index from"
                        " (default stable; sid for the newest versions)")
    p.set_defaults(func=cmd_debian)

    p = sub.add_parser("list", parents=[common],
                       help="fetch a hand-written list of URLs")
    p.add_argument("corpus", help="directory to unpack projects into")
    p.add_argument("urls",
                   help="file of URLs, one per line, git repositories or"
                        " source archives; blank lines and # comments"
                        " are ignored")
    p.set_defaults(func=cmd_list)

    args = ap.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()
