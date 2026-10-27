"""Build algobank/known.json.gz: stored reports for popular packages, and known-bad data.

Not shipped. Downloads wheels and sdists from PyPI and reads advisories from local git checkouts:

  git clone --depth 1 --filter=blob:none --sparse https://github.com/pypa/advisory-database
  git clone --depth 1 --filter=blob:none --sparse https://github.com/ossf/malicious-packages
  curl -o top.json https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json
  python3.14 v0.1/build_cache.py top.json COUNT advisory-database malicious-packages WORKDIR algobank/known.json.gz

Needs PyYAML (the PyPA advisories are YAML). Downloads go to WORKDIR and are parsed, never installed or run.
Reports are made with the same code as `algobank scope` and must be built with the Python version users run.
"""
import datetime, gzip, hashlib, json, os, subprocess, sys, urllib.request
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algobank import diff as ad

def popular(path, count):
    with open(path) as fh:
        d = json.load(fh)
    return [ad.norm(r["project"]) for r in d["rows"][:count]], d.get("last_update", "unknown date")

def git_head(repo):
    return subprocess.run(["git", "-C", repo, "rev-parse", "--short", "HEAD"], capture_output=True, text=True).stdout.strip()

def checkout(repo, base, names):
    """Sparse-checkout only the directories of the given packages."""
    have = subprocess.run(["git", "-C", repo, "ls-tree", "--name-only", "HEAD", base + "/"],
                          capture_output=True, text=True, check=True).stdout.split()
    dirs = [d for d in have if ad.norm(d.rsplit("/", 1)[-1]) in names]
    subprocess.run(["git", "-C", repo, "sparse-checkout", "set", *dirs], check=True)
    return dirs

def summary(e):
    s = e.get("summary") or e.get("details", "").strip().split("\n")[0]
    return s if len(s) <= 200 else s[:197] + "..."

def advisories(repo, base, names):
    out = []
    for d in checkout(repo, base, names):
        for f in sorted(os.listdir(os.path.join(repo, d))):
            path = os.path.join(repo, d, f)
            if f.endswith(".json"):
                with open(path) as fh: out.append(json.load(fh))
            elif f.endswith((".yaml", ".yml")):
                import yaml
                with open(path) as fh: out.append(yaml.safe_load(fh))
    return out

def known_bad(entries, names):
    releases, files, seen = {}, {}, set()
    for e in sorted(entries, key=lambda e: e["id"]):
        ids = {e["id"], *e.get("aliases", [])}
        if ids & seen:
            continue                                   # the same advisory from another source
        seen |= ids
        kind = "malicious" if e["id"].startswith("MAL-") else "vulnerability"
        for a in e.get("affected", []):
            p = a.get("package", {})
            if p.get("ecosystem") != "PyPI" or ad.norm(p.get("name", "")) not in names:
                continue
            for v in a.get("versions", []):
                releases.setdefault(f"{ad.norm(p['name'])}=={v}", []).append(dict(id=e["id"], kind=kind, summary=summary(e)))
        for f in e.get("database_specific", {}).get("iocs", {}).get("files", []):
            d = f.get("digests", {}).get("sha256")
            if d:
                files.setdefault(d, []).append(dict(id=e["id"], note=f.get("note", ", ".join(f.get("paths", [])))))
    return releases, files

def fetch(url, want, work):
    path = os.path.join(work, want)
    if os.path.exists(path):
        with open(path, "rb") as fh: data = fh.read()
        if hashlib.sha256(data).hexdigest() == want: return data
    with urllib.request.urlopen(url, timeout=300) as r:
        data = r.read()
    if hashlib.sha256(data).hexdigest() != want:
        raise ValueError(f"{url} does not match PyPI's SHA-256")
    with open(path, "wb") as fh: fh.write(data)
    return data

def reports(names, work):
    out = {}
    for name in names:
        with urllib.request.urlopen(f"https://pypi.org/pypi/{name}/json", timeout=60) as r:
            meta = json.load(r)
        version = meta["info"]["version"]
        for f in meta["urls"]:                         # every file of the latest release
            want = f["digests"]["sha256"]
            art = ad.Artifact(f["filename"], fetch(f["url"], want, work))
            try:
                rep = ad.scope_report(ad.analyze(art))
            except Exception as e:                     # an unreadable file gets no stored report
                print(f"  skipped {f['filename']}: {e}", file=sys.stderr); continue
            out[want] = dict(name=name, version=version, report=rep)
        print(f"{name} {version}: {len(meta['urls'])} files", file=sys.stderr)
    return out

def main(top, count, advisory_repo, malicious_repo, work, out):
    sys.setrecursionlimit(20000)
    os.makedirs(work, exist_ok=True)
    names, top_date = popular(top, int(count))
    entries = advisories(advisory_repo, "vulns", set(names)) + advisories(malicious_repo, "osv/malicious/pypi", set(names))
    bad_releases, bad_files = known_bad(entries, set(names))
    data = dict(
        date=datetime.date.today().isoformat(),
        python=sys.version.split()[0],
        analyzer=ad.analyzer_root(),
        sources=[f"top {count} PyPI packages by downloads (hugovk/top-pypi-packages, {top_date})",
                 f"pypa/advisory-database {git_head(advisory_repo)}",
                 f"ossf/malicious-packages {git_head(malicious_repo)}"],
        reports=reports(names, work), bad_releases=bad_releases, bad_files=bad_files)
    with open(out, "wb") as raw, gzip.GzipFile(fileobj=raw, mode="wb", mtime=0) as fh:
        fh.write(json.dumps(data, sort_keys=True, separators=(",", ":")).encode())
    print(f"{len(data['reports'])} reports, {len(bad_releases)} known-bad releases, {len(bad_files)} known malicious files",
          file=sys.stderr)

if __name__ == "__main__":
    main(*sys.argv[1:])
