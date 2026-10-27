"""Build algobank/known.json: the published advisories for popular PyPI packages, unchanged.

Not shipped. Reads advisories from local git checkouts and the list of popular packages:

  git clone --depth 1 --filter=blob:none --sparse https://github.com/pypa/advisory-database
  git clone --depth 1 --filter=blob:none --sparse https://github.com/ossf/malicious-packages
  curl -o top.json https://raw.githubusercontent.com/hugovk/top-pypi-packages/main/top-pypi-packages.min.json
  python3.14 v0.1/build_cache.py top.json COUNT advisory-database malicious-packages algobank/known.json

Needs PyYAML (the PyPA advisories are YAML; they are stored as JSON). Records are copied as published:
algobank/diff.py decides what they mean, on the machine that runs it. Nothing is downloaded from PyPI and
no package is analyzed here: a pass is never stored.
"""
import datetime, json, os, subprocess, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from algobank.diff import norm

def popular(path, count):
    with open(path) as fh:
        d = json.load(fh)
    return {norm(r["project"]) for r in d["rows"][:count]}, d.get("last_update", "unknown date")

def git(repo, *args):
    return subprocess.run(["git", "-C", repo, *args], capture_output=True, text=True, check=True).stdout

def records(repo, base, names):
    """Every advisory record in the directories of the given packages (sparse checkout of just those)."""
    dirs = [d for d in git(repo, "ls-tree", "--name-only", "HEAD", base + "/").split() if norm(d.rsplit("/", 1)[-1]) in names]
    subprocess.run(["git", "-C", repo, "sparse-checkout", "set", *dirs], check=True)
    out = []
    for d in dirs:
        for f in sorted(os.listdir(os.path.join(repo, d))):
            with open(os.path.join(repo, d, f)) as fh:
                if f.endswith(".json"): out.append(json.load(fh))
                elif f.endswith((".yaml", ".yml")):
                    import yaml
                    out.append(yaml.safe_load(fh))
    return out

def main(top, count, advisory_repo, malicious_repo, out):
    names, top_date = popular(top, int(count))
    advisories, seen = [], set()
    # malicious-package reports first: when the same report also has a PYSEC alias, the MAL record is kept
    for e in records(malicious_repo, "osv/malicious/pypi", names) + records(advisory_repo, "vulns", names):
        ids = {e["id"], *e.get("aliases", [])}
        if not ids & seen:
            seen |= ids
            advisories.append(e)
    data = dict(
        date=datetime.date.today().isoformat(),
        sources=[f"top {count} PyPI packages by downloads (hugovk/top-pypi-packages, {top_date})",
                 f"pypa/advisory-database {git(advisory_repo, 'rev-parse', '--short', 'HEAD').strip()}",
                 f"ossf/malicious-packages {git(malicious_repo, 'rev-parse', '--short', 'HEAD').strip()}"],
        advisories=sorted(advisories, key=lambda e: e["id"]))
    with open(out, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=1, sort_keys=True, default=str)     # YAML dates become strings
        fh.write("\n")
    print(f"{len(advisories)} advisories for {len(names)} packages", file=sys.stderr)

if __name__ == "__main__":
    main(*sys.argv[1:])
