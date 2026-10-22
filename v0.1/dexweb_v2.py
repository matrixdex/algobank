import sys, os, zipfile, glob, re, statistics as S
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgmerkle import Package, TOP
SP = sys.argv[1]
rels = []
for line in open(f"{SP}/dexweb/urls.tsv"):
    v, url, sha, fn = line.rstrip("\n").split("\t"); rels.append((v, fn))
rels.sort(key=lambda r: tuple(int(x) for x in r[0].split(".")))
res = {}
for v, fn in rels:
    z = zipfile.ZipFile(f"{SP}/dexweb/wheels/{fn}")
    files, meta = {}, ""
    for i in z.infolist():
        if i.is_dir(): continue
        if i.filename.endswith(".py"): files[i.filename] = z.read(i).decode("utf-8")
        if i.filename.endswith("METADATA"): meta = z.read(i).decode()
    pins = {}
    for m in re.finditer(r"^Requires-Dist:[ \t]*([A-Za-z0-9_.\-]+)[ \t]*(.*)$", meta, re.M):
        pins[m.group(1).lower().replace("-", "_")] = m.group(2).strip() or "unpinned"
    if "beautifulsoup4" in pins: pins["bs4"] = pins["beautifulsoup4"]     # import name != distribution name
    res[v] = (Package(files, pins), pins)
print("dependencies declared in 4.2.5:", res["4.2.5"][1] or "none")
print(f"{'ver':<7}{'nodes':>6}{'cross':>6}{'cha':>5}{'TOP':>5} | {'reuse(count)':>13}{'reuse(size)':>12} | flags / caps")
rows, prev = [], None
seen_total = scratch = incr = 0
for v, _ in rels:
    pkg = res[v][0]; nodes = pkg.nodes
    tot_n, tot_s = len(nodes), sum(n["size"] for n in nodes.values())
    cross = sum(n["stats"]["cross"] for n in nodes.values()); cha = sum(n["stats"]["cha"] for n in nodes.values())
    top = sum(1 for n in nodes.values() if TOP in n["caps"])
    flags = sorted(set().union(*[n["direct_flags"] for n in nodes.values()]))
    caps = sorted(set().union(*[n["direct_caps"] for n in nodes.values()]))
    if prev is None:
        print(f"{v:<7}{tot_n:>6}{cross:>6}{cha:>5}{top:>5} | {'-':>13}{'-':>12} | {flags or '-'} {caps or '-'}")
        incr += tot_s; scratch += tot_s
    else:
        pm = {n["merkle"] for n in prev.nodes.values()}
        re_n = [n for n in nodes.values() if n["merkle"] in pm]
        rc, rs = len(re_n) / tot_n, sum(n["size"] for n in re_n) / tot_s
        rows.append((rc, rs)); scratch += tot_s; incr += sum(n["size"] for n in nodes.values() if n["merkle"] not in pm)
        print(f"{v:<7}{tot_n:>6}{cross:>6}{cha:>5}{top:>5} | {rc:>12.0%} {rs:>11.0%} | {flags or '-'} {caps or '-'}")
    prev = pkg
print()
print("median reuse vs previous: count %.0f%%, size-weighted %.0f%%" % (100*S.median(r[0] for r in rows), 100*S.median(r[1] for r in rows)))
print(f"vetting work with previous-release reuse = {incr/scratch:.0%} of from-scratch")
last = res["4.2.5"][0].nodes
print("\n4.2.5 nodes with TOP:", [k for k, n in last.items() if TOP in n["caps"]] or "none")
print("4.2.5 rolled-up capabilities per module-level view:")
for k, n in sorted(last.items()):
    if n["caps"]: print("  ", k, sorted(n["caps"]))
