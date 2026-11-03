# BUILD THE ALGOBANK DEX
# run in site/:  python run.py
# needs dexweb; algobank it and everything it calls first (see the Usage page)

import html, json, os, re, shutil, subprocess
from dexweb import dexgen

# THE INDEX IS THE BANK: rendered from bank.jsonl on the live branch, every build
subprocess.run(["git", "fetch", "-q", "origin", "live"], check=True)
bank = subprocess.run(["git", "show", "origin/live:bank.jsonl"], capture_output=True, text=True, check=True).stdout
records = [json.loads(line) for line in bank.splitlines() if line.strip()]

# THE CODE ROOT AS A STRIP: every banked version is analyzed again at each build. A code root is defined by the
# version of Algobank that computed it, so each record is checked by the algobank its record names (algobanked_by),
# run alone in its own Python. That algobank must itself be in the bank.
import hashlib, math, sys, tempfile, zipfile
sys.path.insert(0, "..")
from algobank.diff import vkey
HIGH = {"network", "process", "env", "native", "TOP"}
WORKER = r"""
import json, os, sys
sys.path.insert(0, sys.argv[1])
from algobank import diff as ad
from algobank.pkgmerkle import Package
out = []
for kind, path in json.loads(sys.stdin.read()):
    if kind == "file":
        p = ad.analyze(ad.Artifact(os.path.basename(path), open(path, "rb").read()))["pkg"]
    else:
        p = Package({os.path.relpath(os.path.join(d, f), path): open(os.path.join(d, f)).read()
                     for d, _, fs in os.walk(path) for f in fs if f.endswith(".py")})
    out.append(dict(root=p.root(), nodes={n: [x["own"], x["size"], sorted(x["caps"])] for n, x in p.nodes.items()}))
print(json.dumps(out))
"""
by_key = {(r["name"], r["version"]): r for r in records}
def prev_of(r):
    older = [x for x in records if x["name"] == r["name"] and vkey(x["version"]) < vkey(r["version"])]
    return max(older, key=lambda x: vkey(x["version"])) if older else None
def analyzer_of(r):
    m = re.match(r"algobank (\S+)", r.get("algobanked_by", ""))
    if not m or ("algobank", m.group(1)) not in by_key:
        sys.exit(f"{r['name']} {r['version']}: algobanked_by names no algobank that is in the bank")
    return m.group(1)
tmp = tempfile.mkdtemp()
inputs = {}                                                 # (name, version) -> ("file", path) or ("tree", folder)
for r in records:
    key = (r["name"], r["version"])
    if r.get("file"):                                       # the file itself, from PyPI, checked against the bank
        subprocess.run([sys.executable, "-m", "pip", "download", "-q", "--no-deps", "--only-binary", ":all:", "-d", tmp,
                        f"{r['name']}=={r['version']}"], check=True)
        path = os.path.join(tmp, r["file"])
        if hashlib.sha256(open(path, "rb").read()).hexdigest() != r["sha256"]:
            sys.exit(f"{r['file']}: SHA-256 differs from bank.jsonl")
        inputs[key] = ("file", path)
    else:                                                   # no file: the source commit named in the record
        commit = re.fullmatch(r"https://github\.com/matrixdex/algobank/tree/([0-9a-f]+)", r["source"]).group(1)
        folder = os.path.join(tmp, f"src-{commit}")
        os.makedirs(folder, exist_ok=True)
        archive = subprocess.run(["git", "archive", commit, "algobank"], cwd="..", capture_output=True, check=True).stdout
        subprocess.run(["tar", "-x", "-C", folder], input=archive, check=True)
        inputs[key] = ("tree", folder)
def analyzer_dir(version):                                  # a folder holding that version's algobank/ package
    kind, path = inputs[("algobank", version)]
    if kind == "tree": return path
    folder = os.path.join(tmp, f"algobank-{version}")
    with zipfile.ZipFile(path) as z:
        z.extractall(folder, [m for m in z.namelist() if m.startswith("algobank/")])
    return folder
jobs = {}                                                   # analyzer version -> versions it analyzes
for r in records:
    v = analyzer_of(r)
    jobs.setdefault(v, []).append((r["name"], r["version"]))
    if prev_of(r): jobs[v].append((prev_of(r)["name"], prev_of(r)["version"]))
nodes = {}                                                  # (name, version, analyzer) -> the nodes of that version
for v, keys in jobs.items():
    keys = sorted(set(keys))
    res = subprocess.run([sys.executable, "-I", "-c", WORKER, analyzer_dir(v)], input=json.dumps([inputs[k] for k in keys]),
                         capture_output=True, text=True, check=True).stdout
    for k, x in zip(keys, json.loads(res)):
        nodes[k + (v,)] = dict(root=x["root"], nodes={n: dict(own=o, size=sz, caps=set(c)) for n, (o, sz, c) in x["nodes"].items()})
for r in records:
    if nodes[(r["name"], r["version"], analyzer_of(r))]["root"] != r["code_root"]:
        sys.exit(f"{r['name']} {r['version']}: code root differs from bank.jsonl (computed by algobank {analyzer_of(r)})")
shutil.rmtree(tmp)
def strip(r):                                               # one slice per node, sized by its code; yellow: own code changed
    v = analyzer_of(r)                                      # both versions by the same algobank, so own hashes compare
    new = nodes[(r["name"], r["version"], v)]["nodes"]
    prev = prev_of(r)
    old = nodes[(prev["name"], prev["version"], v)]["nodes"] if prev else None
    ids = sorted(set(new) | set(old or {}))                 # a removed node keeps its place
    size = {n: math.sqrt(max((new.get(n) or old.get(n))["size"], 1)) for n in ids}
    total, x, slices, marks, red = sum(size.values()), 0.0, [], [], 0
    for n in ids:
        w = 100 * size[n] / total
        changed = old is not None and (n not in new or n not in old or old[n]["own"] != new[n]["own"])
        if n in new:
            caps = new[n]["caps"]
            tone = "red" if caps & HIGH else "file" if "file" in caps else "none"
            red += tone == "red"
            slices.append(f"<rect class='{tone}{' dim' if old is not None and not changed else ''}' x='{x:.2f}' width='{w:.2f}' height='10'/>")
        if changed:
            mw = max(w, 2.5)
            marks.append(f"<rect class='chg' x='{x + w / 2 - mw / 2:.2f}' width='{mw:.2f}' height='10'/>")
        x += w
    label = (f"code root {r['code_root']}. {len(new)} parts. {red} can reach the network, processes, the environment, native code "
             "or code Algobank cannot see." + (f" {len(marks)} changed since {prev['version']}." if prev else " First version in the bank."))
    return (f"<svg class='root' viewBox='0 0 100 10' preserveAspectRatio='none' role='img' aria-label='{esc(label)}'>"
            f"<title>{esc(label)}</title>{''.join(slices)}{''.join(marks)}</svg>")

def esc(v): return html.escape(str(v))
def copy(h): return f"<button type='button' class='copy' data-copy='{esc(h)}' aria-label='copy {esc(h)}'>copy</button>"
def short(h):                                               # a hash in full; CSS shows what fits, then an ellipsis; a copy button
    return f"<code class='hash'>{esc(h)}</code>{copy(h)}"
def text(v):                                                # any 64-character hash inside a text is shortened too
    return re.sub(r"[0-9a-f]{64}", lambda m: short(m.group(0)), esc(v))
def scope(r):
    return ", ".join("<code class='top'>TOP</code>" if s == "TOP" else esc(s) for s in r["scope"]) or "none"
def findings(f, keys=("high", "warning")):
    colors = {"high": "high", "warning": "warning", "medium": "medium", "low": "low"}
    return " ".join(f"<span class='{colors.get(k, '') if f[k] else ''}'>{f[k]} {k}</span>" for k in keys)
def count(f, k):                                            # one finding count, colored when it is not zero
    return f"<span class='{k if f[k] else ''}'>{f[k]}</span>"
def details(r):                                             # every field of the record, in the order of the file
    rows = [("version", esc(r["version"])), ("admitted", esc(r["admitted"])), ("scope", scope(r)),
            ("findings", findings(r["findings"], ("high", "warning", "medium", "low", "info")))]
    rows += [(k.replace("_", " "), short(r[k]) if k == "sha256" else strip(r) + copy(r[k]) if k == "code_root" else text(r[k]))
             for k in ("file", "sha256", "code_root", "nodes", "source", "used_for", "algobanked_by") if k in r]
    return "<dl>" + "".join(f"<dt>{k}</dt><dd>{v}</dd>" for k, v in rows) + "</dl>"
rows = "".join(                                             # one tbody per record: the entry, and its details below it
    f"<tbody data-name='{esc(r['name'])}' data-version='{esc(r['version'])}'>"
    f"<tr class='entry' tabindex='0' aria-expanded='false'>"
    f"<td class='pkg'>{esc(r['name'])}<span class='narrow'> v{esc(r['version'])}</span></td>"
    f"<td class='wide'>{esc(r['version'])}</td><td class='wide'>{scope(r)}</td>"
    f"<td class='wide'>{count(r['findings'], 'high')}</td>"
    f"<td class='wide'>{count(r['findings'], 'warning')}</td>"
    f"<td class='wide'>{esc(r['admitted'])}</td><td class='wide'>{short(r['sha256']) if r.get('sha256') else ''}</td>"
    f"<td class='wide'>{strip(r)}</td><td class='narrow'>{findings(r['findings'])}</td></tr>"
    f"<tr class='details' hidden><td colspan='10'>{details(r)}</td></tr></tbody>"
    for _, r in sorted(enumerate(records), key=lambda x: (x[1]["admitted"], x[0]), reverse=True))  # newest admitted first; same day: last added first
page = (
    "<input id='q' type='text' placeholder='Search package in algobank (for example, dexweb v4.2.0)' data-phone='Search algobank' aria-label='Search the bank' autocomplete='off' spellcheck='false'>\n"
    "<div id='msg' role='status'></div>\n"
    "<table id='bank'><thead><tr><th>package</th><th class='wide'>version</th><th class='wide'>scope</th><th class='wide'>high</th>"
    "<th class='wide'>warning</th><th class='wide'>admitted</th><th class='wide'>sha256</th><th class='wide'>code root</th>"
    "<th class='narrow'>findings</th></tr></thead>" + rows + "</table>\n"
    "<p><button type='button' data-export='jsonl'>export as JSONL</button> <button type='button' data-export='csv'>export as CSV</button></p>\n"
    "<script type='application/x-ndjson' id='bank.jsonl'>\n" + bank.replace("</", "<\\/") + "</script>\n")
with open("config.json") as f:
    config = json.load(f)
config["index_template"] = re.sub(                         # between the BANK markers; braces doubled for dexweb's format()
    r"(<!-- BANK:.*?-->\n).*?(<!-- /BANK -->)", lambda m: m.group(1) + page.replace("{", "{{").replace("}", "}}") + m.group(2),
    config["index_template"], flags=re.S)
with open("config.json", "w") as f:
    f.write(json.dumps(config, indent=4) + "\n")

# KNOWN EXPLOITS AND VULNERABILITIES: a magazine of known.json for codegens, rendered from live every build
from algobank.diff import norm, vkey                        # Algobank's own name normalization and PEP 440 ordering
known = json.loads(subprocess.run(["git", "show", "origin/live:known.json"], capture_output=True, text=True, check=True).stdout)
admitted = {}
for r in records:
    admitted.setdefault(norm(r["name"]), []).append(r["version"])
def first_line(e):                                          # the record's own words: its summary, or its details' first sentence
    t = (e.get("summary") or e.get("details", "")).strip().split("\n")[0]
    t = re.split(r"(?<=[.!?])\s", t, maxsplit=1)[0]
    return t if len(t) <= 200 else t[:199] + "…"
def affected(e):
    out = []
    for a in e.get("affected", []):
        for rg in a.get("ranges", []):
            ev = [f"{k} {v}" for x in rg.get("events", []) for k, v in x.items()]
            out.append(", ".join(ev))
        if not a.get("ranges") and a.get("versions"):
            out.append(f"{len(a['versions'])} listed versions")
    return "; ".join(out) or "all versions"
def fixed(e):
    fx = [v for a in e.get("affected", []) for rg in a.get("ranges", []) for x in rg.get("events", []) for k, v in x.items() if k == "fixed"]
    fx = [v for v in fx if vkey(v)]
    return max(fx, key=vkey) if fx else ""
index = []                                                  # one line per advisory: what this page shows, for codegens
for e in sorted(known["advisories"], key=lambda e: (e.get("published", ""), e["id"]), reverse=True):
    pkgs = sorted({norm(a["package"]["name"]) for a in e.get("affected", []) if a.get("package", {}).get("ecosystem") == "PyPI"})
    index.append(dict(id=e["id"], kind="malicious" if e["id"].startswith("MAL-") else "vulnerability", packages=pkgs,
                      published=e.get("published", "")[:10], modified=e.get("modified", "")[:10], withdrawn=e.get("withdrawn", "")[:10],
                      aliases=e.get("aliases", []), affected=affected(e), fixed=fixed(e), summary=first_line(e)))
def advisory_rows(items):
    return "".join(
        f"<tbody data-search='{esc(' '.join([x['id'], *x['aliases'], *x['packages']]).lower())}'>"
        f"<tr class='entry' tabindex='0' aria-expanded='false'>"
        f"<td class='wide'>{esc(x['published'])}</td>"
        f"<td><span class='{'high' if x['kind'] == 'malicious' else 'warning'}'>{esc(x['id'])}</span>"
        + (" <span class='withdrawn'>withdrawn</span>" if x["withdrawn"] else "") + "</td>"
        f"<td class='pkg'>{esc(', '.join(x['packages']))}</td><td class='wide'>{esc(x['fixed'])}</td>"
        f"<td class='wide summary'>{esc(x['summary'])}</td></tr>"
        f"<tr class='details' hidden><td colspan='5'><dl>"
        + "".join(f"<dt>{k}</dt><dd>{esc(v)}</dd>" for k, v in [
            ("published", x["published"]), ("modified", x["modified"]), ("withdrawn", x["withdrawn"]), ("aliases", ", ".join(x["aliases"])),
            ("affected", x["affected"]), ("fixed in", x["fixed"]), ("summary", x["summary"])] if v)
        + "</dl></td></tr></tbody>" for x in items)
slots = {}
for x in index:
    if x["withdrawn"]:
        continue
    for p in x["packages"]:
        s_ = slots.setdefault(p, dict(package=p, malicious=0, vulnerabilities=0, fixed=[]))
        s_["malicious" if x["kind"] == "malicious" else "vulnerabilities"] += 1
        if x["fixed"]: s_["fixed"].append(x["fixed"])
slot_list = sorted(slots.values(), key=lambda s_: (-s_["malicious"], -s_["vulnerabilities"], s_["package"]))
slot_rows = "".join(
    f"<tbody data-search='{esc(s_['package'])}'><tr>"
    f"<td class='pkg'>{esc(s_['package'])}</td>"
    f"<td>{'<span class=high>' + str(s_['malicious']) + ' malicious</span> ' if s_['malicious'] else ''}{s_['vulnerabilities']} vulnerabilities</td>"
    f"<td class='wide'>{esc(max(s_['fixed'], key=vkey) if s_['fixed'] else '')}</td>"
    f"<td>{'admitted ' + esc(', '.join(admitted[s_['package']])) if s_['package'] in admitted else '<span class=low>open</span>'}</td></tr></tbody>"
    for s_ in slot_list)
mal = [x for x in index if x["kind"] == "malicious"]
vul = [x for x in index if x["kind"] == "vulnerability"]
head = "<thead><tr><th class='wide'>published</th><th>advisory</th><th>package</th><th class='wide'>fixed in</th><th class='wide'>summary</th></tr></thead>"
open_slots = sum(1 for s_ in slot_list if s_["package"] not in admitted)
magazine = (
    "<input id='q' type='text' placeholder='Search package or advisory (for example, django or PYSEC-2026-1872)' data-phone='Search' aria-label='Search known exploits and vulnerabilities' autocomplete='off' spellcheck='false'>"
    "<div id='msg' role='status'></div>"
    f"<p class='dateline'><span>Dated: <b>{esc(known['date'])}</b></span><span>Packages: <b>{len(slots)}</b></span>"
    f"<span>Advisories: <b>{len(index)}</b></span><span><a href='#open'>Open</a>: <b>{open_slots}</b></span></p>"
    f"<h2>Malicious releases <span class='count'>{len(mal)}</span></h2><table class='known'>{head}{advisory_rows(mal)}</table>"
    f"<h2>Vulnerabilities <span class='count'>{len(vul)}</span></h2><table class='known'>{head}{advisory_rows(vul)}</table>"
    f"<h2 id='open'>Open slots <span class='count'>{open_slots}</span></h2>"
    "<p>A package is open when it has known advisories but no version of it is admitted in algobank. "
    "An unalgobanked (not on algobank) package is open for codegens (coding agents, bots and human developers) to analyze and run algobank on. "
    "Algobanking generates a report saved in algobank for the package, making it an <a href='index.html'>algobanked package</a>.</p>"
    f"<table class='known slots'><thead><tr><th>package</th><th>advisories</th>"
    f"<th class='wide'>latest fix</th><th>in the bank</th></tr></thead>{slot_rows}</table>"
    "<p><button type='button' data-export='jsonl'>export as JSONL</button> <button type='button' data-export='csv'>export as CSV</button></p>"
    "<script type='application/x-ndjson' id='known.jsonl'>\n"
    + "".join(json.dumps(x, sort_keys=True) + "\n" for x in index).replace("</", "<\\/") + "</script>")
with open("data.json") as f:
    pages = json.load(f)
next(p for p in pages if p["title"] == "Known Exploits and Vulnerabilities")["body"] = [magazine]
with open("data.json", "w") as f:
    f.write(json.dumps(pages, indent=4) + "\n")

dex = dexgen.Dexgen()                                       # data.json + config.json + styles.css -> gen/
shutil.copytree("assets", "gen/assets", dirs_exist_ok=True)  # the font: dexgen copies only styles.css
