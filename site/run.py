# BUILD THE ALGOBANK DEX
# run in site/:  python run.py
# needs dexweb; algobank it and everything it calls first (see the Usage page)

import html, json, re, shutil, subprocess
from dexweb import dexgen

# THE INDEX IS THE BANK: rendered from bank.jsonl on the live branch, every build
subprocess.run(["git", "fetch", "-q", "origin", "live"], check=True)
bank = subprocess.run(["git", "show", "origin/live:bank.jsonl"], capture_output=True, text=True, check=True).stdout
records = [json.loads(line) for line in bank.splitlines() if line.strip()]

def esc(v): return html.escape(str(v))
def short(h):                                               # a hash: its first 8 characters, an ellipsis, a copy button
    return f"<code>{esc(h[:8])}…</code><button type='button' class='copy' data-copy='{esc(h)}' aria-label='copy {esc(h)}'>copy</button>"
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
    rows += [(k.replace("_", " "), short(r[k]) if k in ("sha256", "code_root") else text(r[k]))
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
    f"<td class='wide'>{short(r['code_root'])}</td><td class='narrow'>{findings(r['findings'])}</td></tr>"
    f"<tr class='details' hidden><td colspan='10'>{details(r)}</td></tr></tbody>"
    for r in records)
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

dex = dexgen.Dexgen()                                       # data.json + config.json + styles.css -> gen/
shutil.copytree("assets", "gen/assets", dirs_exist_ok=True)  # the font: dexgen copies only styles.css
