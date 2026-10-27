# BUILD THE ALGOBANK DEX
# run in site/:  python run.py
# needs dexweb; algobank it and everything it calls first (see the Usage page)

import html, json, re, shutil, subprocess
from dexweb import dexgen

# THE INDEX IS THE BANK: rendered from bank.jsonl on the live branch, every build
subprocess.run(["git", "fetch", "-q", "origin", "live"], check=True)
bank = subprocess.run(["git", "show", "origin/live:bank.jsonl"], capture_output=True, text=True, check=True).stdout
records = [json.loads(line) for line in bank.splitlines() if line.strip()]

def cell(label, v): return f"<td data-label='{label}'>" + v + "</td>"
def scope(r): return ", ".join("<code class='top'>TOP</code>" if s == "TOP" else html.escape(s) for s in r["scope"]) or "none"
rows = "".join(                                             # one tbody per record: its fields, then its hashes
    f"<tbody data-name='{html.escape(r['name'])}' data-version='{html.escape(r['version'])}'><tr>"
    + cell("package", html.escape(r["name"])) + cell("version", html.escape(r["version"])) + cell("scope", scope(r))
    + cell("high", str(r["findings"]["high"])) + cell("warning", str(r["findings"]["warning"])) + cell("admitted", html.escape(r["admitted"]))
    + "</tr><tr class='hashes'><td colspan='6'>"
    + (f"<span>sha256 <code>{html.escape(r['sha256'])}</code></span>" if r.get("sha256") else "")
    + f"<span>code root <code>{html.escape(r['code_root'])}</code></span></td></tr></tbody>"
    for r in records)
page = (
    "<input id='q' type='text' placeholder='Search package in algobank (for example, dexweb v4.2.0)' data-phone='Search algobank' aria-label='Search the bank' autocomplete='off' spellcheck='false'>\n"
    "<div id='msg' role='status'></div>\n"
    "<table id='bank'><thead><tr><th>package</th><th>version</th><th>scope</th><th>high</th>"
    "<th>warning</th><th>admitted</th></tr></thead>" + rows + "</table>\n"
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
