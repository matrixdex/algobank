# BUILD THE ALGOBANK DEX
# run in site/:  python run.py
# needs dexweb; algobank it and everything it calls first (see the Usage page)

import html, json, shutil, subprocess
from dexweb import dexgen

# BANK PAGE: rendered from bank.jsonl on the live branch, every build
subprocess.run(["git", "fetch", "-q", "origin", "live"], check=True)
bank = subprocess.run(["git", "show", "origin/live:bank.jsonl"], capture_output=True, text=True, check=True).stdout
records = [json.loads(line) for line in bank.splitlines() if line.strip()]

def cell(v): return "<td>" + html.escape(str(v)) + "</td>"
rows = "".join(
    f"<tr data-name='{html.escape(r['name'])}' data-version='{html.escape(r['version'])}'>"
    + cell(r["name"]) + cell(r["version"]) + cell(", ".join(r["scope"]) or "none")
    + cell(r["findings"]["high"]) + cell(r["findings"]["warning"]) + cell(r["admitted"])
    + cell(r.get("sha256", "")) + cell(r["code_root"]) + "</tr>"
    for r in records)
body = [
    "<input id='q' type='text' placeholder='package v1.2.3' aria-label='Search the bank' autocomplete='off' spellcheck='false'>"
    "<div id='msg' role='status'></div>",
    "<div class='scroll'><table id='bank'><thead><tr><th>package</th><th>version</th><th>scope</th><th>high</th>"
    "<th>warning</th><th>admitted</th><th>sha256</th><th>code root</th></tr></thead><tbody>" + rows + "</tbody></table></div>",
    "<button type='button' data-export='jsonl'>export as JSONL</button> <button type='button' data-export='csv'>export as CSV</button>"
    "<script type='application/x-ndjson' id='bank.jsonl'>\n" + bank.replace("</", "<\\/") + "</script>",
]
with open("data.json") as f:
    pages = json.load(f)
next(p for p in pages if p["title"] == "algobank Algorithm Bank")["body"] = body
with open("data.json", "w") as f:
    f.write(json.dumps(pages, indent=4) + "\n")

dex = dexgen.Dexgen()                                       # data.json + config.json + styles.css -> gen/
shutil.copytree("assets", "gen/assets", dirs_exist_ok=True)  # the font: dexgen copies only styles.css
