import os, sys, shutil, tempfile
sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pkgmerkle import Package, TOP

ROOT = sys.argv[1]
V = {
"demo/__init__.py": "",
"demo/util.py": "def clean(text):\n    return text.strip().lower()\n",
"demo/store.py": "import os\nfrom .util import clean\n\ndef save(path, text):\n    with open(path, 'w') as fh:\n        fh.write(clean(text))\n",
"demo/plugins/__init__.py": "",
"demo/plugins/a.py": "from demo.store import save\n\ndef run(arg):\n    save(arg, 'hello from plugin a')\n    return 'a-done'\n",
"demo/plugins/b.py": "import socket\n\ndef run(arg):\n    try:\n        socket.create_connection(('127.0.0.1', 9), timeout=0.2)\n    except OSError:\n        pass\n    return 'b-done'\n",
"demo/core.py": "import importlib\nfrom . import util\n\ndef load_plugin(name):\n    return importlib.import_module('demo.plugins.' + name)\n\ndef run(name, arg):\n    plugin = load_plugin(name)\n    return plugin.run(arg)\n\ndef shout(text):\n    return util.clean(text).upper()\n",
"demo/cli.py": "from . import core\n\ndef dispatch(command, *args):\n    handler = getattr(core, command)\n    return handler(*args)\n",
}
V_UTIL  = dict(V, **{"demo/util.py": "def clean(text):\n    return text.strip().lower().replace('\\x00', '')\n"})
V_PLUGB = dict(V, **{"demo/plugins/b.py": V["demo/plugins/b.py"].replace("('127.0.0.1', 9)", "('127.0.0.1', 10)")})

def show(title, pkg):
    print(f"--- {title}")
    for nid, n in sorted(pkg.nodes.items()):
        if nid.endswith(":<module>") and n["size"] <= 2 and not n["caps"] and not n["flags"]: continue
        c = ",".join(sorted(n["caps"])) or "-"
        d = ",".join(sorted(n["direct_caps"])) or "-"
        f = ",".join(sorted(n["direct_flags"])) or "-"
        print(f"  {nid:<26} merkle={n['merkle']}  direct_caps={d:<8} rolled_caps={c:<22} direct_flags={f}")
    print()

p1 = Package(V); show("v1 (new analyzer: cross-module + dynamic)", p1)

def changed(a, b): return sorted(k for k in a.nodes if k in b.nodes and a.nodes[k]["merkle"] != b.nodes[k]["merkle"])
def old_style(files):
    """previous behavior: each file analyzed alone, so no cross-module edges"""
    out = {}
    for path, src in files.items():
        if path.endswith(".py"):
            for k, v in Package({path: src}).nodes.items(): out[k] = v["merkle"]
    return out

print("=== cross-module propagation: util.clean() edited ===")
new_ch = changed(p1, Package(V_UTIL))
o1, o2 = old_style(V), old_style(V_UTIL)
old_ch = sorted(k for k in o1 if o1[k] != o2.get(k))
print("  per-file analysis (old) flags as changed:", old_ch)
print("  whole-package analysis (new) flags as changed:", new_ch)
print()
print("=== plugin b edited (host port 9 -> 10): who is invalidated? ===")
print("  ", changed(p1, Package(V_PLUGB)))
print("  (core.run is invalidated although it never names plugin b: it dynamically imports any module)\n")

# ---------------- runtime observation with audit hooks ----------------
work = tempfile.mkdtemp(prefix="synth_", dir=ROOT)
for path, src in V.items():
    full = os.path.join(work, "v1", path); os.makedirs(os.path.dirname(full), exist_ok=True)
    open(full, "w").write(src)
sys.path.insert(0, os.path.join(work, "v1"))
events = []
def hook(event, args):
    if event == "open":
        p, mode = str(args[0]), args[1]
        if not p.endswith((".py", ".pyc")) and mode and any(m in str(mode) for m in "wax+"):
            events.append(("file", f"write {os.path.basename(p)}"))
    elif event == "socket.connect": events.append(("network", f"connect {args[1]}"))
    elif event in ("subprocess.Popen", "os.system"): events.append(("process", event))
    elif event in ("exec", "compile") and "demo" in repr(args)[:200]: pass
sys.addaudithook(hook)
from demo import core
out = os.path.join(work, "out.txt")
for name, arg in (("a", out), ("b", None)):
    events.clear()
    core.run(name, arg)
    print(f"runtime: core.run({name!r}) observed ->", sorted(set(events)) or "nothing")
shutil.rmtree(work)
print("\nstatic rolled-up caps at core:run =", sorted(p1.nodes['demo.core:run']['caps']))
