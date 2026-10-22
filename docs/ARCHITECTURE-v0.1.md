# Algobank v0.1: technical architecture reference

This file records what Algobank v0.1 is, what was built and tested, and what is still only a plan. Each part carries a status:

- **[built]** implemented in `v0.1/` and tested.
- **[spec]** decided in design, not implemented in v0.1.

Code in this release: `v0.1/pkgmerkle.py` (the analyzer), `v0.1/synth_demo.py` (a synthetic multi-module test), `v0.1/dexweb_v2.py` (a release-history test on a real package). The last file was called `dexweb_v3.py` in the request; the file that was run and tested is `dexweb_v2.py`.

## 1. What Algobank is

Algobank is a curated library of software parts (a "garden") in which every part shows what it can do, and in which parts compose into larger programs without gaining hidden powers. Each part is identified by a content hash, so a change to a part is visible and earlier checks of unchanged parts can be reused.

### The core

Algobank's core, without banking and insurance, has three parts:

1. **Identity.** A code Merkle tree gives each package and each function a hash, so changes are exact and earlier work can be reused. [built]
2. **Scope.** What the code can do is visible, and dynamic code is `TOP`. [built]
3. **A place to attach results by hash.** Any party can publish a signed result about a node: a test run, a fuzz run, an AI review, a leak check. Algobank stores it against the hash and reuses it while the hash is unchanged. [spec]

Algobank does not build its own checks. Tests, fuzzers, linters and reviewers are external tools, and their signed results attach to node hashes. Because each result is tied to a hash and not to a pipeline step, checks are independent, run in any order, and can be added without changing the core.

The bank layer (deposits, penalties, interest) sits on top of this core. It is not part of v0.1. See section 12.

## 2. The five decisions v0.1 builds on

1. **Scope is always visible.** What a package can do must be shown. "Scope" and "capability" mean the same thing here. Scopes in v0.1: `file`, `network`, `process`, `env`, `native`, and `TOP`. [built]
2. **Code Merkle trees replace the code graph.** A node's hash covers its own syntax tree and the hashes of the code it calls. Codegraph is not used. [built]
3. **Cross-module calls are resolved. One package is one Merkle tree.** A package has one root hash. [built]
4. **Dynamic imports, reflection and monkey-patching are assigned `TOP`.** `TOP` means the code may do anything. It spreads to every caller. [built, with gaps listed in section 9]
5. **The analyzer is the first garden part.** `pkgmerkle.py` is small, pure, has no dependencies outside the Python standard library and declares no scopes. Its root hash is its identity (section 11). [built as an identity; no log exists yet]

## 3. Terms

| Term | Meaning |
|---|---|
| **Package** | A set of Python source files analyzed together. One package has one Merkle tree. |
| **Node** | A function or method (`module:qualname`), or a module's top-level code (`module:<module>`). |
| **Own hash** | Hash of a node's cleaned-up syntax tree alone. |
| **Merkle hash** | Own hash combined with the Merkle hashes of every node it calls, and with the pins of the outside packages it uses. |
| **Leaf** | `H(node_id + "=" + merkle_hash)`. It commits to the public name and the content. |
| **Root** | A binary Merkle root over the sorted leaves. This is the package identity. |
| **Scope** | A power the code can use. Each node has its own scopes and a rolled-up set that adds the scopes of everything it calls. |
| **Scope root** | A hash of the sorted set of all scopes in the package. |
| **TOP** | Unknown or unbounded scope. Absorbs everything above it. |
| **Pin** | A fixed identifier for an outside dependency. Pins are part of the hash. |

`H` is SHA-256, truncated to 12 hex characters in v0.1. This is for readable output. Production use needs the full digest.

## 4. The code Merkle tree [built]

### 4.1 Nodes

- Every function and method, at any class depth. Async functions count as functions.
- Each module's top-level code, called `<module>`. This is the module with every function body removed, so it keeps imports, constants, class headers and any statement that runs at import time.
- Nested functions and lambdas are not separate nodes. They are part of the parent's tree.

### 4.2 Cleaning up a function before hashing

The goal is that changes with no meaning do not change the hash. The cleaned tree is dumped without line numbers.

| Item | Treatment |
|---|---|
| Function name | Replaced by `_` (the name lives in the leaf, not in the own hash) |
| Parameters and local variables | Renamed by position: `_0`, `_1`, and so on |
| Argument annotations | Removed |
| Docstring (first statement, if a string) | Removed |
| Decorators, default values, return annotations | Kept |
| Global names, attributes, import aliases, string and number constants | Kept as written |

Rule: if there is doubt whether something changes behavior, keep it in the hash. A reformat, a pure rename of locals, or a docstring edit does not change the hash. This is tested.

### 4.3 Merkle hash and cycles

For a node with no cycles: `merkle = H(base + own)`, where `base` combines the node's own hash, the Merkle hashes of every callee, and the sorted pins of outside packages the node uses.

Calls can form cycles (recursion, mutual recursion). The graph is reduced to strongly connected components (Tarjan). Each component is hashed as one unit, then each member hashes that value with its own hash.

### 4.4 Package root

1. Compute every node's leaf.
2. Sort the leaves.
3. Pair-hash upward (duplicate the last leaf when a level has an odd count) to one root.

The root commits to names as well as content, because names are the public interface. Renaming a function changes the root. Reformatting does not. Inclusion proofs (proving that one node is in a root) are possible with this tree but are not implemented.

## 5. Resolving calls [built]

The analyzer builds one call graph for the whole package.

| Case | Handling |
|---|---|
| `import a.b`, `import a.b as x` | Binds a module. Attribute chains resolve to the longest matching module, then the function. |
| `from a.b import f as g` | Binds a symbol (function, class, or submodule). |
| Relative imports (`from . import x`, `from .y import z`) | Resolved from the importing module's package. |
| Instantiating a class | Resolves to that class's `__init__`. |
| `self.m()` and `cls.m()` | Resolves to the method in the same class. If missing, falls back to the next row. |
| A call on an object of unknown type, `obj.m()` | Over-approximation: an edge to every method named `m` in the package. This is the class-hierarchy fallback. It may invalidate more than needed. It never invalidates less. |
| Module top-level code | Has edges to the top-level code of every package module it imports, and to every package function it calls at import time. |
| Imports inside a function | Added to that function's name table. |
| `from x import *` | Flagged `star-import`. Names it brings in are not resolved. See section 9. |

Calls into outside packages are not followed. They count toward scopes (section 6) and pins (section 7).

## 6. Scopes [built]

### 6.1 How a node gets a scope

Scopes come from a table keyed by where the name was imported from:

| Source | Scope |
|---|---|
| `socket`, `ssl`, `urllib`, `http`, `requests`, `httpx`, `aiohttp`, `ftplib`, `smtplib`, `websockets` | `network` |
| `subprocess`, `multiprocessing`, and `os.system`, `os.popen`, `os.execv`, `os.execl`, `os.execvp`, `os.spawnl`, `os.fork`, `os.kill` | `process` |
| `open(...)`, `shutil`, `tempfile`, `glob`, and `os.remove`, `os.unlink`, `os.rmdir`, `os.rename`, `os.replace`, `os.makedirs`, `os.mkdir`, `os.listdir`, `os.scandir`, `os.walk`, `os.chmod` | `file` |
| Any `.write_text .read_text .write_bytes .read_bytes .unlink .rmtree .mkdir .touch` | `file` (matched by method name, so a heuristic) |
| `os.environ`, `os.getenv`, `os.putenv` | `env` |
| `ctypes`, `cffi` | `native` |

### 6.2 Roll-up

A node's rolled-up scope is its own scopes plus the rolled-up scopes of everything it calls, across modules. A package's scope is the union over all nodes. The scope root hashes that set.

A change that adds a scope to any node changes the scope root. In the dexweb test this showed exactly where a new power entered (section 10).

## 7. Dependencies and pins [built, partly]

An outside package that a node uses becomes a pin in that node's hash. v0.1 reads names from `Requires-Dist` in wheel metadata and maps the import name to the distribution name for known mismatches (`bs4` to `beautifulsoup4`).

In the dexweb test every dependency was declared without a version, so each pin was `unpinned`. A real garden part may depend only on other garden parts, pinned by digest. This is **[spec]**: v0.1 records pins but does not enforce them.

## 8. Dynamic code is `TOP` [built, with gaps]

### 8.1 What produces `TOP`

| Construct | Flag | Effect |
|---|---|---|
| Import with a computed name (`importlib.import_module(x)`, `__import__(x)`) | `dyn-import` | `TOP`, and an edge to every module in the package, so any module change invalidates the node |
| Entry-point loading (`entry_points`) | `dyn-import` | Same |
| `getattr`, `setattr`, `delattr` with a computed name; `globals()`, `locals()`, `vars()` | `dyn-attr` | `TOP` |
| `eval`, `exec`, `compile`; `pickle`, `marshal`, `dill`, `shelve` load calls | `dyn-exec` | `TOP` |
| Assigning an attribute on an imported module; storing into `sys.modules` | `dyn-patch` | `TOP` |

Import with a literal name that is a package module is resolved as a normal import.

### 8.2 What `TOP` means for checks

- `TOP` spreads upward: any caller of a `TOP` node is `TOP`.
- A `TOP` node cannot earn a verdict such as "uses no network". It can earn only verdicts that hold regardless of what it does.
- Static analysis gives an upper bound. Runtime observation gives a lower bound (section 10.1). In the garden, enforcement by the host is the guarantee; the analyzer is for triage and for cache keys.

## 9. Known gaps in v0.1

| # | Gap | Effect | Suggested fix |
|---|---|---|---|
| G1 | Functions do not depend on their module's top-level code. A change to a module-level constant does not change the hash of a function that reads it. | A stale verdict can survive. **This is a soundness gap.** | Add an edge from each function to the module-level names it reads, or to its `<module>` node. The second choice over-invalidates, so measure the cost on the dexweb history first. |
| G2 | `__getattr__` definitions and `from x import *` are flagged but do not produce `TOP`. | Contradicts decision 4. | Add the two flags to the `TOP` rule. |
| G3 | Computed `getattr` targets are not added to the hash. | `cli.dispatch` in the synthetic test was `TOP` but was not invalidated when `util.clean` changed, though it can reach it at run time. | Either forbid unbounded dynamic code in admission, or require an explicit list of allowed targets that joins the hash. |
| G4 | Literal imports of outside modules (`import_module("socket")`) do not add that module's scope. | Scope is under-reported. | Map literal outside imports through the scope table. |
| G5 | The scope table is short, Python only, and partly matched by method name. | Misses libraries it does not list. | Build a proper API-to-scope database per language. |
| G6 | Native extensions, `ctypes`, and anything below the Python level are invisible to the hooks and the parser. | Under-reported. | Garden admission refuses `native` without a separate build vouch. |
| G7 | Methods in base classes are reached only by the name-based fallback. | Over-approximates. | Real class-hierarchy resolution. |
| G8 | No inclusion proofs. | Cannot prove one node is in a root without the full list. | Standard Merkle audit paths over the sorted leaves. |
| G9 | The digest is truncated to 12 hex characters. | Not collision-safe for production. | Use the full SHA-256. |
| G10 | Dynamic behavior that avoids every listed pattern (functions stored in dictionaries and called by key, for example). | Not detected. | Runtime observation and host enforcement. |
| G11 | Hashes come from Python's `ast.dump`, whose output can change between interpreter versions. v0.1 targets Python 3.14 only. | The same source could get a different root under another Python version. | Record the interpreter version with every root. Add a test that compares roots across supported versions. Longer term, hash a version-independent serialization of the tree. |

## 10. Test results

### 10.1 Synthetic package (`synth_demo.py`)

An eight-file package with a dynamic plugin loader, a computed `getattr` dispatcher, and two plugins that use files and the network.

| Test | Result |
|---|---|
| Edit `util.clean()`; per-file analysis | 1 node changed |
| Same edit; whole-package analysis | 5 nodes changed: `util.clean`, `store.save`, `plugins.a.run`, `core.run`, `core.shout` |
| `core.load_plugin` (computed import); `cli.dispatch` (computed `getattr`) | Both `TOP` |
| Edit `plugins/b.py` | `plugins.b.run` and `core.run` changed |
| Static scope at `core.run` | `TOP`, `file`, `network` |
| Runtime observation (Python audit hook), plugin a | Observed `file` only |
| Runtime observation, plugin b | Observed `network` only |

The static result is an upper bound, and the runtime result is what happened on one path.

### 10.2 Real package: dexweb (`dexweb_v2.py`)

All 25 PyPI wheels of `dexweb` (0.0.1 through 4.2.5). Every file hash matched PyPI's record. Nothing from the package was executed.

| Measure | Value |
|---|---|
| Median share of nodes unchanged vs the previous release | 88% by count, 74% by code size |
| Vetting work across all releases when earlier verdicts are reused | 25% of the from-scratch cost |
| Releases with no code change | 4.0.3, 4.0.4, 4.1.3, 4.1.4, 4.1.5, 4.1.6, 4.1.8, 4.2.2 |
| Cross-module call edges | 0 (the two modules never import each other) |
| `TOP` nodes | 0 |
| Scope change | `process` first appeared at 4.2.3 (`subprocess.run` of git, in `dexweb.py`) |
| Non-code change | 4.2.0 added a 200 KB data file |
| Dependencies | Four, all unpinned |

This is one small package by one author. Do not generalize the percentages before more packages are measured.

### 10.3 Self-analysis

`pkgmerkle.py` analyzed itself: 25 nodes, no scopes, no `TOP`, identical hashes on a second run. A one-line edit in `H()` moved only `H`, `Package._analyze` and `Package.__init__`.

## 11. The first garden part: the analyzer's own identity [built as an identity; not logged]

`pkgmerkle.py` meets the admission rules the design favors: small, pure computation, no dependencies outside the standard library, no scopes, no `TOP`, no install-time code.

Identity of `v0.1/pkgmerkle.py` as shipped, computed with the file key `pkgmerkle.py`:

| Item | Value |
|---|---|
| Package root | `5af18aa47d8a` |
| Scope | none |
| Scope root | `140bedbf9c3f` |
| Nodes | 25 |
| File SHA-256 | `e7edbf91da0cf836b93014ff7b03db0512ba53487de42ec7ccd84d29b46f50be` |

Any edit to the file changes the root. This is a candidate vouched artifact, not a vouched one: there is no transparency log, no independent builder and no witness yet. The values above are only a record in this file.

To recompute:

```
cd v0.1
python3.14 -I -B -c "
import sys; sys.path.insert(0, '.')
from pkgmerkle import Package
with open('pkgmerkle.py') as fh:
    p = Package({'pkgmerkle.py': fh.read()})
print(p.root(), p.scope(), p.scope_root(), len(p.nodes))"
```

The root depends on the output format of Python's `ast.dump`, so record the Python version with it. See gap G11.

## 12. Target architecture around v0.1 [spec]

These parts are decided in design and not built.

| Part | Purpose |
|---|---|
| **Transparency log** | Append-only Merkle log of every admission, vouch, revocation and key change. The package root goes here. |
| **Independent builders** | At least k of n builders on different operators, clouds and keys rebuild each release from a pinned commit. They must agree on the digest before admission. A shared cache between builders defeats independence, so admission always rebuilds fresh. |
| **Witnesses** | Independent parties that cosign each log head after checking it extends the previous one. Stops the operator from showing different histories to different clients. |
| **Admission rules** | Pinned repository identity and commit, no binary blobs, no install or startup hooks, no unbounded dynamic code, scope declared and enforced. |
| **Host-enforced scope** | A sandbox (WebAssembly Component Model is the intended runtime) grants only declared scope. The analyzer's output is advice; enforcement is the guarantee. |
| **Vouches and deposits** | A reviewer, human or AI, signs an evidence bundle and locks a deposit behind it. A proven breach pays the finder. A vouch attaches to a node or subtree hash so that unchanged subtrees keep their earlier vouch. |
| **Work frontier** | For a root, the list of nodes that lack a valid verdict for each required check. Agents cover that list and nothing else. |
| **Data artifact class** | Large non-code files (model weights, data tables) with allowed formats, size limits and pinned digests. |
| **Patch lane** | An emergency path from an upstream fix to a vouched garden release within hours. |
| **Client gate** | A lockfile check and an agent tool that refuse unvouched digests. |

## 13. How to run v0.1

Requirements: Python 3.14, standard library only.

```
# self-analysis and identity: see section 11

# synthetic package, with runtime observation (give it any writable scratch directory)
python3.14 -I v0.1/synth_demo.py /path/to/scratch

# dexweb history: first fetch the wheels into <scratch>/dexweb/
mkdir -p <scratch>/dexweb/wheels && cd <scratch>/dexweb
curl -sS -o meta.json https://pypi.org/pypi/dexweb/json
python3.14 -I - <<'EOF' > urls.tsv
import json
d = json.load(open("meta.json"))
for v, files in d["releases"].items():
    for f in files:
        if f["packagetype"] == "bdist_wheel":
            print(v, f["url"], f["digests"]["sha256"], f["filename"], sep="\t")
EOF
# download each URL into wheels/<filename> and check its sha256 against the third column
python3.14 -I v0.1/dexweb_v2.py <scratch>
```

The wheels are parsed and never run.

## 14. Next steps for v0.2

1. Fix G1 (global reads) and measure the effect on the dexweb reuse numbers.
2. Fix G2 and G3 so the `TOP` rule matches decision 4.
3. Add inclusion proofs and the full digest, and record the interpreter version with each root (G11).
4. Run the release-history test on two or three larger, multi-author packages.
5. Stand up a minimal transparency log and record the analyzer's root as its first entry.
6. Write the admission checker as code. Section 12 lists its rules.
