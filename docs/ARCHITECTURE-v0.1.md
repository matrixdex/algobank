# Algobank architecture

Version 0.1 · Python 3.14

This document is the reference for Algobank's design. It describes what Algobank is, how each part works, what is implemented, and what is specified but not yet built.

Status markers:

- **[built]** implemented in `v0.1/` and tested.
- **[spec]** specified in this document, not yet implemented.

## 1. Overview

Algobank is a curated library of software parts, called the garden. Every part shows what it can do, and parts compose into larger programs without gaining hidden powers. Each part is identified by a content hash, so any change is exact and visible, and work already done on unchanged parts is reused.

### 1.1 The core

Algobank's core, without banking and insurance, has three parts:

1. **Identity.** A code Merkle tree gives each package and each function a hash, so changes are exact and earlier work can be reused. [built]
2. **Scope.** What the code can do is visible, and dynamic code is `TOP`. [built]
3. **Results by hash.** Any party can publish a signed result about a node: a test run, a fuzz run, an AI review, a leak check. Algobank stores it against the hash and reuses it while the hash is unchanged. [spec]

### 1.2 What Algobank owns

Algobank owns a small set of core checks:

- computing identity and scope;
- the admission gates (section 7);
- verifying submitted results: signature, hash binding and sampled reruns (section 6);
- replaying breach proofs (bank layer).

It also sets the evidence policy: which results each scope and tier requires.

All other checks (tests, fuzzers, linters, reviews) are external tools whose signed results attach to node hashes. Because a result is tied to a hash and not to a pipeline step, external checks are independent, run in any order, and can be added without changing the core. Algobank runs a reference set of them at the start, so the result store is not empty.

### 1.3 Design principles

1. Scope is always visible. "Scope" and "capability" mean the same thing.
2. Identity comes from code Merkle trees. One package is one tree with one root.
3. Calls across modules are resolved. Dynamic imports, reflection and monkey-patching are `TOP`.
4. Static analysis sorts and flags. A boundary outside the code enforces.
5. Every enforcement step fails closed: if a restriction cannot be applied and verified, the part does not run.
6. Existing standards and tools are reused wherever they fit.

### 1.4 Layers above the core

Banking and insurance (vouches, deposits, penalties, interest, payouts) sit on top of the core. They are not part of v0.1. Section 9 lists them.

## 2. Terms

| Term | Meaning |
|---|---|
| **Package** | A set of source files analyzed together. One package has one code Merkle tree. |
| **Part** | A package admitted to the garden. The unit that is confined and run. |
| **Node** | A function or method (`module:qualname`), a module's top-level code (`module:<module>`), or a module value (`module:=name`). |
| **Own hash** | The hash of a node's normalized syntax tree alone. |
| **Merkle hash** | The own hash combined with the Merkle hashes of every node it calls and the pins of outside packages it uses. |
| **Leaf** | `H(0x00 ‖ node_id ‖ "=" ‖ merkle_hash)`. It commits to the node's public name and its content. |
| **Code root** | The binary Merkle root over a package's sorted leaves. The package's identity. |
| **Scope** | A power the code can use, such as `file` or `network`. |
| **Scope root** | The hash of the sorted set of all scopes in a package. |
| **`TOP`** | Unknown or unbounded scope. It absorbs every other scope. |
| **Pin** | A fixed identifier for an outside dependency. Pins are part of the hash. |
| **Compute part** | A part that declares no scope. |
| **Effect part** | A part that declares one or more narrow scopes. |
| **Tier** | How a part is confined at run time: component tier or native tier (section 5.2). |
| **Result** | A signed statement by a check about a node or package hash. |

## 3. Identity: the code Merkle tree [built]

### 3.1 Nodes

- Every function and method, at any class depth. Async functions count as functions.
- Each module's top-level code, called `<module>`: the module with every function body removed. It keeps imports, constants, class headers and any statement that runs at import time. It stands for importing the module.
- Each module-level name, called a module value (`module:=name`): the top-level statements that bind or may change that name. These are assignments, imports, class definitions without their methods, conditional definitions, and statements that change the name (`REG["a"] = f`, `sys.path.insert(...)`). A statement that binds several names belongs to each of them.
- Each module's remaining top-level statements, which bind or change no name, called `module:=<effects>`.
- Nested functions and lambdas are part of their parent node.

### 3.2 Normalization

Changes with no meaning must not change the hash. The normalized tree is serialized without line numbers.

| Item | Treatment |
|---|---|
| Function name | Replaced by `_`. The name is in the leaf, not in the own hash. |
| Parameters and local variables | Renamed by position: `_0`, `_1`, and so on. |
| Argument annotations | Removed. |
| Docstring (first statement, if a string) | Removed. |
| Decorators, default values, return annotations | Kept. |
| Global names, attributes, import aliases, constants | Kept as written. |

Rule: if there is doubt whether something changes behavior, it stays in the hash. Reformatting, renaming locals and editing docstrings do not change the hash.

### 3.3 Merkle hash and cycles

Nodes are grouped into components (section 3.8). A node's Merkle hash is `H(base + own)`, where `own` is the hash of its normalized code and `base` is the hash of its component:

```
base = H( "|".join(sorted own hashes of the component's members)
        + "#" + "|".join(Merkle hashes of the component's external dependencies)
        + "#" + "|".join(H(pin) for each sorted pin string) )
```

Every item joined by `|` is a 64-character hex digest, so the encoding splits back uniquely. Pin strings are hashed before joining because a version specifier may itself contain `|`.

Proven property (section 10.5): if a node's Merkle hash is unchanged, every node it can reach has a counterpart with the same Merkle hash, the same own hash and the same pins. An unchanged hash therefore means unchanged code underneath, which is what makes reusing results safe.

A node depends on exactly what it uses. A function depends on the functions it calls or references and on the module values it reads, including values read through another module (`config.LIMIT` depends on `config:=LIMIT` only). A method also depends on its class's value, which holds the class attributes. A module value depends on what its statements read, call or import, so `from .config import LIMIT` makes the local value depend on `config:=LIMIT`. A function that writes a name through `global` is a dependency of that name's value, so every reader depends on the writer. Every function in a module depends on the module's `<effects>` node, if it has one. A change to one module-level name therefore changes only the code that reads it.

Recursion and mutual recursion form cycles, which is why the hash is computed per component: each component is hashed as one unit, and each member then combines that value with its own hash.

### 3.4 Code root

1. Compute every node's leaf: `H(0x00 ‖ node_id ‖ "=" ‖ merkle_hash)`.
2. Sort the leaves.
3. Hash pairs upward as `H(0x01 ‖ left ‖ right)`, duplicating the last leaf of an odd-sized level, until one root remains.

The 0x00 and 0x01 prefixes separate leaf inputs from interior inputs, as in RFC 6962, so a leaf can never be mistaken for an interior node. A package with no nodes has the root `H("empty")`.

The root commits to names and content, because names are the public interface. Renaming a function changes the root; reformatting does not.

Proven properties (section 10.4), assuming a collision-resistant hash:

- **Binding.** Two packages have the same code root only if they have the same set of (node id, Merkle hash) pairs.
- **Order independence.** The root depends only on that set, not on the order of nodes.

Binding depends on node ids being unique. With repeated leaves the rule that duplicates an odd last leaf makes different lists collide: `[a, b, c]` and `[a, b, c, c]` have the same root.

### 3.5 Call resolution

The call graph covers the whole package.

| Case | Handling |
|---|---|
| `import a.b`, `import a.b as x` | Binds a module. Attribute chains resolve to the longest matching module, then the function. |
| `from a.b import f as g` | Binds a function, class or submodule. |
| Relative imports | Resolved from the importing module's package. |
| Instantiating a class | Resolves to the class's `__init__`. |
| `self.m()`, `cls.m()` | Every definition of `m` in the class's ancestors and in all its package subclasses, since the instance may be a subclass that overrides `m`. |
| `super().m()` | Every definition of `m` in the ancestors of the class and of its subclasses, other than the class itself. |
| `x.m()` where `x` is a literal or builtin value | No package method. A local variable counts when every assignment to it is a plain `x = ...` in the function with a literal, a comprehension, or a call to an unshadowed builtin constructor (`list`, `dict`, `str`, `sorted`, ...). |
| `x.m()` where `x` is a local assigned only from package class constructors | Every definition of `m` in those classes and their ancestors. The constructor counts only if the class name is bound once and never rebound, and the class and its ancestors have no `__new__`, no metaclass and no unresolved base. |
| `obj.m()` on anything else (parameters, attributes, call results, other locals) | An edge to every method named `m` in the package. This over-approximates: it may invalidate more than needed, never less. |
| Classes with an unresolved base, a metaclass or `__getattr__` | Calls resolved through them also link to every method named `m`. |
| Module top-level code | Edges to the top-level code of every package module it imports, and to every package function it calls at import time. |
| Imports inside a function | Added to that function's name table. |
| `from x import *` | Flagged `star-import`. The names it brings in are not resolved. |

Narrowing uses only evidence that holds at run time. Type annotations are not used: a function annotated to take one class can be passed any object.

Calls into outside packages are not followed. They contribute to scope (section 4) and pins (section 3.6).

### 3.6 Dependencies and pins

Each outside package a node uses becomes a pin in that node's hash. v0.1 reads dependency names from wheel metadata (`Requires-Dist`) and maps import names to distribution names where they differ, for example `bs4` to `beautifulsoup4`. [built]

A garden part may depend only on other garden parts, pinned by digest. v0.1 records pins but does not enforce this. [spec]

### 3.7 Hash function

`H` is SHA-256, written as 64 hex characters. Every digest in a tree has the same length; `root()` raises an error otherwise, because splitting a concatenated input back into its halves relies on that length. Hashes come from Python's `ast.dump`, whose format can differ between interpreter versions, so the interpreter version is recorded with every root.

### 3.8 Front end, back end and checker

The analyzer has three parts:

| Part | Input | Output | Trust |
|---|---|---|---|
| Front end | Source files | Per-node facts: own hash, dependency edges, pin strings, direct scope, flags | Trusted and tested; Python has no formal semantics to prove it against |
| Back end (`backend`) | The facts | Components (Tarjan's algorithm) and Merkle hashes over all dependency edges; rolled-up scope and flags over call edges only (section 4.3) | Untrusted |
| Checker (`check_backend`) | The facts and the back end's output | Accept, or an error | Checks exactly the conditions of the Merkle soundness proof |

The checker verifies that own hashes are digests; that every node belongs to exactly the component it is assigned to; that every component's members are mutually reachable; that every dependency edge stays inside the component or is listed as an external dependency, and every listed external dependency is used; and that every Merkle hash satisfies the equation in section 3.3. The analyzer runs the checker on every analysis and stops if it fails, so the theorem covers every result the analyzer produces. This is the proven-checker approach: Tarjan's algorithm is not proven; its output is checked.

## 4. Scope

### 4.1 The scope set

| Scope | Covers | Detected in v0.1 | Component tier | Native tier |
|---|---|---|---|---|
| `file` | Reading, writing, listing or deleting files | yes | enforced | enforced |
| `network` | Any network connection or listening socket | yes | enforced | enforced |
| `process` | Starting or signaling other processes | yes | enforced | enforced |
| `env` | Reading or changing environment variables | yes | enforced | enforced |
| `native` | Loading native code (`ctypes`, `cffi`, C extensions) | yes | not allowed | native tier only |
| `clock` | Reading the time or date | no (G13) | enforced | detected only |
| `entropy` | Reading random numbers, `os.urandom`, `uuid4` | no (G13) | enforced | detected only |
| `TOP` | Unknown or unbounded behavior | yes | must be resolved or rejected | must be resolved or rejected |

`clock` and `entropy` are scopes because results are reused only while code is deterministic, because a clock is a common trigger for dormant malicious behavior, and because key generation depends on the quality of its random source.

Enforcement in both tiers is [spec] (section 5).

### 4.2 Detection [built]

Scopes come from a table keyed by where a name was imported from.

| Source | Scope |
|---|---|
| `socket`, `ssl`, `urllib`, `http`, `requests`, `httpx`, `aiohttp`, `ftplib`, `smtplib`, `websockets` | `network` |
| `subprocess`, `multiprocessing`; `os.system`, `os.popen`, `os.execv`, `os.execl`, `os.execvp`, `os.spawnl`, `os.fork`, `os.kill` | `process` |
| `open()`, `shutil`, `tempfile`, `glob`; `os.remove`, `os.unlink`, `os.rmdir`, `os.rename`, `os.replace`, `os.makedirs`, `os.mkdir`, `os.listdir`, `os.scandir`, `os.walk`, `os.chmod` | `file` |
| Methods named `.write_text`, `.read_text`, `.write_bytes`, `.read_bytes`, `.unlink`, `.rmtree`, `.mkdir`, `.touch` | `file` (matched by name) |
| `os.environ`, `os.getenv`, `os.putenv` | `env` |
| `ctypes`, `cffi` | `native` |

### 4.3 Roll-up [built]

A node's rolled-up scope is its own scope plus the rolled-up scope of everything that runs when it runs: the functions it calls and, for a module's top-level code, the modules it imports and the functions it calls at import time. Roll-up follows these call edges only. A function that reads a module's constants depends on that module for hashing (section 3.3) but does not run its import-time code, so it does not inherit that code's scope. A package's scope is the union over its nodes, and the scope root hashes that set. Any change that adds a scope anywhere changes the scope root, which pinpoints where a new power entered.

### 4.4 `TOP` [built]

| Construct | Flag | Effect |
|---|---|---|
| Import with a computed name (`importlib.import_module(x)`, `__import__(x)`), entry-point loading | `dyn-import` | `TOP`, and an edge to every module in the package, so any module change invalidates the node |
| `getattr`, `setattr`, `delattr` with a computed name; `globals()`, `locals()`, `vars()` | `dyn-attr` | `TOP` |
| `eval`, `exec`, `compile`; loads from `pickle`, `marshal`, `dill`, `shelve` | `dyn-exec` | `TOP` |
| Assigning an attribute of an imported module; writing to `sys.modules` | `dyn-patch` | `TOP` |

An import with a literal name of a package module is resolved as a normal import.

`TOP` spreads to every caller. A `TOP` node cannot earn a result such as "uses no network"; it can earn only results that hold regardless of what it does.

### 4.5 Compute and effect parts [spec]

Separating computation from effects lets reviewers concentrate on the small parts that touch files, the network or processes, while pure compute parts need lighter review.

1. **Two kinds of part.** A compute part declares no scope: no effectful imports, no `TOP`, no introspection, no clock and no randomness. An effect part declares narrow scopes with parameters, for example `file: read ./data` or `network: api.example.com:443`. Effect parts should be small.
2. **Effects flow in as arguments.** Compute code receives data, readers, clients, the current time or a random generator from its caller and never reaches out itself. Authority is then visible where parts are wired together ("functional core, imperative shell").
3. **Manifest.** Each package declares the scope of each module in a manifest such as `algobank.toml`. Admission rejects any module whose detected scope exceeds its declared scope, and reports declared scope that is never used.
4. **Allowlist for compute parts.** A compute part may import only from a list of pure standard-library modules and may not use dunder introspection or frame access. An allowlist fails safe; a denylist of dangerous names always misses something.
5. **Review by scope.** The evidence policy (section 6.4) requires more evidence as scope grows.

## 5. Enforcement [spec]

### 5.1 Principle

Static analysis decides where to look and what to flag. It does not enforce. Python cannot isolate one module from another inside a single process, so enforcement happens at a boundary between parts, and calls across that boundary are serialized. Parts must therefore be coarse enough for that cost to be acceptable.

### 5.2 Tiers

| | Component tier | Native tier |
|---|---|---|
| Boundary | WebAssembly component | Confined operating-system process |
| Platforms | Linux, macOS, Windows | Linux; other systems run the host in a Linux VM |
| Scopes enforced | All, including `clock` and `entropy` | `file`, `network`, `process`, `env`; `clock` and `entropy` detected only |
| Typical parts | Pure-Python code | Packages with C extensions, such as NumPy |
| Status | The only long-term boundary | For parts that cannot yet run as components |

**Component tier.** A part runs as a WebAssembly component. A compute component receives no imports. An effect component receives only the WASI interfaces it declared, for example the file system limited to one pre-opened directory. `componentize-py` builds Python components; pure Python is well supported, packages with C extensions are only partly supported, and CPython's `ssl` module is not available inside a component.

**Native tier.** A part runs in its own confined process (section 5.3). Packages with C extensions stay in this tier until a component build exists. Emscripten builds (Pyodide) already run NumPy, but target a JavaScript host rather than WASI components; WASI builds of NumPy are not yet available.

A part's tier is recorded at admission and visible to agents and reviewers. The evidence policy depends on it.

### 5.3 Native-tier confinement

The Linux kernel enforces every restriction. Algobank's host only configures them, and none can be undone from inside.

| Layer | Effect |
|---|---|
| Namespaces (user, mount, network, PID, IPC) | The part sees only its mounted files, no network interfaces and only its own processes. An empty network namespace blocks every protocol. |
| Privileges | `no_new_privs` set and all capabilities dropped; the part cannot gain rights. |
| System-call filter (seccomp) | An allowlist of the system calls the runtime needs. Internet sockets, new namespaces, process tracing, kernel-module loading and, after start-up, starting programs are refused. |
| File rules (Landlock) | A second file layer under the mount namespace. A layer, never the boundary. |
| Resource limits (cgroups, rlimits) | Caps on memory, CPU, process count and open files. |
| gVisor or a microVM (Firecracker) | For effect parts and parts that parse untrusted input: the part talks to a small user-space kernel or a minimal VM instead of the host kernel. |

### 5.4 Launch sequence

1. The host builds a confinement profile from the part's declared scope in its admission record.
2. The host starts the process with namespaces, mounts, a cleared environment and dropped privileges.
3. A small trusted runner inside the process applies the final system-call filter, then verifies its own state: no capabilities, filter active, no network interfaces, expected mounts. If any check fails, it exits without loading the part.
4. The runner imports the part, including its native extensions.
5. Data enters and leaves only through a pipe, in a plain format checked against a schema.
6. The digest of the confinement profile is recorded with the run.

### 5.5 Two-way boundary

The host treats a part's output as untrusted. Output is never unpickled or otherwise executed; it is parsed from a plain format and validated against a schema.

### 5.6 Failing closed

Every layer is verified, not assumed. When the kernel lacks a feature the profile needs, the part does not run. Landlock illustrates why: the kernel rejects rules it does not support, but best-effort libraries drop them silently, so the host checks the Landlock version before relying on it. Network rules need version 4 (Linux 6.7).

### 5.7 Native-tier security rules

Native code has no memory safety, and the analyzer cannot see the scope of compiled code. The native tier is therefore weaker than the component tier, and these rules apply:

1. **Native only when measured performance requires it.**
2. **Always confined.** A native part never runs outside the profile in section 5.3.
3. **Nothing worth stealing.** The process holds no credentials, secrets or files beyond its declared scope.
4. **Evidence for native code.** Reproducible builds by independent builders, fuzzing with memory-error detectors (sanitizers), hardened compiler settings, and a reviewer's vouch on the native source.
5. **Sampled cross-checks.** Where a component build exists, a random sample of real calls is rerun on it and the outputs are compared. This detects wrong results from a compromised native part. Agreement shows correctness on the sampled inputs; it is not evidence that the native code is secure.
6. **Untrusted input.** Native code that parses untrusted files or network data requires the component tier or substantially heavier evidence.
7. **Memory-safe native code is preferred.** A Rust extension ranks above a C extension; `unsafe` blocks are reviewed specifically.

### 5.8 Tools

Confinement reuses existing tools: bubblewrap or nsjail for namespaces, seccomp and resource limits; gVisor and Firecracker for the stronger option. Algobank's own code is the runner, the mapping from declared scope to profile, the self-check, and recording the profile digest.

Python audit hooks (PEP 578) are not a boundary. PEP 578 states that they are not a sandbox. They are used for observation only.

## 6. Results and evidence [spec]

### 6.1 Results by hash

A result names the node or package hash it covers, the check (tool, tool digest and version), the outcome, the digest of its evidence, and the submitter's signature. A result stays valid while the hash it names is unchanged, so unchanged code is never rechecked. A result for a `TOP` node is limited to properties that hold regardless of its behavior.

### 6.2 Verification of submitted results

A store of signed results from any party is a target. Algobank accepts a result only if:

1. the signature is valid and the submitter is registered;
2. the result is bound to the correct hash and checker version;
3. sampled reruns of deterministic checks reproduce it.

### 6.3 Reference runner

Algobank runs a reference set of external checks itself, so the store is not empty before other parties contribute.

### 6.4 Evidence policy

The policy states which results each scope and tier requires. A compute part in the component tier might need tests and the static checks; an effect part with `network` in the native tier might also need a fuzz result and a reviewer's vouch. The policy is versioned and every version is logged (section 8).

### 6.5 Work frontier

For a given code root, the work frontier is the set of nodes that lack a valid result for a required check. Agents and reviewers work on the frontier and nothing else.

### 6.6 Formal proofs

A proof is the strongest result type: it shows that a node meets a specification for every input, not only the inputs tested. A proof result records:

- the node hash it covers;
- the specification digest;
- the prover and proof checker, with digests and versions;
- the proof artifact digest.

**Specifications are artifacts.** A proof shows that code matches its specification, not that the specification is right. Specifications are hashed, logged and reviewed like code. A proof is valid only while both the node hash and the specification digest are unchanged.

**Rechecking is cheap.** Finding a proof is expensive; checking one is fast and deterministic. Algobank reruns the proof checker on submitted proofs, which makes proofs well suited to the verification in section 6.2. Proofs written by AI agents are accepted on the same terms: the checker decides, not the author.

**Scope of a proof.** A proof holds for the model it was checked against. It assumes the compiler, runtime and hardware behave as modeled, and does not cover side channels. Confinement (section 5) still applies to proven parts.

**Where proofs apply.**

- Compute parts, which are small and pure: parsers, codecs, numeric routines, cryptographic primitives.
- The trusted base that every admission depends on: the analyzer, the code and log Merkle functions, signature checks, and the runner's self-check.
- Native code, where a proof of memory safety addresses the main weakness of the native tier (section 5.7).

Python has no mature general verifier. Proven parts are written in a verifiable subset or in a verification language, such as F\*, Lean, Dafny, or Rust with Verus or Kani, and called from Python. HACL\*, verified cryptography written in F\* and compiled to C, is an example already used in production.

**Policy.** Proofs are optional evidence. The evidence policy (section 6.4) may accept a proof in place of other results; for example, a proven parser of untrusted input may meet a requirement that would otherwise demand heavy fuzzing. Parts without proofs are never rejected for lacking one.

## 7. Admission [spec]

A package becomes a part only when all gates pass:

1. Repository identity and commit are pinned.
2. At least k of n independent builders, on different operators, clouds and keys, rebuild the release from the pinned commit and agree on the digest. Admission always rebuilds fresh; builders never share a cache.
3. No binary blobs in the source, and no install-time or startup hooks.
4. Dependencies are garden parts, pinned by digest.
5. No unresolved `TOP`. Dynamic behavior is either removed or limited to an explicit list of targets that joins the hash.
6. Detected scope does not exceed declared scope (section 4.5).
7. The tier is assigned and the confinement profile can be applied on the target platform.
8. The evidence policy for the part's scope and tier is met.

## 8. Transparency log [spec]

Every admission, result, vouch, revocation, key change and policy change is recorded in an append-only log. The log reuses existing open specifications.

### 8.1 Two trees

The **code Merkle tree** (one per package, section 3) identifies code; its root is a value inside a log entry. The **log Merkle tree** (one, global, append-only) records entries; its root proves that no past entry was changed or removed.

### 8.2 Format

| Part | Specification |
|---|---|
| Tree hashing | RFC 6962 / RFC 9162: leaf hash = SHA-256(0x00 ‖ entry bytes), interior hash = SHA-256(0x01 ‖ left ‖ right). |
| Digests | Full SHA-256. |
| Signed tree head | C2SP `tlog-checkpoint` in `signed-note` format: the log's origin, tree size and root hash, followed by signatures. |
| Witness cosignatures | C2SP `tlog-cosignature`, collected through C2SP `tlog-witness`. Clients accept a checkpoint only when k of n witnesses have cosigned it, which prevents the operator from showing different histories to different clients. |
| Serving | C2SP `tlog-tiles`: the log is published as static, cacheable files. Sigstore's Rekor v2 uses this model. |
| Entry encoding | JSON canonicalized with RFC 8785. Large evidence is stored outside the log and referenced by digest. |

### 8.3 Entry kinds

| Kind | Content |
|---|---|
| `admission` | Package name and version, artifact digest, source repository and commit, code root, declared and detected scope per module, scope root, tier, analyzer root and Python version, builder signatures, policy version. |
| `result` | Code root, a Merkle root over the per-node results of the batch, check name, tool digest and version, evidence digest, submitter signature. |
| `vouch` | Node or subtree hash, the evidence relied on, reviewer signature. |
| `revocation` | The revoked hash, the reason, a reference to the proof. |
| `key` | A submitter, builder, witness or log key added, rotated or retired. |
| `policy` | A new version of the evidence policy. |

Example admission entry (digests shortened):

```json
{"kind": "admission", "package": "dexweb", "version": "4.2.5",
 "artifact_sha256": "…", "source": {"repo": "https://github.com/matrixdex/dexweb", "commit": "…"},
 "code_root": "…", "scope": {"dexweb.dexgen": ["file"], "dexweb.dexweb": ["file", "process"]},
 "scope_root": "…", "tier": "native", "analyzer": {"name": "pkgmerkle", "root": "…", "python": "3.14"},
 "builders": [{"id": "builder-a", "sig": "…"}, {"id": "builder-b", "sig": "…"}], "policy_version": 1}
```

### 8.4 Operation

- **Batched results.** One `result` entry covers all nodes of one package for one check through a Merkle root over the per-node outcomes. A single node's result is proven by an inclusion proof into the batch.
- **Submission control.** Every entry is signed by a registered submitter key and rate-limited per submitter, as in Sigsum. The log checks signatures and format only; result verification (section 6.2) and monitors judge content.
- **Reproducible admissions.** Every input to the analyzer is in the admission entry, so any monitor can rerun it and compare the code root and scope. A bug found in the analyzer identifies exactly which admissions to recheck.
- **Open question: absence.** An append-only log proves that an entry exists, not that no revocation exists for a hash. Answering "is this hash revoked?" needs either monitors that scan the log or an index committed to by the checkpoint (a verifiable map).

## 9. Planned layers

| Layer | Purpose |
|---|---|
| Vouches and deposits | A reviewer, human or AI, signs an evidence bundle and locks a deposit behind it. A proven breach pays the finder. A vouch attaches to a node or subtree hash, so unchanged subtrees keep it. |
| Data artifacts | Large non-code files (model weights, data tables) with allowed formats, size limits and pinned digests. |
| Patch lane | A fast path from an upstream fix to an admitted garden release. |
| Client gate | A lockfile check and an agent tool that refuse digests without the required evidence. |

## 10. Implementation (v0.1)

### 10.1 Files

| File | Purpose |
|---|---|
| `v0.1/pkgmerkle.py` | The analyzer: code Merkle tree, call resolution, scope detection and roll-up, `TOP`, code root and scope root. Standard library only. |
| `v0.1/synth_demo.py` | Test on a synthetic eight-file package with a dynamic plugin loader, a computed `getattr` dispatcher, and plugins that use files and the network. |
| `v0.1/dexweb_v2.py` | Release-history test over every published wheel of the `dexweb` package. |
| `v0.1/test_pkgmerkle.py` | Regression tests: full digests, prefixes, module-level dependencies (constants, imported constants, class attributes, `global` writers, references, registries, conditional and star imports), precision (unrelated changes do not spread), method receivers (builtins, constructors, parameters, annotations, rebinding, subclass overrides, `super()`, call results, unresolved bases), and one test per checker condition. |
| `v0.1/algobank_diff.py` | Diff tool: compares two versions of a package and reports new scope, dynamic code, hooks, binaries and dependencies (section 10.6). |
| `v0.1/test_diff.py` | Tests for the diff tool on synthetic wheels that reproduce real attack patterns. |
| `v0.1/proofs/CodeRoot.v` | Coq proof of the code root computation (section 10.4). |
| `v0.1/proofs/MerkleSound.v` | Coq proof of Merkle soundness (section 10.5). |
| `v0.1/proofs/check_model.py`, `Extract.v`, `driver.ml` | Check that the proven model computes the same root as `pkgmerkle.py`. |

Built: sections 3.1–3.5, 3.6 (recording pins), 3.7, 3.8, 4.2–4.4, and the proofs of sections 3.3 and 3.4. Everything else is specified.

### 10.2 First garden part

`pkgmerkle.py` meets the admission rules the design favors: small, pure computation, no dependencies outside the standard library, no scope, no `TOP`, no install-time code. Its code root is its identity. It is a candidate part; no log, builders or witnesses exist yet to admit it.

| Item | Value |
|---|---|
| Code root | `39f5dea3511a6adf14f409b143065198031a82916ff21148b58a158d6c7d3791` |
| Scope | none |
| Scope root | `140bedbf9c3f6d56a9846d2ba7088798683f4da0c248231336e6a05679e4fdfe` |
| Nodes | 65 |
| File SHA-256 | `de25bd5cfdb29394b0881f061a452fd8ba7b78193b06877da0e5043c3805881d` |
| Python | 3.14 |

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

### 10.3 Validation

**Synthetic package** (`synth_demo.py`):

| Check | Result |
|---|---|
| Edit `util.clean()`: nodes changed with whole-package resolution | The 5 functions that call it directly or indirectly (`util.clean`, `store.save`, `plugins.a.run`, `core.run`, `core.shout`) and the 2 module values that import it; per-file analysis finds only 1 |
| Computed import and computed `getattr` | Both nodes `TOP` |
| Edit a plugin loaded dynamically | The plugin and the function that calls it through the loader both change |
| Static scope at the loader vs observed at run time | Static: `TOP`, `file`, `network`. Observed with audit hooks: `file` for one plugin, `network` for the other. |

**Real package** (`dexweb_v2.py`, all 25 published wheels, parsed and never run):

| Measure | Value |
|---|---|
| Median share of nodes unchanged from the previous release | 91% by count, 74% by code size |
| Review work across all releases when results are reused | 25% of the work without reuse |
| Updates with no code change | 8 of 24 |
| Scope change detected | `process` first appears in 4.2.3 |
| Scope per module (4.2.5) | `dexweb.dexgen`: `file`, 7 of 22 nodes pure; `dexweb.dexweb`: `file`, `process`, 1 of 11 pure |
| Dependencies | 4, none pinned |
| Module-level dependency | In 4.2.4 the import statement of `dexweb.dexweb` changed. Three functions that read the imported names (`Dexweb.__init__`, `publish_folder`, `run_git`) change hash although their own code did not. |

The dexweb figures come from one small package with one author and should not be generalized.

**Self-analysis:** `pkgmerkle.py` analyzed by itself has 65 nodes, no scope and no `TOP`, and gives identical hashes on repeated runs. A one-line change to `H()` changes `H` and the eight nodes that call it directly or indirectly; the other 56 nodes keep their hashes.

### 10.4 Proof of the code root

`v0.1/proofs/CodeRoot.v` models `Package.leaves()` and `Package.root()` in Coq 8.18 and proves:

| Theorem | Statement |
|---|---|
| `code_root_binding` | If two well-formed packages have the same code root, they contain the same (node id, Merkle hash) pairs. |
| `code_root_canonical` | Listing a package's nodes in a different order gives the same code root. |
| `code_root_correct` | For well-formed packages, the code roots are equal exactly when the sets of pairs are equal. |
| `dup_collision` | Without unique leaves, binding fails: `[a, b, c]` and `[a, b, c, c]` reduce to the same root. |

A package is well formed when it has no repeated pair and every Merkle hash is a 64-character digest; `pkgmerkle.py` guarantees both, because node ids are dictionary keys and Merkle hashes are outputs of `H`.

**Assumptions.** The proof is parameterized over the hash and the sort, with these hypotheses:

1. `H` returns 64 characters and is injective. Injectivity idealizes the collision resistance of SHA-256.
2. The sort returns a permutation of its input, and the same output for inputs that are permutations of each other. Python's `sorted` on strings satisfies both.

`Print Assumptions code_root_correct` reports no axioms beyond these hypotheses. The trusted base is the Coq kernel and the correspondence between the model and the Python code.

**Model check.** `check_model.py` closes the second gap by testing. It extracts the proven `code_root` to OCaml and compares it with `Package.root()` on 5,000 random packages of 0 to 80 nodes, using the same stand-in hash on both sides. All 5,000 roots match. Two deliberate changes to the Python code (pairing an odd last leaf with nothing, and not sorting leaves) each produce mismatches on more than half the cases, so the check detects divergence.

### 10.5 Proof of Merkle soundness

`v0.1/proofs/MerkleSound.v` models the back end's output as a graph with components and proves, in Coq 8.18:

| Theorem | Statement |
|---|---|
| `merkle_sound` | If node `n1` in one analysis and node `n2` in another have the same Merkle hash, every node reachable from `n1` has a counterpart reachable from `n2` with the same Merkle hash. |
| `merkle_sound_content` | The counterpart also has the same own hash and its component has the same pins. |
| `merkle_sound_back` | The same holds in the other direction. |

The theorems hold for any output that meets the checker's conditions (section 3.8), stated in the proof as the record `WF`. Each field of `WF` corresponds to one check in `check_backend`.

**Assumptions.** `H` returns 64 lowercase hex characters and is injective, and the sort returns a permutation of its input. `Print Assumptions merkle_sound_content` reports no axioms beyond these hypotheses.

**What the proof required.** The original encoding joined raw pin strings with `|`. A version specifier containing `|` would make two different pin lists encode the same way, so the proof could not go through. Pins are now hashed before joining.

**Validation.**

| Check | Result |
|---|---|
| One test per checker condition, each confirming the specific failure | All conditions reject a deliberately broken output; for the two structural conditions, Merkle hashes are recomputed first so only the condition under test can fail |
| The theorem on real data: every pair of nodes with the same Merkle hash across consecutive dexweb releases | 24 updates, 527 pairs, every reachable node matched |
| The checker on every analysis in the test suite, the synthetic package, the self-analysis and all 25 dexweb releases | Accepted |

**Gap between proof and code.** The proof covers the conditions; `check_backend` is Python, and its correspondence to `WF` is established by the per-condition tests, not by proof. The front end, including normalization and own hashes, is outside the proof.

### 10.6 Diff tool

`algobank_diff.py` is the first product built on the core. For a Python package it answers two questions a developer or coding agent faces when adding or updating a dependency: what changed, and what can the package do now.

```
python3.14 -I v0.1/algobank_diff.py diff NAME OLD NEW [--json]
python3.14 -I v0.1/algobank_diff.py scope NAME VERSION [--json]
```

`OLD`, `NEW` and `VERSION` are PyPI versions or paths to local wheel or sdist files. The tool downloads a wheel (preferring a pure-Python wheel, otherwise a Linux x86-64 wheel, otherwise the sdist), checks it against PyPI's SHA-256, and reads it in memory. Nothing from the package is installed, imported or run.

**Findings.**

| Finding | Severity |
|---|---|
| New file that runs on every Python start (`.pth`, `sitecustomize.py`) | high |
| Package can now use `network`, `process`, `env`, `native` or `TOP`, which it could not before | high |
| Such a scope newly reachable from existing code, named with where it enters | high |
| New `eval`, `exec`, deserialization, or run-time changes to another module | high |
| New native binary (not analyzed) | high |
| New `file` scope, other new dynamic code (computed imports and attributes, `__getattr__`, `import *`), changed native binary, new dependency, new entry point or installed script | medium |
| Changed dependency range, new or changed data files | low |

Exit status is 1 when any finding is high, 0 otherwise, and 2 on error, so the tool can gate a CI job. `--json` gives the same report for programs and agents. The report also states what it could not see: unparsed files, native binaries, and analysis from an sdist when no wheel exists.

**Validation.**

| Check | Result |
|---|---|
| Synthetic wheels reproducing attack patterns: a `.pth` file with a module that reads the environment and uses the network (LiteLLM 1.107.0); an existing formatting function that starts using the network (chalk/debug); new `exec`; a new native binary; a new dependency | Each produces the expected high or medium finding (`test_diff.py`) |
| A clean update of the same synthetic package, and a dependency range that changes only in formatting | No findings |
| Normal updates of popular packages: requests 2.31.0→2.32.3, urllib3 2.2.1→2.2.2, idna 3.6→3.7, rich 13.7.0→13.7.1, packaging 24.0→24.1 | Four have no medium or high findings. requests has one real change flagged high: a new computed import, run at import time, that selects a character-detection library. |
| dexweb 4.2.2→4.2.3 | `process` reported as new, entering at `Dexweb.run_git` |

**Reuse on real updates.** The share of nodes whose hash is unchanged is 70% for rich 13.7.0→13.7.1, 70% for requests 2.31.0→2.32.3, 65% for urllib3 2.2.1→2.2.2, 75% for idna 3.6→3.7 and 38% for packaging 24.0→24.1. When a function depended on its module's entire top-level code, rich kept 6% and requests 1%.

The known malicious releases of LiteLLM (1.82.7, 1.82.8, 1.107.0) have been removed from PyPI, so they could not be tested directly.

### 10.7 Running

Requirements: Python 3.14, standard library only. The proof additionally needs Coq 8.18 and, for the model check, OCaml with `ocamlfind`.

```
# regression tests
python3.14 -I v0.1/test_pkgmerkle.py

# synthetic package, with runtime observation (any writable scratch directory)
python3.14 -I v0.1/synth_demo.py /path/to/scratch

# dexweb history: fetch the wheels into <scratch>/dexweb/ first
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

```
# diff tool
python3.14 -I v0.1/test_diff.py
python3.14 -I v0.1/algobank_diff.py diff requests 2.31.0 2.32.3

# check the proofs
cd v0.1/proofs && coqc -Q . Algobank CodeRoot.v && coqc -Q . Algobank MerkleSound.v

# compare the proven model with pkgmerkle.py (builds in a temporary directory)
python3.14 -I v0.1/proofs/check_model.py
```

## 11. Known limitations

| # | Limitation | Effect | Remedy |
|---|---|---|---|
| G1 | Module state changed by mutation (for example, appending to a module-level list) in a function that does not declare `global`. | A reader's hash does not depend on the mutating function. | Treat functions that mutate module-level objects as writers; forbid mutable module state in compute parts. |
| G2 | `__getattr__` definitions and `from x import *` are flagged but do not produce `TOP`. | Inconsistent with section 4.4. | Add both flags to the `TOP` rule. |
| G3 | Targets of computed `getattr` are not part of the hash. | A dispatcher can reach changed code without being invalidated. | Reject unbounded dynamic code at admission, or require an explicit target list that joins the hash. |
| G4 | Literal imports of outside modules through `import_module` do not add scope. | Scope is under-reported. | Map literal imports through the scope table. |
| G5 | The scope table is short, Python only, and partly matched by method name. | Unlisted libraries are missed. | A maintained API-to-scope table per language. |
| G6 | Compiled code is invisible to the analyzer. | Native scope is unknown. | Native tier with confinement and native-code evidence (section 5.7). |
| G7 | Method calls on parameters, attributes and call results link to every package method with that name. | Over-approximation, sound but costly. In rich 13.7.0→13.7.1, 765 nodes change hash through dependencies. Receiver type inference (section 3.5) leaves this almost unchanged; even perfect typing of every local and call result would reach 747, and without name-based linking it would be 219. The remainder comes from parameters and attributes, which a library cannot narrow soundly: any caller can pass any object. | Accepted as the cost of soundness. Results stay keyed to the full Merkle hash. |
| G8 | No inclusion proofs for code roots. | A single node cannot be proven without the full leaf list. | Merkle audit paths over the sorted leaves. |
| G10 | Dynamic behavior outside the listed patterns, such as functions stored in dictionaries and called by key. | Not detected. | Runtime enforcement. |
| G11 | Hashes depend on the `ast.dump` format of the interpreter. | A different Python version can give a different root. | Record the version with every root; test roots across versions; move to a version-independent serialization. |
| G12 | Introspection through dunder attributes or frames can reach effectful functions without importing them. | Such code is reported with no scope. Soundness gap. | Treat introspection as `TOP`; allowlist for compute parts (section 4.5); enforce at the boundary. |
| G13 | No `clock` or `entropy` detection. | Code that is not deterministic can appear pure. | Add both scopes to the detection table. |

## 12. Roadmap (v0.2)

1. Close the soundness gap G12, and G2 and G3 so `TOP` is complete.
2. Add `clock` and `entropy` detection (G13) and a per-module scope report.
3. Add inclusion proofs and record the interpreter version with each root (G8, G11).
4. Implement the scope manifest and the declared-versus-detected check.
5. Build the native-tier runner: profile from declared scope, system-call allowlist, self-check, fail closed, profile digest recorded.
6. Stand up a minimal transparency log in the C2SP formats, with the analyzer's code root as its first admission.
7. Implement the admission gates as code.
8. Run the release-history test on larger packages with many contributors.
9. Evaluate the component tier for pure-Python parts with `componentize-py`.
10. Take the diff tool to users: a GitHub Action that comments on pull requests changing `requirements.txt`, `uv.lock` or `poetry.lock`; a shared cache of reports keyed by artifact hash; and an MCP server for coding agents. Measure how often a report changes a decision and how often users mark findings as harmless.
11. Continue proving the core on the front end, back end and checker split (section 3.8):
    1. Roll-up soundness and `TOP` propagation, with the matching conditions added to the checker.
    2. Reuse soundness: a result accepted for a hash stays valid wherever that hash appears.
    3. The result acceptance rule (section 6.2).
12. Define the proof result format and record each core proof in it.

## References

- [RFC 6962](https://www.rfc-editor.org/rfc/rfc6962), [RFC 9162](https://www.rfc-editor.org/rfc/rfc9162): Certificate Transparency
- [RFC 8785](https://www.rfc-editor.org/rfc/rfc8785): JSON Canonicalization Scheme
- [C2SP specifications](https://github.com/C2SP/C2SP/): signed-note, tlog-checkpoint, tlog-cosignature, tlog-witness, tlog-tiles
- [Rekor v2](https://blog.sigstore.dev/rekor-v2-ga/): tile-based transparency log
- [Sigsum design](https://git.sigsum.org/sigsum/tree/doc/design.md): submitter-based rate limiting
- [PEP 578](https://peps.python.org/pep-0578/): Python runtime audit hooks
- [componentize-py](https://www.fermyon.com/blog/introducing-componentize-py) and [ssl in WASI components](https://urllib3future.readthedocs.io/en/latest/wasi.html)
- [PEP 783](https://peps.python.org/0783) and [Pyodide 314](https://blog.pyodide.org/posts/314-release): Emscripten packaging
- [Landlock networking, Linux 6.7](https://phoronix.com/news/Landlock-Networking-Linux-6.7)
- [HACL\*](https://github.com/hacl-star/hacl-star): formally verified cryptography
