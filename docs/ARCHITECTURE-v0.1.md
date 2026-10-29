# Algobank architecture

Version 1.0.0 · Python 3.14

This document is the reference for the design of Algobank. It tells what Algobank is. It tells how each part works. It tells which parts are built. It tells which parts are only specified.

Status markers:

- **[built]**: implemented in `v0.1/`. Tests exist.
- **[spec]**: specified in this document. Not implemented.

## 1. Overview

Algobank is a curated library of software parts. The library is the garden. Each part shows what it can do. Parts compose into larger programs. A composed program gets no hidden powers.

Each part has a content hash. A change to a part changes its hash. Thus each change is exact and visible. Work on an unchanged part is not done again.

### 1.1 The core

The core is Algobank without banking and insurance. The core has three parts:

1. **Identity.** A code Merkle tree gives a hash to each package. It also gives a hash to each function. Changes are exact. Earlier work is used again. [built]
2. **Scope.** The scope of the code is visible. Dynamic code is `TOP`. [built]
3. **Results by hash.** Any party can publish a signed result about a node. Examples are a test run, a fuzz run, an AI review and a leak check. Algobank keeps the result against the hash. Algobank uses the result again while the hash does not change. [spec]

### 1.2 What Algobank owns

Algobank owns a small set of core checks:

- computation of identity and scope;
- the admission gates (section 7);
- verification of submitted results: signature, hash binding and sampled reruns (section 6);
- replay of breach proofs (bank layer).

Algobank also sets the evidence policy. The policy tells which results each scope and tier needs.

All other checks are external tools. Examples are tests, fuzzers, linters and reviews. Their signed results attach to node hashes. A result attaches to a hash, not to a pipeline step. Thus external checks are independent. They run in any order. You can add a check without a change to the core.

Algobank runs a reference set of checks at the start. Thus the result store is not empty.

### 1.3 Design principles

1. Scope is always visible. "Scope" and "capability" have the same meaning.
2. Identity comes from code Merkle trees. One package is one tree. One tree has one root.
3. Algobank resolves calls across modules. Dynamic imports are `TOP`. Reflection is `TOP`. Monkey-patching is `TOP`.
4. Static analysis sorts and flags. A boundary outside the code enforces.
5. Each enforcement step fails closed. If Algobank cannot apply and verify a restriction, the part does not run.
6. Algobank uses existing standards and tools where they fit.
7. Simplicity is more important than saved work. Add complexity only when core functionality is not possible without it. If the alternative is only more computation, use the CPU cycles. Keep the design simple.
   Example: an independent review of each function prevents a full recheck after a change. A full recheck gives the same result. Thus Algobank does not add independent function review.
8. Findings are signal. Algobank does not suppress a finding because it is common. Algobank does not downgrade a finding because it is "probably harmless". Algobank reports each unexplained power. Algobank rates code that it cannot see into by what the code can do (`TOP`).
   Findings are feedback for codegens. The feedback gives better code. Example: Algobank analyzed its own release. It flagged a parse-only `compile()` call as `TOP`. A change to `ast.parse` made the scope of the tool exact.
9. Catch once. Pass each time. Each package is a version. Its hash identifies it.
   - An insecure version must be caught only once. Algobank keeps each catch forever.
   - A secure version must pass each time Algobank checks it.
   - Algobank keeps a pass only as the admission of that exact version (section 9.1).
   - A pass never moves to a different version.
   - The codegen checks each version that is not admitted. This redundancy uses CPU cycles on purpose.

### 1.4 Layers above the core

Banking and insurance are layers on top of the core. They include vouches, deposits, penalties, interest and payouts. They are not part of version 1.0.0. Section 9 lists them.

## 2. Terms

| Term | Meaning |
|---|---|
| **Package** | A set of source files that Algobank analyzes together. One package has one code Merkle tree. |
| **Algobanking** | Analysis and storage. Analysis computes the code Merkle tree and scope of a version. Analysis then checks the result. Thus analysis decides if the version is safe. The analysis is available in Algobank. Storage keeps the version by its hash. Storage is admission to the club of versions that are safe by Algobank standards. An admitted version is safe to use again. Admission stops when Algobank finds the version insecure (section 9.1). Algobank is the first algobanked code. It has algobanked itself. Findings do not stop algobanking. |
| **Codegen** | Anything that writes or runs code. Examples are AI coding agents, GitHub Actions and other CI runners, package managers, build systems and human maintainers. |
| **Called package** | A package that a package calls. It is a dependency. |
| **Part** | A package that the garden admits. It is the unit that Algobank confines and runs. |
| **Node** | A function or method (`module:qualname`). A top-level code block of a module (`module:<module>`). A module value (`module:=name`). |
| **Own hash** | The hash of the normalized syntax tree of one node only. |
| **Merkle hash** | The own hash with the Merkle hashes of each node that the node calls. It also includes the pins of the outside packages that the node uses. |
| **Leaf** | `H(0x00 ‖ node_id ‖ "=" ‖ merkle_hash)`. It commits to the public name of the node. It also commits to the content of the node. |
| **Code root** | The binary Merkle root over the sorted leaves of a package. It is the identity of the package. |
| **Scope** | A power that the code can use. Examples are `file` and `network`. |
| **Scope root** | The hash of the sorted set of all scopes in a package. |
| **`TOP`** | Unknown or unbounded scope. It contains all other scopes. |
| **Pin** | A fixed identifier for an outside dependency. Pins are part of the hash. |
| **Compute part** | A part that declares no scope. |
| **Effect part** | A part that declares one or more narrow scopes. |
| **Tier** | The type of confinement for a part at run time. There are two tiers: the component tier and the native tier (section 5.2). |
| **Result** | A signed statement by a check about the hash of a node or package. |

## 3. Identity: the code Merkle tree [built]

### 3.1 Nodes

- Each function and each method is a node. The class depth is not important. An async function is a function.
- The top-level code of each module is a node. Its name is `<module>`. It is the module without the bodies of its functions. It keeps imports, constants and class headers. It keeps each statement that runs at import time. It represents the import of the module.
- Each module-level name is a node. This node is a module value (`module:=name`). It holds the top-level statements that bind the name. It also holds the top-level statements that can change the name. These statements include:
  - assignments;
  - imports;
  - class definitions without their methods;
  - conditional definitions;
  - statements that change the name, for example `REG["a"] = f` and `sys.path.insert(...)`.
- A statement that binds more than one name belongs to each of these names.
- Some top-level statements bind no name and change no name. In each module, these statements are one node. Its name is `module:=<effects>`.
- A nested function is part of its parent node. A lambda is also part of its parent node.

### 3.2 Normalization

A change with no meaning must not change the hash. The normalized tree has no line numbers.

| Item | Treatment |
|---|---|
| Function name | Replaced by `_`. The name is in the leaf. The name is not in the own hash. |
| Parameters and local variables | Renamed by position: `_0`, `_1`, and so on. |
| Argument annotations | Removed. |
| Docstring (first statement, if a string) | Removed. |
| Decorators, default values, return annotations | Kept. |
| Global names, attributes, import aliases, constants | Kept as written. |

Rule: if an item can change behavior, it stays in the hash.

These changes do not change the hash:

- new formatting;
- new names for local variables;
- changes to docstrings.

### 3.3 Merkle hash and cycles

Algobank puts nodes into components (section 3.8). The Merkle hash of a node is `H(base + own)`:

- `own` is the hash of the normalized code of the node.
- `base` is the hash of the component of the node.

```
base = H( "|".join(sorted own hashes of the component's members)
        + "#" + "|".join(Merkle hashes of the component's external dependencies)
        + "#" + "|".join(H(pin) for each sorted pin string) )
```

Each item between `|` signs is a 64-character hex digest. Thus the encoding splits back in one way only. A version specifier can contain `|`. Thus Algobank hashes each pin string before the join.

Proven property (section 10.5): if the Merkle hash of a node does not change, each node that it can reach has a counterpart. The counterpart has the same Merkle hash. It has the same own hash. It has the same pins. Thus an unchanged hash shows unchanged code below it. This makes the reuse of results safe.

A node depends only on what it uses:

- A function depends on the functions that it calls.
- A function depends on the functions that it references.
- A function depends on the module values that it reads. This includes values from a different module. Example: `config.LIMIT` depends only on `config:=LIMIT`.
- A method also depends on the value of its class. The class value holds the class attributes.
- A module value depends on what its statements read, call or import. Example: `from .config import LIMIT` makes the local value depend on `config:=LIMIT`.
- A function can write a name through `global`. This function is a dependency of the value of that name. Thus each reader depends on the writer.
- Each function in a module depends on the `<effects>` node of the module, if the module has one.

Thus a change to one module-level name changes only the code that reads that name.

Recursion makes cycles. Mutual recursion also makes cycles. Thus Algobank computes the hash for each component. Algobank hashes each component as one unit. Each member then adds its own hash to that value.

### 3.4 Code root

1. Compute the leaf of each node: `H(0x00 ‖ node_id ‖ "=" ‖ merkle_hash)`.
2. Sort the leaves.
3. Hash pairs upward as `H(0x01 ‖ left ‖ right)`. If a level has an odd number of leaves, duplicate its last leaf. Continue until one root remains.

The 0x00 prefix is for leaf inputs. The 0x01 prefix is for interior inputs. This is the method of RFC 6962. Thus a leaf can never look like an interior node.

A package with no nodes has the root `H("empty")`.

The root commits to names and content. Names are the public interface. A new function name changes the root. New formatting does not change the root.

Proven properties (section 10.4). These properties assume a collision-resistant hash:

- **Binding.** Two packages have the same code root only if they have the same set of (node id, Merkle hash) pairs.
- **Order independence.** The root depends only on that set. The order of the nodes is not important.

Binding needs unique node ids. Repeated leaves cause a collision. The rule that duplicates an odd last leaf gives the same root to different lists. Example: `[a, b, c]` and `[a, b, c, c]` have the same root.

### 3.5 Call resolution

The call graph covers the full package.

| Case | Handling |
|---|---|
| `import a.b`, `import a.b as x` | Binds a module. An attribute chain resolves to the longest module that matches. Then it resolves to the function. |
| `from a.b import f as g` | Binds a function, class or submodule. |
| Relative imports | Resolved from the package of the importing module. |
| A new instance of a class | Resolves to the `__init__` of the class. |
| Each other method call `x.m()`. This includes `self.m()`, `super().m()` and calls on call results. | An edge to each method with the name `m` in the package. This covers subclass overrides. It covers each receiver type. It is an over-approximation. It can invalidate more than necessary. It never invalidates less. |
| Top-level code of a module | Edges to the top-level code of each package module that it imports. Edges to each package function that it calls at import time. |
| Imports in a function | Added to the name table of that function. |
| `from x import *` | Flagged `star-import`. Algobank does not resolve the names that it brings. |

Algobank never narrows method calls by inferred types. Narrowing would only decrease rechecks. Thus principle 7 does not permit it. Also, type annotations are not reliable. A caller can give any object.

Algobank does not follow calls into outside packages. These calls add to scope (section 4) and to pins (section 3.6).

### 3.6 Dependencies and pins

Each outside package that a node uses becomes a pin in the hash of that node. [built]

- Version 1.0.0 reads dependency names from wheel metadata (`Requires-Dist`).
- Version 1.0.0 maps import names to distribution names where they are different. Example: `bs4` maps to `beautifulsoup4`.

A garden part can depend only on other garden parts. Each dependency is pinned by digest. Version 1.0.0 records pins. It does not enforce this rule. [spec]

### 3.7 Hash function

`H` is SHA-256. Algobank writes it as 64 hex characters.

All digests in a tree have the same length. If not, `root()` gives an error. The split of a joined input into its halves needs that length.

Hashes come from the `ast.dump` function of Python. Its format can change between interpreter versions. Thus Algobank records the interpreter version with each root.

### 3.8 Front end, back end and checker

The analyzer has three parts:

| Part | Input | Output | Trust |
|---|---|---|---|
| Front end | Source files | Facts for each node: own hash, dependency edges, pin strings, direct scope, flags | Trusted. Tests exist. Python has no formal semantics. Thus no proof is possible against it. |
| Back end (`backend`) | The facts | Components (Tarjan's algorithm). Merkle hashes over all dependency edges. Rolled-up scope and flags over call edges only (section 4.3). | Not trusted |
| Checker (`check_backend`) | The facts and the output of the back end | Accept, or an error | Checks the conditions of the Merkle soundness proof exactly |

The checker verifies these conditions:

1. Each own hash is a digest.
2. Each node belongs to the component that it is assigned to. It belongs to no other component.
3. All members of each component can reach each other.
4. Each dependency edge stays in its component, or it is in the list of external dependencies.
5. Each listed external dependency is used.
6. Each Merkle hash satisfies the equation in section 3.3.

The analyzer runs the checker on each analysis. If the checker fails, the analyzer stops. Thus the theorem covers each result of the analyzer.

This is the proven-checker method. Tarjan's algorithm has no proof. Its output is checked.

## 4. Scope

### 4.1 The scope set

| Scope | Covers | Detected in 1.0.0 | Component tier | Native tier |
|---|---|---|---|---|
| `file` | Reading, writing, listing or deleting files | yes | enforced | enforced |
| `network` | Each network connection or listening socket | yes | enforced | enforced |
| `process` | Starting or signaling other processes | yes | enforced | enforced |
| `env` | Reading or changing environment variables | yes | enforced | enforced |
| `native` | Loading native code (`ctypes`, `cffi`, C extensions) | yes | not permitted | native tier only |
| `clock` | Reading the time or date | no (G13) | enforced | detected only |
| `entropy` | Reading random numbers, `os.urandom`, `uuid4` | no (G13) | enforced | detected only |
| `TOP` | Unknown or unbounded behavior | yes | must be resolved or rejected | must be resolved or rejected |

`clock` and `entropy` are scopes for three reasons:

- Algobank uses a result again only while the code is deterministic.
- A clock is a frequent trigger for dormant malicious behavior.
- Key generation depends on the quality of its random source.

Enforcement in both tiers is [spec] (section 5).

### 4.2 Detection [built]

Scopes come from a table. The key of the table is the source of an imported name.

| Source | Scope |
|---|---|
| `socket`, `ssl`, `urllib`, `http`, `requests`, `httpx`, `aiohttp`, `ftplib`, `smtplib`, `websockets` | `network` |
| `subprocess`, `multiprocessing`; `os.system`, `os.popen`, `os.execv`, `os.execl`, `os.execvp`, `os.spawnl`, `os.fork`, `os.kill` | `process` |
| `open()`, `shutil`, `tempfile`, `glob`; `os.remove`, `os.unlink`, `os.rmdir`, `os.rename`, `os.replace`, `os.makedirs`, `os.mkdir`, `os.listdir`, `os.scandir`, `os.walk`, `os.chmod` | `file` |
| Methods with the names `.write_text`, `.read_text`, `.write_bytes`, `.read_bytes`, `.unlink`, `.rmtree`, `.mkdir`, `.touch` | `file` (matched by name) |
| `os.environ`, `os.getenv`, `os.putenv` | `env` |
| `ctypes`, `cffi` | `native` |

### 4.3 Roll-up [built]

The rolled-up scope of a node is its own scope plus the rolled-up scope of all code that runs when it runs:

- the functions that it calls;
- for the top-level code of a module: the modules that it imports;
- for the top-level code of a module: the functions that it calls at import time.

Roll-up follows these call edges only. A function can read the constants of a module. For hashing, the function then depends on that module (section 3.3). But the function does not run the import-time code of that module. Thus it does not get the scope of that code.

The scope of a package is the union of the scopes of its nodes. The scope root is the hash of that set. A new scope anywhere changes the scope root. This shows where a new power came in.

### 4.4 `TOP` [built]

| Construct | Flag | Effect |
|---|---|---|
| Import with a computed name (`importlib.import_module(x)`, `__import__(x)`). Entry-point loading. | `dyn-import` | `TOP`. Also an edge to each module in the package. Thus a change to any module invalidates the node. |
| `getattr`, `setattr`, `delattr` with a computed name. `globals()`, `locals()`, `vars()`. | `dyn-attr` | `TOP` |
| `eval`, `exec`, `compile`. Loads from `pickle`, `marshal`, `dill`, `shelve`. | `dyn-exec` | `TOP` |
| Assignment to an attribute of an imported module. A write to `sys.modules`. | `dyn-patch` | `TOP` |

Algobank resolves an import of a package module with a literal name as a normal import.

`TOP` goes to each caller. A `TOP` node cannot get a result such as "uses no network". It can get only results that are true for all of its possible behaviors.

### 4.5 Compute and effect parts [spec]

Reviewers must examine the small parts that touch files, the network or processes. Pure compute parts need less review. Thus Algobank separates computation from effects.

1. **Two types of part.**
   - A compute part declares no scope. It has no effectful imports. It has no `TOP`. It has no introspection. It has no clock. It has no randomness.
   - An effect part declares narrow scopes with parameters. Examples: `file: read ./data` and `network: api.example.com:443`. Effect parts must be small.
2. **Effects come in as arguments.** Compute code gets data from its caller. It also gets readers, clients, the current time and random generators from its caller. It never gets them itself. Thus authority is visible at the point where parts connect. This pattern is "functional core, imperative shell".
3. **Manifest.** Each package declares the scope of each module in a manifest, for example `algobank.toml`. Admission rejects each module whose detected scope is larger than its declared scope. Admission reports declared scope that is never used.
4. **Allowlist for compute parts.** A compute part can import only from a list of pure standard-library modules. It cannot use dunder introspection. It cannot use frame access. An allowlist fails safe. A denylist of dangerous names always misses something.
5. **Review by scope.** The evidence policy (section 6.4) needs more evidence for a larger scope.

## 5. Enforcement [spec]

### 5.1 Principle

Static analysis decides where to look. It decides what to flag. It does not enforce.

Python cannot isolate one module from a different module in one process. Thus enforcement occurs at a boundary between parts. Calls across that boundary are serialized. This has a cost. Thus parts must be large enough to make that cost acceptable.

### 5.2 Tiers

| | Component tier | Native tier |
|---|---|---|
| Boundary | WebAssembly component | Confined operating-system process |
| Platforms | Linux, macOS, Windows | Linux. Other systems run the host in a Linux VM. |
| Scopes enforced | All. This includes `clock` and `entropy`. | `file`, `network`, `process`, `env`. `clock` and `entropy` are detected only. |
| Typical parts | Pure-Python code | Packages with C extensions, such as NumPy |
| Status | The only long-term boundary | For parts that cannot run as components yet |

**Component tier.** A part runs as a WebAssembly component.

- A compute component gets no imports.
- An effect component gets only the WASI interfaces that it declared. Example: the file system, limited to one pre-opened directory.
- `componentize-py` builds Python components. It supports pure Python well. It supports packages with C extensions only partly.
- The `ssl` module of CPython is not available in a component.

**Native tier.** A part runs in its own confined process (section 5.3). Packages with C extensions stay in this tier until a component build exists.

Emscripten builds (Pyodide) run NumPy already. But they target a JavaScript host. They do not target WASI components. WASI builds of NumPy are not available yet.

Algobank records the tier of a part at admission. Agents and reviewers can see it. The evidence policy depends on it.

### 5.3 Native-tier confinement

The Linux kernel enforces each restriction. The host of Algobank only configures the restrictions. Code in the part cannot cancel them.

| Layer | Effect |
|---|---|
| Namespaces (user, mount, network, PID, IPC) | The part sees only its mounted files. It sees no network interfaces. It sees only its own processes. An empty network namespace blocks all protocols. |
| Privileges | `no_new_privs` is set. All capabilities are dropped. The part cannot get rights. |
| System-call filter (seccomp) | An allowlist of the system calls that the runtime needs. The filter refuses internet sockets. It refuses new namespaces. It refuses process tracing. It refuses kernel-module loading. After start-up, it refuses new programs. |
| File rules (Landlock) | A second file layer below the mount namespace. It is a layer. It is never the boundary. |
| Resource limits (cgroups, rlimits) | Limits for memory, CPU, process count and open files. |
| gVisor or a microVM (Firecracker) | For effect parts. For parts that parse input that is not trusted. The part talks to a small user-space kernel or a minimal VM. It does not talk to the host kernel. |

### 5.4 Launch sequence

1. The host makes a confinement profile from the declared scope of the part. The declared scope is in the admission record.
2. The host starts the process. It applies namespaces and mounts. It clears the environment. It drops privileges.
3. A small trusted runner in the process applies the final system-call filter.
4. The runner then verifies its own state:
   - no capabilities;
   - the filter is active;
   - no network interfaces;
   - the mounts are as expected.
   If a check fails, the runner stops. It does not load the part.
5. The runner imports the part. This includes its native extensions.
6. Data goes in and out only through a pipe. The data has a plain format. A schema checks the data.
7. Algobank records the digest of the confinement profile with the run.

### 5.5 Two-way boundary

The host does not trust the output of a part. The host never unpickles the output. The host never executes the output. The host parses the output from a plain format. A schema validates the output.

### 5.6 Failing closed

Algobank verifies each layer. It does not assume a layer. If the kernel does not have a feature that the profile needs, the part does not run.

Landlock shows why:

- The kernel rejects rules that it does not support.
- But best-effort libraries drop these rules silently.
- Thus the host checks the Landlock version before it uses Landlock.
- Network rules need version 4 (Linux 6.7).

### 5.7 Native-tier security rules

Native code has no memory safety. The analyzer cannot see the scope of compiled code. Thus the native tier is weaker than the component tier. These rules apply:

1. **Native code only when measured performance needs it.**
2. **Always confined.** A native part never runs outside the profile in section 5.3.
3. **Nothing to steal.** The process holds no credentials. It holds no secrets. It holds no files outside its declared scope.
4. **Evidence for native code.** This evidence includes:
   - reproducible builds by independent builders;
   - fuzzing with memory-error detectors (sanitizers);
   - hardened compiler settings;
   - a vouch from a reviewer on the native source.
5. **Sampled cross-checks.** If a component build exists, Algobank runs a random sample of real calls on it again. Algobank compares the outputs. This finds wrong results from a compromised native part. Agreement shows correctness on the sampled inputs. Agreement does not show that the native code is secure.
6. **Input that is not trusted.** Native code that parses untrusted files or network data needs the component tier. Alternatively, it needs much more evidence.
7. **Memory-safe native code is preferred.** A Rust extension is better than a C extension. Reviewers examine `unsafe` blocks specially.

### 5.8 Tools

Confinement uses existing tools:

- bubblewrap or nsjail for namespaces, seccomp and resource limits;
- gVisor and Firecracker for the stronger option.

Algobank's own code is:

- the runner;
- the map from declared scope to profile;
- the self-check;
- the record of the profile digest.

Python audit hooks (PEP 578) are not a boundary. PEP 578 tells that they are not a sandbox. Algobank uses them only to observe.

## 6. Results and evidence [spec]

### 6.1 Results by hash

A result names these items:

- the hash of the node or package that it covers;
- the check: the tool, the tool digest and the tool version;
- the outcome;
- the digest of its evidence;
- the signature of the submitter.

A result stays valid while the hash that it names does not change. Thus Algobank never checks unchanged code again.

A result for a `TOP` node is limited to properties that are true for all of its possible behaviors.

### 6.2 Verification of submitted results

A store of signed results from any party is a target. Algobank accepts a result only if these conditions are true:

1. The signature is valid. The submitter is registered.
2. The result is bound to the correct hash and checker version.
3. Sampled reruns of deterministic checks give the same result.

### 6.3 Reference runner

Algobank runs a reference set of external checks itself. Thus the store is not empty before other parties contribute.

### 6.4 Evidence policy

The policy tells which results each scope and tier needs.

- Example: a compute part in the component tier can need tests and the static checks.
- Example: an effect part with `network` in the native tier can also need a fuzz result and a vouch from a reviewer.

The policy has versions. The log records each version (section 8).

### 6.5 Work frontier

For a code root, the work frontier is the set of nodes with no valid result for a necessary check. Agents and reviewers work on the frontier only.

### 6.6 Formal proofs

A proof is the strongest type of result. A test shows a property for the tested inputs. A proof shows that a node meets a specification for all inputs.

A proof result records:

- the node hash that it covers;
- the digest of the specification;
- the prover and the proof checker, with digests and versions;
- the digest of the proof artifact.

**Specifications are artifacts.** A proof shows that code matches its specification. A proof does not show that the specification is correct. Thus Algobank hashes, logs and reviews specifications like code. A proof is valid only while the node hash does not change. It is also valid only while the specification digest does not change.

**A recheck costs little.** It is expensive to find a proof. It is fast to check a proof. The check is deterministic. Algobank runs the proof checker again on submitted proofs. Thus proofs are good for the verification in section 6.2. Algobank accepts proofs from AI agents on the same terms. The checker decides. The author does not decide.

**Scope of a proof.** A proof is true for the model that it was checked against. It assumes that the compiler behaves as modeled. It assumes the same for the runtime and the hardware. It does not cover side channels. Confinement (section 5) also applies to proven parts.

**Where proofs apply.**

- Compute parts. They are small and pure. Examples are parsers, codecs, numeric routines and cryptographic primitives.
- The trusted base. Each admission depends on it. It includes the analyzer, the code and log Merkle functions, signature checks and the self-check of the runner.
- Native code. A proof of memory safety removes the main weakness of the native tier (section 5.7).

Python has no mature general verifier. Thus proven parts use a verifiable subset or a verification language. Examples are F\*, Lean, Dafny, and Rust with Verus or Kani. Python then calls them. HACL\* is an example in production. It is verified cryptography. It is written in F\*. It compiles to C.

**Policy.** Proofs are optional evidence. The evidence policy (section 6.4) can accept a proof in place of other results. Example: a proven parser of untrusted input can meet a requirement that otherwise needs much fuzzing. Algobank never rejects a part because it has no proof.

## 7. Admission [spec]

A package becomes a part only when all gates pass:

1. The repository identity and the commit are pinned.
2. At least k of n independent builders rebuild the release from the pinned commit. The builders use different operators, clouds and keys. They must agree on the digest. Admission always rebuilds from the start. Builders never share a cache.
3. The source has no binary blobs. It has no install-time hooks. It has no startup hooks.
4. Each dependency is a garden part. Each dependency is pinned by digest.
5. No `TOP` stays unresolved. Dynamic behavior is removed, or it is limited to an explicit list of targets. That list is part of the hash.
6. The detected scope is not larger than the declared scope (section 4.5).
7. The tier is assigned. The confinement profile can be applied on the target platform.
8. The part meets the evidence policy for its scope and tier.

## 8. Transparency log [spec]

An append-only log records these events:

- each admission;
- each result;
- each vouch;
- each revocation;
- each key change;
- each policy change.

The log uses existing open specifications.

### 8.1 Two trees

- The **code Merkle tree** identifies code. There is one tree for each package (section 3). Its root is a value in a log entry.
- The **log Merkle tree** records entries. There is one global tree. It is append-only. Its root proves that no past entry was changed or removed.

### 8.2 Format

| Part | Specification |
|---|---|
| Tree hashing | RFC 6962 / RFC 9162. Leaf hash = SHA-256(0x00 ‖ entry bytes). Interior hash = SHA-256(0x01 ‖ left ‖ right). |
| Digests | Full SHA-256. |
| Signed tree head | C2SP `tlog-checkpoint` in `signed-note` format. It holds the origin of the log, the tree size and the root hash. Signatures follow. |
| Witness cosignatures | C2SP `tlog-cosignature`, collected through C2SP `tlog-witness`. A client accepts a checkpoint only when k of n witnesses cosigned it. This stops the operator from showing different histories to different clients. |
| Serving | C2SP `tlog-tiles`. The log is published as static files. The files can be cached. Rekor v2 of Sigstore uses this model. |
| Entry encoding | JSON, canonicalized with RFC 8785. Large evidence is kept outside the log. The entry references it by digest. |

### 8.3 Entry types

| Type | Content |
|---|---|
| `admission` | Package name and version. Artifact digest. Source repository and commit. Code root. Declared and detected scope for each module. Scope root. Tier. Analyzer root and Python version. Builder signatures. Policy version. |
| `result` | Code root. A Merkle root over the results of the batch for each node. Check name. Tool digest and version. Evidence digest. Submitter signature. |
| `vouch` | Node or subtree hash. The evidence that the reviewer used. Reviewer signature. |
| `revocation` | The revoked hash. The reason. A reference to the proof. |
| `key` | A key for a submitter, builder, witness or log. The key is added, rotated or retired. |
| `policy` | A new version of the evidence policy. |

Example admission entry. The digests are shortened.

```json
{"kind": "admission", "package": "dexweb", "version": "4.2.5",
 "artifact_sha256": "…", "source": {"repo": "https://github.com/matrixdex/dexweb", "commit": "…"},
 "code_root": "…", "scope": {"dexweb.dexgen": ["file"], "dexweb.dexweb": ["file", "process"]},
 "scope_root": "…", "tier": "native", "analyzer": {"name": "pkgmerkle", "root": "…", "python": "3.14"},
 "builders": [{"id": "builder-a", "sig": "…"}, {"id": "builder-b", "sig": "…"}], "policy_version": 1}
```

### 8.4 Operation

- **Batched results.** One `result` entry covers all nodes of one package for one check. It does this through a Merkle root over the outcome of each node. An inclusion proof into the batch proves the result of one node.
- **Submission control.** A registered submitter key signs each entry. The log limits the rate for each submitter, as in Sigsum. The log checks only signatures and format. Result verification (section 6.2) and monitors judge the content.
- **Reproducible admissions.** Each input to the analyzer is in the admission entry. Thus any monitor can run the analyzer again. It can compare the code root and the scope. If someone finds a bug in the analyzer, the log shows which admissions to check again.
- **Open question: absence.** An append-only log proves that an entry exists. It does not prove that no revocation exists for a hash. The question "is this hash revoked?" needs one of two solutions:
  - monitors that scan the log;
  - an index that the checkpoint commits to (a verifiable map).

## 9. Planned layers

| Layer | Purpose |
|---|---|
| Vouches and deposits | A reviewer signs an evidence bundle. The reviewer can be a human or an AI. The reviewer locks a deposit behind it. A proven breach pays the finder. A vouch attaches to a node or subtree hash. Thus unchanged subtrees keep it. |
| Data artifacts | Large files that are not code, for example model weights and data tables. They have permitted formats, size limits and pinned digests. |
| Patch lane | A fast path from an upstream fix to an admitted garden release. |
| Client gate | A lockfile check and an agent tool. They refuse digests that do not have the necessary evidence. |

### 9.1 Admission and insurance

Each package is a version. The version is the exact code that Algobank received. Its hash identifies it. Algobank admits or rejects each version alone.

- **Admission.** A version that passes algobanking is stored. It is admitted to the club of versions that are safe by Algobank standards. Algobank insures admitted versions. Their maintainers get their share of usage fees. 33% of the insurance fee goes to the programmers of the current iteration.
- **Rejection.** A failed check makes a version insecure. A known-bad record also makes a version insecure. Algobank keeps the insecure version in its cache permanently.
  - Rejection affects only that version. A rejected v2 does not affect an admitted v1.
  - If a newer version is rejected and an older version is admitted, Algobank recommends the older version. Algobank continues to insure it.
  - Algobank uses only versions that it found secure. This includes later versions that it admits after a rejection.
- **Fees after rejection.** Users of a rejected version pay the same cost for the code. But the version has no insurance. Its maintainer gets no share. The withheld money is a pool. The pool rewards secure, insured algorithms.
  - Users have a reason to move to insured versions.
  - Maintainers and codegens have a reason to make a patch quickly.
  - They have a reason to release the patch. They have a reason to get admission again.
- **Disclosure.** Algobank tells users of a rejected version that it has no insurance. Algobank tells them which admitted version has insurance. The incentive works only when users know which versions have insurance.

## 10. Implementation (1.0.0)

### 10.1 Files

| File | Purpose |
|---|---|
| `algobank/pkgmerkle.py` | The analyzer. It computes the code Merkle tree. It resolves calls. It detects and rolls up scope. It flags `TOP`. It computes the code root and the scope root. It uses the standard library only. |
| `v0.1/synth_demo.py` | Test on a synthetic package of eight files. The package has a dynamic plugin loader and a computed `getattr` dispatcher. Its plugins use files and the network. |
| `v0.1/dexweb_v2.py` | Release-history test over each published wheel of the `dexweb` package. |
| `v0.1/test_pkgmerkle.py` | Regression tests. They cover full digests and prefixes. They cover module-level dependencies: constants, imported constants, class attributes, `global` writers, references, registries, conditional imports and star imports. They cover precision: unrelated changes do not spread. They cover method calls: subclass overrides, `super()`, call results, and receivers that must never be narrowed. There is one test for each checker condition. |
| `pyproject.toml` | Package metadata for PyPI. The build backend is `flit_core`. It has no dependencies. The wheel contains only `algobank/`. |
| `algobank/diff.py` | The diff tool and the `algobank` command. It compares two versions of a package. It reports new scope, dynamic code, hooks, binaries and dependencies (section 10.6). |
| `v0.1/test_diff.py` | Tests for the diff tool. They use synthetic wheels that copy real attack patterns. |
| `site/` | The source of the website. The website is a dex. dexweb builds it (section 10.9). It is not shipped. |
| `v0.1/build_cache.py` | Builds `algobank/known.json` from the published advisory repositories (section 10.6, known data). It is not shipped. It is the only part of Algobank that uses the network. It downloads no package. It analyzes no package. |
| `algobank/known.json` | Published advisory records for popular packages. The records are not changed. They ship in the package. |
| `v0.1/proofs/CodeRoot.v` | Coq proof of the code root computation (section 10.4). |
| `v0.1/proofs/MerkleSound.v` | Coq proof of Merkle soundness (section 10.5). |
| `v0.1/proofs/check_model.py`, `Extract.v`, `driver.ml` | Check that the proven model computes the same root as `pkgmerkle.py`. |

Built: sections 3.1–3.5, 3.6 (pin records), 3.7, 3.8 and 4.2–4.4. The proofs of sections 3.3 and 3.4 are also built. All other sections are specified only.

### 10.2 First garden part

`pkgmerkle.py` meets the admission rules that the design prefers:

- It is small.
- It is pure computation.
- It has no dependencies outside the standard library.
- It has no scope.
- It has no `TOP`.
- It has no install-time code.

Its code root is its identity. It is a candidate part. No log exists yet to admit it. No builders exist. No witnesses exist.

| Item | Value |
|---|---|
| Code root | `ef9e84687a74c28fd06aa5867b3e4a447f9bbdea68087a8b1ceb649ec1c503ab` |
| Scope | none |
| Scope root | `140bedbf9c3f6d56a9846d2ba7088798683f4da0c248231336e6a05679e4fdfe` |
| Nodes | 50 |
| File SHA-256 | `601182eaf3303372010e79c2fcd7c47015544ab43588a41976e96f24f53a8916` |
| Python | 3.14 |

To compute these values again:

```
cd algobank
python3.14 -I -B -c "
import sys; sys.path.insert(0, '..')
from algobank.pkgmerkle import Package
with open('pkgmerkle.py') as fh:
    p = Package({'pkgmerkle.py': fh.read()})
print(p.root(), p.scope(), p.scope_root(), len(p.nodes))"
```

### 10.3 Validation

**Synthetic package** (`synth_demo.py`):

| Check | Result |
|---|---|
| Edit `util.clean()`. Count the changed nodes with whole-package resolution. | 5 functions that call it directly or indirectly change: `util.clean`, `store.save`, `plugins.a.run`, `core.run`, `core.shout`. 2 module values that import it change. Analysis of each file alone finds only 1. |
| Computed import and computed `getattr` | Both nodes are `TOP`. |
| Edit a plugin that is loaded dynamically | The plugin changes. The function that calls it through the loader also changes. |
| Static scope at the loader compared with the scope observed at run time | Static: `TOP`, `file`, `network`. Observed with audit hooks: `file` for one plugin. `network` for the other plugin. |

**Real package** (`dexweb_v2.py`). Algobank parsed all 25 published wheels. It ran none of them.

| Measure | Value |
|---|---|
| Median share of nodes that did not change from the previous release | 91% by count. 74% by code size. |
| Review work across all releases when results are used again | 25% of the work without reuse |
| Updates with no code change | 8 of 24 |
| Scope change detected | `process` first comes in 4.2.3. |
| Scope for each module (4.2.5) | `dexweb.dexgen`: `file`. 7 of 22 nodes are pure. `dexweb.dexweb`: `file`, `process`. 1 of 11 nodes is pure. |
| Dependencies | 4. None is pinned. |
| Module-level dependency | In 4.2.4 the import statement of `dexweb.dexweb` changed. Three functions read the imported names: `Dexweb.__init__`, `publish_folder`, `run_git`. Their hashes changed. Their own code did not change. |

The dexweb numbers come from one small package with one author. Do not make general conclusions from them.

**Self-analysis.** Algobank analyzed `pkgmerkle.py` alone:

- It has 50 nodes.
- It has no scope.
- It has no `TOP`.
- Repeated runs give the same hashes.
- A one-line change to `H()` changes `H`. It also changes the 8 nodes that call `H` directly or indirectly. The other 41 nodes keep their hashes.

### 10.4 Proof of the code root

`v0.1/proofs/CodeRoot.v` models `Package.leaves()` and `Package.root()` in Coq 8.18. It proves these theorems:

| Theorem | Statement |
|---|---|
| `code_root_binding` | Two well-formed packages can have the same code root. Then they contain the same (node id, Merkle hash) pairs. |
| `code_root_canonical` | A different order of the nodes of a package gives the same code root. |
| `code_root_correct` | For well-formed packages, the code roots are equal exactly when the sets of pairs are equal. |
| `dup_collision` | Without unique leaves, binding fails. `[a, b, c]` and `[a, b, c, c]` reduce to the same root. |

A package is well formed when these conditions are true:

- It has no repeated pair.
- Each Merkle hash is a 64-character digest.

`pkgmerkle.py` makes both conditions true. Node ids are dictionary keys. Merkle hashes are outputs of `H`.

**Assumptions.** The proof has the hash and the sort as parameters. It uses these hypotheses:

1. `H` returns 64 characters. `H` is injective. Injectivity is an ideal form of the collision resistance of SHA-256.
2. The sort returns a permutation of its input. The sort returns the same output for inputs that are permutations of each other. The `sorted` function of Python on strings does both.

`Print Assumptions code_root_correct` reports no axioms in addition to these hypotheses. The trusted base has two items:

- the Coq kernel;
- the correspondence between the model and the Python code.

**Model check.** `check_model.py` tests the second item. It extracts the proven `code_root` to OCaml. It compares that code with `Package.root()` on 5,000 random packages of 0 to 80 nodes. Both sides use the same stand-in hash. All 5,000 roots are the same.

Two intentional changes to the Python code were tested:

- an odd last leaf paired with nothing;
- leaves that are not sorted.

Each change gives mismatches on more than half of the cases. Thus the check finds divergence.

### 10.5 Proof of Merkle soundness

`v0.1/proofs/MerkleSound.v` models the output of the back end as a graph with components. It proves these theorems in Coq 8.18:

| Theorem | Statement |
|---|---|
| `merkle_sound` | Node `n1` in one analysis and node `n2` in a different analysis can have the same Merkle hash. Then each node that `n1` can reach has a counterpart that `n2` can reach. The counterpart has the same Merkle hash. |
| `merkle_sound_content` | The counterpart also has the same own hash. Its component has the same pins. |
| `merkle_sound_back` | The same is true in the other direction. |

The theorems are true for each output that meets the conditions of the checker (section 3.8). The proof states these conditions as the record `WF`. Each field of `WF` is one check in `check_backend`.

**Assumptions.** `H` returns 64 lowercase hex characters. `H` is injective. The sort returns a permutation of its input. `Print Assumptions merkle_sound_content` reports no axioms in addition to these hypotheses.

**What the proof needed.** The first encoding joined raw pin strings with `|`. A version specifier can contain `|`. Then two different pin lists can have the same encoding. Thus the proof failed. Now Algobank hashes each pin before the join.

**Validation.**

| Check | Result |
|---|---|
| One test for each checker condition. Each test confirms the specific failure. | Each condition rejects an output that is broken on purpose. For the two structural conditions, the test first computes the Merkle hashes again. Thus only the condition under test can fail. |
| The theorem on real data: each pair of nodes with the same Merkle hash across consecutive dexweb releases | 24 updates. 527 pairs. Each node that can be reached has a match. |
| The checker on each analysis: the test suite, the synthetic package, the self-analysis and all 25 dexweb releases | Accepted |

**Gap between proof and code.** The proof covers the conditions. `check_backend` is Python. The per-condition tests show that it matches `WF`. No proof shows this. The front end is outside the proof. This includes normalization and own hashes.

### 10.6 Diff tool

The diff tool is the first product on the core. Its command is `algobank`. A developer or coding agent adds or updates a dependency. The tool then answers two questions about the Python package:

- What changed?
- What can the package do now?

```
algobank diff OLD NEW [--json] [--ignore-native]
algobank scope FILE [FILE ...] [--json] [--ignore-native]
```

`OLD`, `NEW` and `FILE` are paths to wheel or sdist files. The tool reads each file in memory. It installs nothing from the package. It imports nothing from the package. It runs nothing from the package.

**Scope of the tool.** Algobank has no network access. It writes no files. Its only power is to read the files that it gets. The package manager downloads the files. The package manager has network access wherever packages can be installed:

```
pip download --only-binary :all: -d wheels/ NAME==VERSION     # the whole closure; add --no-deps for one package
algobank scope wheels/<file>.whl                              # for each wheel
pip install --no-index --find-links wheels/ NAME==VERSION     # installs exactly the files analyzed
```

`--only-binary :all:` is important. To read the metadata of an sdist, pip runs its build backend. Thus pip executes package code during the download. Algobank cannot see that code. Thus each sdist is a high finding.

**Findings.**

| Finding | Severity |
|---|---|
| A new file that runs at each Python start (`.pth`, `sitecustomize.py`) | high |
| The package can now use `network`, `process`, `env`, `native` or `TOP`. It could not before. | high |
| Existing code can now reach such a scope. The finding names where the scope comes in. | high |
| New `eval`, `exec` or deserialization. New run-time changes to a different module. | high |
| A native binary: new or changed in `diff`, any in `scope`. The text is "native binary detected. not checked". | high. With `--ignore-native`, the finding stays in the report. It is marked ignored. It does not change the exit status. |
| A new dependency. This includes test-only and optional dependencies. Algobank does not analyze its code here. Thus its scope is unknown (`TOP`). | high |
| A source distribution. Its build runs the build backend and any `setup.py` (`TOP`). | high, in `scope` and in `diff` |
| New `file` scope. Other new dynamic code: computed imports and attributes, `__getattr__`, `import *`. A new entry point or installed script. | medium |
| A changed dependency range. New or changed data files. | low |

**Called packages.** Each package that a package calls must be algobanked too. These are the `Requires-Dist` dependencies in its metadata. This is a soft condition:

- A called package that was not algobanked in the same run is a `warning`.
- Algobank always reports a warning.
- A warning never changes the exit status.

To algobank a full closure in one run, give `scope` each file of the closure. `pip download` without `--no-deps` gives the closure.

The severities, from the top, are `high`, `warning`, `medium`, `low` and `info`.

In `diff`, a new dependency stays high. A release that changes what it pulls in is a change to review. This is true if the dependency is algobanked or not.

**Native binaries.** Algobank analyzes Python source. It cannot see what compiled code does.

- A wheel with binaries gets `native` in its scope.
- It gets the high finding "native binary detected. not checked". The finding names each binary.
- Algobank records each binary by hash.
- Other methods must check the binaries. Examples are a reproducible build from source or a native-code result (section 6).

This does not stop algobanking. Algobank keeps the report with the binaries flagged. Use `--ignore-native` when you check the binaries separately. The finding stays in the report. It is marked ignored. The run passes.

**Exit status.**

- 1: at least one finding is high.
- 0: no finding is high.
- 2: an error occurred.

Thus the tool can gate a CI job. `--json` gives the same report for programs and agents. The report also tells what it could not see: unparsed files and native binaries.

**Known data.** Each release of Algobank ships `algobank/known.json`. `v0.1/build_cache.py` builds it. It holds the published advisory records for the 1,000 most downloaded PyPI packages. The records are in OSV format. They are not changed. Algobank needs no network for them at run time. They come through the package manager, like any package.

The file contains:

- malicious-package reports from OpenSSF (`ossf/malicious-packages`, `MAL-` identifiers). Some reports publish the SHA-256 digests of the malicious files. These digests are included. Examples are the `.pth` and `sitecustomize.py` files of litellm 1.107.0.
- known vulnerabilities from PyPA (`pypa/advisory-database`, `PYSEC-` identifiers).

Rules:

1. **Records are data. The code decides.** Algobank ships the records as published. `algobank/diff.py` decides on the machine of the user if a record applies. A record applies to a version in its list. A record also applies to a version in one of its ranges. Algobank compares versions with PEP 440 order. A codegen can read the records. It can also read the code. Algobank trusts nothing that was interpreted elsewhere.
2. **Algobank never matches a withdrawn advisory.** Its publisher retracted it. Thus the versions that it named must pass. The record stays in `known.json`. Records are only added.
3. **A match is a high finding.** The finding names the advisory identifier. It points to `known.json`. The result of the analysis does not change this.
   - Sometimes a version cannot be compared with a range. Then the advisory can apply. Thus Algobank reports it.
   - Algobank checks each file in the archive against the published malicious-file digests. Thus Algobank also catches a repackaged copy.
   - Some advisories have two identifiers: a `MAL-` record and its `PYSEC-` alias. Algobank ships such an advisory once.
4. **Algobank keeps catches. It never stores passes** (principle 9). Records are only added. They are never removed. Algobank ships no report or verdict about any package. Algobank analyzes each file each time it checks the file.
5. **Each result tells the age of the data.** It gives the date of the data. It gives the sources. A report after that date is missing until Algobank is updated. Thus the release cadence of Algobank is the update cadence of the known data.

**Validation.**

| Check | Result |
|---|---|
| Synthetic wheels that copy attack patterns. A `.pth` file with a module that reads the environment and uses the network (LiteLLM 1.107.0). An existing formatting function that starts to use the network (chalk/debug). New `exec`. A new native binary. A new dependency. | Each gives the expected high or medium finding (`test_diff.py`). |
| A clean update of the same synthetic package. A dependency range that changes only in format. | No findings |
| A new test-only dependency (`setuptools ; extra == 'testing'`) | High. Optional dependencies also bring code that is not analyzed. |
| The wheel of Algobank (`algobank scope dist/algobank-1.0.0-py3-none-any.whl`) | `file`, in `load` and `known`. `load` reads the one file that it gets. `known` reads `known.json`. No network. No other findings. |
| The sdist of Algobank | High. Its build runs `flit_core`. |
| Normal updates of popular packages: requests 2.31.0→2.32.3, urllib3 2.2.1→2.2.2, idna 3.6→3.7, rich 13.7.0→13.7.1, packaging 24.0→24.1 | Four have no medium or high findings. requests has one real change, flagged high: a new computed import. It runs at import time. It selects a character-detection library. |
| dexweb 4.2.2→4.2.3 | `process` is reported as new. It comes in at `Dexweb.run_git`. |

**Reuse on real updates.** This is the share of nodes whose hash did not change:

| Update | Unchanged nodes |
|---|---|
| rich 13.7.0→13.7.1 | 69% |
| requests 2.31.0→2.32.3 | 68% |
| urllib3 2.2.1→2.2.2 | 62% |
| idna 3.6→3.7 | 75% |
| packaging 24.0→24.1 | 38% |

An earlier design made each function depend on all top-level code of its module. With that design, rich kept 6%. requests kept 1%.

PyPI removed the known malicious releases of LiteLLM (1.82.7, 1.82.8, 1.107.0). Thus a direct test with them was not possible.

### 10.7 Running

Requirements: Python 3.14, standard library only. The proof also needs Coq 8.18. The model check also needs OCaml with `ocamlfind`.

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

Algobank parses the wheels. It never runs them.

```
# install from the repository and run the diff tool
pip install .
pip download --no-deps --only-binary :all: -d wheels/ requests==2.31.0
pip download --no-deps --only-binary :all: -d wheels/ requests==2.32.3
algobank diff wheels/requests-2.31.0-py3-none-any.whl wheels/requests-2.32.3-py3-none-any.whl

# diff tool tests
python3.14 -I v0.1/test_diff.py

# check the proofs
cd v0.1/proofs && coqc -Q . Algobank CodeRoot.v && coqc -Q . Algobank MerkleSound.v

# compare the proven model with pkgmerkle.py (builds in a temporary directory)
python3.14 -I v0.1/proofs/check_model.py
```

### 10.8 Release

`uv build` (or `python -m build`) makes two files:

- `dist/algobank-1.0.0-py3-none-any.whl`
- `dist/algobank-1.0.0.tar.gz`

Both files contain only the `algobank` package, `LICENSE`, `README.md` and metadata. They do not contain tests, proofs, documents or `CLAUDE.md`. `twine check dist/*` passes.

The maintainer uploads the files manually with the maintainer's own PyPI credentials. The repository contains no credentials. The code reads no environment variables.

### 10.9 Website and branches

The repository is the full company. Each branch has one role:

| Branch | Holds | Served |
|---|---|---|
| `main` | The core index: the library (`algobank/`), documents, tests and proofs. Also the source of the website in `site/`. | No |
| `web` | The generated website only | At matrixdex.github.io/algobank, by GitHub Pages |
| `live` | The live state: the current known advisories and the bank of algobanked versions, as records | Read as files |

Each website is a dex. dexweb builds it. `python run.py` in `site/` writes the website to `site/gen/`. dexweb publishes it to `web`.

**The index is the bank.** Its title is "algobank Algorithm Bank". At each build, `run.py` renders `bank.jsonl` from `live` into the index template in `site/config.json`. The index has these items:

- A search bar. It takes `package` or `package v1.2.3`. A link can carry `?q=`.
- A message for a version that is not in the bank: `package v1.2.3 are not algobanked`. The admitted versions of the package show below it.
- The records as a table. On wide screens (1,045 pixels and wider), each field has its own column. On narrower screens, the table shows the package and its findings. A click on an entry opens all of its fields below it.
- Each hash as its first eight characters. A button copies the full hash.
- Buttons that export the bank as JSONL or CSV. The JSONL is the file without changes. The CSV has one column for each field.
- The lines of the file without changes, in a `<script type='application/x-ndjson' id='bank.jsonl'>` block for codegens.

A short script in `config.json` (`index_javascript`) does the search and the exports. It loads nothing from elsewhere.

**Known Exploits and Vulnerabilities** is a magazine for codegens. At each build, `run.py` renders it from `known.json` and `bank.jsonl` on `live`. It has these items:

- A search bar.
- A line with the date of the data. The line also shows the number of packages, advisories and open slots.
- Malicious releases and vulnerabilities, newest first. Each entry shows its identifier, package, fixed-in version and the summary of the record. On narrow screens, a click opens the details.
- Open slots. A slot is a package with advisories and no admitted version. Each slot shows the latest fixed version.
- Withdrawn advisories have a label. They do not open slots.
- Export as JSONL or CSV. The index is also in a `<script type='application/x-ndjson' id='known.jsonl'>` block.

**Limits** tells the one claim of Algobank. A file whose hash is in the bank, under its code root, is algobanked. It is secure to the best of the capabilities of Algobank. The page also tells where Algobank fails. It also gives the CC0 disclaimer.

**The other pages** are in `site/data.json`. The footer of each page links to them. No page sends the reader to a different site. The Architecture page is a static copy of this document. It is rendered to HTML once and kept in `data.json`. It changes only when someone updates it there.

**Styles.** `site/styles.css` lays out the pages like a GitHub README:

- The original dex colors: black, light grays, white and green `#00ff41`.
- Severity colors on the Findings page and in the bank: red for high and for `TOP`, yellow for warning and medium, green for low.
- Three fonts only: Arial, monospace and Italiana. Italiana is only for the name algobank. The name is the homepage title and the footer title on every page. All other titles are Arial. The dex serves Italiana from `site/assets/` (SIL Open Font License).
- Lists have no bullets. Only the Findings page marks its items. Each mark is a band in the color of the severity.
- Code blocks never go off the page.
- Each page fits screens of 320 pixels and wider.

**Dependencies.** All dependencies of Algobank are algobanked. They are admitted to the bank (`bank.jsonl` on `live`). Each version is identified by the SHA-256 of its file. Each SHA-256 was checked against the digest that PyPI publishes.

| Version | Used for | Scope | Findings |
|---|---|---|---|
| `algobank` 0.1.0 | Itself. The first algobanked code. | `file` | no high |
| `flit_core` 3.12.0 | The build backend of Algobank. It runs when Algobank is installed from source. | `TOP`, `env`, `file` | no high |
| `dexweb` 4.2.5 | It builds the website. | `file`, `process` | no high |
| `beautifulsoup4` 4.15.0, `cobble` 0.1.4, `importlib_resources` 7.1.0, `mammoth` 1.13.0, `pypdf` 6.21.2, `soupsieve` 3.0.4, `typing_extensions` 4.16.0 | The packages that dexweb calls | From `TOP` only to `TOP`, `env`, `file`, `process` (`pypdf`). `mammoth` uses `network`. | No high. Warnings only for optional extras that the closure does not install. |

One `algobank scope` run checks the full dexweb closure. The website is built only from those files (`pip install --no-index --find-links`). Algobank needs none of these packages at run time. It uses the standard library only.

## 11. Known limitations

| # | Limitation | Effect | Remedy |
|---|---|---|---|
| G1 | A function can change module state by mutation without `global`. Example: it appends to a module-level list. | The hash of a reader does not depend on the mutating function. | Treat functions that mutate module-level objects as writers. Forbid mutable module state in compute parts. |
| G2 | `__getattr__` definitions and `from x import *` are flagged. They do not give `TOP`. | This does not agree with section 4.4. | Add both flags to the `TOP` rule. |
| G3 | The targets of a computed `getattr` are not part of the hash. | A dispatcher can reach changed code. The change does not invalidate the dispatcher. | Reject unbounded dynamic code at admission. Alternatively, require an explicit list of targets as part of the hash. |
| G4 | Literal imports of outside modules through `import_module` add no scope. | The reported scope is too small. | Map literal imports through the scope table. |
| G5 | The scope table is short. It is for Python only. Some entries match by method name. | Libraries that are not in the table are missed. | A maintained table from API to scope for each language. |
| G6 | The analyzer cannot see compiled code. | The native scope is unknown. | The native tier with confinement and native-code evidence (section 5.7). |
| G7 | Method calls that do not go through imports link to each package method with that name. | Over-approximation. It is sound but it costs work. In rich 13.7.0→13.7.1, 789 nodes changed hash through dependencies. Only 3 changed their code. | Accepted under principle 7. Rechecks cost CPU. Narrowing adds complexity. Sound narrowing also helps little. Parameters and attributes are the main source. A library cannot narrow them. Any caller can give any object. |
| G8 | Code roots have no inclusion proofs. | A single node cannot be proven without the full list of leaves. | Merkle audit paths over the sorted leaves. |
| G10 | Some dynamic behavior is outside the listed patterns. Example: functions kept in dictionaries and called by key. | Not detected. | Runtime enforcement. |
| G11 | Hashes depend on the `ast.dump` format of the interpreter. | A different Python version can give a different root. | Record the version with each root. Test roots across versions. Move to a serialization that does not depend on the version. |
| G12 | Introspection through dunder attributes or frames can reach effectful functions without imports. | Algobank reports such code with no scope. This is a soundness gap. | Treat introspection as `TOP`. Use the allowlist for compute parts (section 4.5). Enforce at the boundary. |
| G13 | No detection of `clock` or `entropy`. | Code that is not deterministic can look pure. | Add both scopes to the detection table. |
| G15 | Algobanking checks code before it runs. Code can be replaced in memory at run time. Another package can assign `clean_lib.fn = evil`. It can put a different module in `sys.modules`. It can add an import hook. Then callers of an algobanked library run code that was never algobanked. | A clean result does not prove what runs. In an algobanked package, such patching is flagged `TOP`. From a package outside the analysis, it is not visible. | Algobank each package in the dependency closure. At run time, verify that loaded functions still match their algobanked hashes. Section 5 covers enforcement. |

## 12. Roadmap (v0.2)

1. Close the soundness gap G12. Close G2 and G3. Then `TOP` is complete.
2. Add detection of `clock` and `entropy` (G13). Add a scope report for each module.
3. Add inclusion proofs (G8). Record the interpreter version with each root (G11).
4. Implement the scope manifest. Implement the check of declared against detected scope.
5. Build the native-tier runner. It makes a profile from the declared scope. It applies a system-call allowlist. It checks itself. It fails closed. It records the profile digest.
6. Start a minimal transparency log in the C2SP formats. Its first admission is the code root of the analyzer.
7. Implement the admission gates as code.
8. Run the release-history test on larger packages with many contributors.
9. Evaluate the component tier for pure-Python parts with `componentize-py`.
10. Take the diff tool to users:
    - a GitHub Action that comments on pull requests that change `requirements.txt`, `uv.lock` or `poetry.lock`;
    - an MCP server for coding agents. It takes file paths. Like the command, it has no network access. It writes no files.

    Both are necessary before the diff tool ships to agents. The MCP server must be algobanked before it ships. Its full dependency closure must also be algobanked. Measure how frequently a finding causes a change in a dependency or in the code.
11. Continue to prove the core on the split of front end, back end and checker (section 3.8):
    1. Roll-up soundness and `TOP` propagation. Add the matching conditions to the checker.
    2. Reuse soundness. A result accepted for a hash stays valid wherever that hash occurs.
    3. The rule for result acceptance (section 6.2).
12. Define the format of a proof result. Record each core proof in it.

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
