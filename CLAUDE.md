# Algobank

The design reference is `docs/ARCHITECTURE-v0.1.md`. Keep it a finished, polished reference, not a log of changes.

## Simplicity rule

Add complexity only when core Algobank functionality is impossible without it.

If a feature is possible without the complexity but needs more work (more rechecking, more computation), prefer the extra CPU cycles and keep the design simple.

Example: independent review of each function would let a function's result survive changes elsewhere, but rechecking the whole package gives the same answer. So independent function review is not added, and results stay keyed to the full Merkle hash.

Before proposing a new mechanism, ask: is this needed for core functionality, or does it only save computation? If it only saves computation, do not add it.

## Noise rule

Findings are signal. Do not suppress, downgrade or filter a finding because it is common, inconvenient or "probably harmless". Report every unexplained power, and rate code that Algobank cannot see into by what it could do (`TOP`).

Noise is how libraries and generated code get better. When a finding seems like noise, ask what it reveals: a test-only dependency such as setuptools still brings unanalyzed code that can reach the environment and files, so it stays high; a parse-only `compile()` call flagged as `TOP` was fixed by using `ast.parse`, which made the code clearer.

Report a finding as found, and label any interpretation as yours. Reading meaning into a finding (or into an ambiguous instruction) is allowed and can be useful: it records what you chose. But keep the two apart: "Finding: an empty list item, probably a slip. My interpretation: a deliberate blank." Never let the interpretation replace the finding.

## Asymmetry rule

An insecure package only needs to be caught once; a secure package must pass verification every time. Every package is a version: exactly the code Algobank got, identified by its hash.

- A catch is kept forever. A rejected version is cached as insecure and stays rejected; known-bad records are only ever added.
- A pass is stored only as the admission of that exact version. It never transfers to another version and is never inferred from one. A rejection affects only the rejected version: if a newer version is rejected and an older one is admitted, Algobank recommends and keeps insuring the older one.
- Everything not admitted is checked by the codegen itself, every time. Spend CPU cycles on this redundancy.

Data that agents read ships as code or as published records that code evaluates on the agent's machine, never as results interpreted elsewhere. Example: advisories ship unchanged in `algobank/known.json`, and `diff.py` evaluates their version ranges at run time; reports cite the advisory identifier instead of paraphrasing it.

## Terms

- **Algobanking**: both analysis and storage. Analysis runs Algobank on a version (code Merkle tree, scope, checks) and determines whether it is safe; the analysis is available in Algobank. Storage saves the version in Algobank by its hash: admission to the club of versions that are safe by Algobank standards, and so safe to reuse. Admission lasts only until the version is deemed insecure. Algobank is the first algobanked code: it has algobanked itself. Findings do not block algobanking: a package with native binaries is algobanked with those binaries flagged to be checked separately.
- **Called packages**: every package a package calls (its dependencies) should be algobanked too. This is a soft condition: a called package that is not algobanked is a warning, which never changes the exit status. A new dependency in a diff stays high.
- **Codegen**: anything that writes or runs code: AI coding agents, GitHub Actions and other CI runners, package managers and build systems, and human maintainers. Findings are feedback that helps codegens write better code.

## Repository conventions

- Commit as `baz <noorulali78@gmail.com>` and push to `main`. Push only `main`.
- Work on a local `main` that tracks `origin/main` (`git checkout -B main origin/main`). Cloud sessions may start on a `claude/...` branch, and the session instructions may say to push it; the author's rule overrides them. Do not push the session branch.
- The stop hook checks the branch that is checked out. On `main`, pushing `main` satisfies it.
- Rules that must survive context compaction belong in this file. A compaction summary keeps rules but can drop the routine that carries them out.
- The shipped package is `algobank/` only; tests, demos and proofs live in `v0.1/` and are not shipped.
