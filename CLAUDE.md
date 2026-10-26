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

## Terms

- **Algobanking**: analyzing a package with Algobank (code Merkle tree, scope, checks). An algobanked package has been analyzed this way.
- **Codegen**: an AI coding agent. Findings are feedback that helps codegens write better code.

## Repository conventions

- Commit as `baz <noorulali78@gmail.com>` and push to `main`.
- The shipped package is `algobank/` only; tests, demos and proofs live in `v0.1/` and are not shipped.
