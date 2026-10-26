# algobank
Algorithm Bank for composable secure algorithms and software insurance

Algobank gives every function in a Python package a content hash (a code Merkle tree) and shows what the package can do: use files, the network, processes or the environment, load native code, or run dynamic code it cannot see into (`TOP`). Algobanking a package means analyzing it this way.

## Diff tool

Before you or your coding agent add or update a dependency, see what changed and what it can do now:

```
pip install algobank
algobank diff requests 2.31.0 2.32.3
algobank scope requests 2.32.3
```

`algobank diff` downloads both versions from PyPI, checks them against PyPI's SHA-256, and reads them in memory. Nothing from the package is installed, imported or run. It reports, by severity:

- files that run on every Python start (`.pth`, `sitecustomize.py`)
- new powers (network, process, environment, native code, `TOP`) and where they enter
- new `exec`, `eval`, deserialization and other dynamic code
- new native binaries, which it cannot analyze
- new dependencies, whose code it does not analyze, so their scope is unknown

Arguments can also be paths to local wheel or sdist files. Add `--json` for programs and agents. The exit status is 1 when a finding is high, so it can gate CI.

The report is a signal for review, not a guarantee: static analysis can be evaded, and native code is not analyzed.

## More

- [Architecture reference](docs/ARCHITECTURE-v0.1.md)
- [Prototype code, tests and proofs](v0.1/)
