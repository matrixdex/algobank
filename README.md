# algobank
Algorithm Bank for composable secure algorithms and software insurance

Algobank gives every function in a Python package a content hash (a code Merkle tree) and shows what the package can do: use files, the network, processes or the environment, load native code, or run dynamic code it cannot see into (`TOP`). Algobanking a package means analyzing it this way.

## Diff tool

Before you or your coding agent add or update a dependency, see what changed and what it can do now:

```
pip install algobank
pip download --no-deps --only-binary :all: -d wheels/ requests==2.31.0
pip download --no-deps --only-binary :all: -d wheels/ requests==2.32.3
algobank diff wheels/requests-2.31.0-py3-none-any.whl wheels/requests-2.32.3-py3-none-any.whl
algobank scope wheels/requests-2.32.3-py3-none-any.whl
```

Algobank has no network access and writes no files. It reads only the wheel or sdist files you give it, in memory. Nothing from the package is installed, imported or run. Your package manager does the downloading: pip already has network access wherever packages can be installed.

Use `--only-binary :all:`. Without it, pip may download an sdist, and pip runs an sdist's build backend to read its metadata, which executes the package's code before Algobank sees it. Algobank reports any sdist as high for this reason.

To vet a whole dependency closure, leave out `--no-deps`, analyze every downloaded wheel, then install exactly those files: `pip install --no-index --find-links wheels/ NAME==VERSION`.

It reports, by severity:

- files that run on every Python start (`.pth`, `sitecustomize.py`)
- new powers (network, process, environment, native code, `TOP`) and where they enter
- new `exec`, `eval`, deserialization and other dynamic code
- new native binaries, which it cannot analyze
- new dependencies, whose code it does not analyze, so their scope is unknown

Every result is also checked against the advisories shipped inside Algobank (`algobank/known.json`) for the 1,000 most downloaded packages: releases reported as malicious (OpenSSF) or as having a known vulnerability (PyPA), and the digests of known malicious files, checked against every file in the archive. The records are shipped as published, and Algobank's own code decides on your machine whether one applies. Each result states the date of that data; update Algobank to get newer advisories.

Algobank stores no verdicts: every file is analyzed every time you check it. An insecure package only needs to be caught once; a secure package passes every time.

Add `--json` for programs and agents. The exit status is 1 when a finding is high, so it can gate CI.

The report is a signal for review, not a guarantee: static analysis can be evaded, and native code is not analyzed.

## More

- [Architecture reference](docs/ARCHITECTURE-v0.1.md)
- [Prototype code, tests and proofs](v0.1/)
