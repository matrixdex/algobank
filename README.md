# algobank
algobank (Algorithm Bank) for composable secure algorithms and software insurance

Algobank gives every function in a Python package a content hash (code Merkle tree) and shows package scope/capability: use files, access network, processes or environment, load native code or run dynamic code it cannot see into (`TOP`). Algobanking a package means analyzing and recording the report in algobank.

Designed for use by codegens (coding agents, human maintainers and bots)

## Diff tool

Before you or your coding agent add or update a dependency, see what changed and what it can do now:

```
pip install algobank
pip download --no-deps --only-binary :all: -d wheels/ requests==2.31.0
pip download --no-deps --only-binary :all: -d wheels/ requests==2.32.3
algobank diff wheels/requests-2.31.0-py3-none-any.whl wheels/requests-2.32.3-py3-none-any.whl
algobank scope wheels/requests-2.32.3-py3-none-any.whl
```

Algobank has no network access and writes no files. It reads only the wheel or sdist files you give it. Nothing from the package is installed, imported or run. Your package manager downloads packages because pip already has network access wherever packages can be installed.

Always use `--only-binary :all:`. Without it, pip may download an sdist and run the sdist's build backend to read its metadata, which executes the package's code before Algobank sees it. Algobank reports any sdist as high for this reason.

To vet a whole dependency closure, leave out `--no-deps`, analyze every downloaded wheel, then install exactly those files: `pip install --no-index --find-links wheels/ NAME==VERSION`.

Give `algobank scope` every downloaded file at once (`algobank scope wheels/*.whl`). Every package a package calls should be algobanked too. A called package missing from the run gets a warning. Warnings don't change exit status.

algobank reports by severity:

- files that run on every Python start (`.pth`, `sitecustomize.py`)
- new powers (network, process, environment, native code, `TOP`) and where they enter
- new `exec`, `eval`, deserialization and other dynamic code
- new native binaries which it cannot analyze
- new dependencies whose code algobank does not analyze, so their scope is unknown

Every result is also checked against the advisories shipped inside algobank (`algobank/known.json`) for the 1,000 most downloaded packages. These are releases reported as malicious (OpenSSF) or as having a known vulnerability (PyPA), and digests of known malicious files checked against every file in the archive. The records are shipped as published, and algobank's own code decides on your machine whether one applies. Each result states the date of that data; update algobank to get newer advisories.

algobank stores no verdicts. Every file is analyzed every time you check it. An insecure package only needs to be caught once; a secure package passes every time.

Add `--json` for programs and agents. The exit status is 1 when a finding is high, so it can gate CI.

## More
- [Live](https://matrixdex.github.io/algobank)
- [Prototype code, tests and proofs](https://github.com/matrixdex/algobank/tree/main/v0.1)
- [Architecture](https://matrixdex.github.io/algobank/architecture.html)
