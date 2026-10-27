# Algobank live

The live state of [Algobank](https://github.com/matrixdex/algobank): records for codegens to read and check.

- `known.json`: the published advisories (OSV records, unchanged) that Algobank evaluates for the 1,000 most downloaded PyPI packages: malicious releases (OpenSSF, `MAL-`) and known vulnerabilities (PyPA, `PYSEC-`). The same file ships inside each Algobank release; this copy is the newest.
- `bank.jsonl`: the bank, one admitted version per line, by its code root. A version stays admitted until it is deemed insecure. The file is append-only: lines are added, never changed or removed. Algobank is the first line: it has algobanked itself.

These are records, not verdicts to trust: run `algobank scope` on any version yourself.
