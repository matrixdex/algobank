"""Checks that the Coq model in CodeRoot.v computes the same code root as pkgmerkle.py.

Compiles CodeRoot.v, extracts code_root to OCaml, and compares it with
pkgmerkle.Package.root() on random packages. Both sides use the same stand-in
hash (the MD5 hex digest written twice, 64 characters); the theorems hold for any injective hash.

Usage: python3.14 -I v0.1/proofs/check_model.py [cases]
Needs coqc (Coq 8.18) and ocamlfind/ocamlopt.
"""
import hashlib, os, random, shutil, subprocess, sys, tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import pkgmerkle

def md5_64(s):
    if isinstance(s, str): s = s.encode()
    return hashlib.md5(s).hexdigest() * 2

def build(work):
    for f in ("CodeRoot.v", "Extract.v", "driver.ml"):
        shutil.copy(os.path.join(HERE, f), work)
    run = lambda *cmd: subprocess.run(cmd, cwd=work, check=True, capture_output=True, text=True)
    run("coqc", "-Q", ".", "Algobank", "CodeRoot.v")
    run("coqc", "-Q", ".", "Algobank", "Extract.v")
    run("ocamlfind", "ocamlopt", "coderoot.mli", "coderoot.ml", "driver.ml", "-o", "driver")
    return os.path.join(work, "driver")

def random_package(rng):
    size = rng.choice([0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, rng.randint(0, 80)])
    alphabet = "abcxyz_.:<>0123456789"
    nids = set()
    while len(nids) < size:
        nids.add(rng.choice(["m", "pkg.m", "a.b.c"]) + ":" + "".join(rng.choice(alphabet) for _ in range(rng.randint(1, 10))))
    return {nid: "".join(rng.choice("0123456789abcdef") for _ in range(64)) for nid in nids}

def python_root(nodes):
    p = pkgmerkle.Package.__new__(pkgmerkle.Package)
    p.nodes = {nid: {"merkle": m} for nid, m in nodes.items()}
    return p.root()

def main():
    cases = int(sys.argv[1]) if len(sys.argv) > 1 else 5000
    rng = random.Random(0)
    pkgs = [random_package(rng) for _ in range(cases)]
    pkgmerkle.H = md5_64
    with tempfile.TemporaryDirectory() as work:
        driver = build(work)
        stdin = "".join(" ".join(f"{n} {m}" for n, m in p.items()) + "\n" for p in pkgs)
        out = subprocess.run([driver], input=stdin, capture_output=True, text=True, check=True).stdout.split("\n")
    mismatches = [i for i, p in enumerate(pkgs) if python_root(p) != out[i]]
    sizes = sorted({len(p) for p in pkgs})
    print(f"{cases} packages, sizes {sizes[0]}..{sizes[-1]} ({len(sizes)} distinct), mismatches: {len(mismatches)}")
    sys.exit(1 if mismatches else 0)

if __name__ == "__main__":
    main()
