"""Build algobank's wheel and sdist so that anyone can build the same files again. Not shipped.

  python3.14 -m venv .venv && . .venv/bin/activate
  pip install --require-hashes -r build-requirements.txt      # flit_core 3.12.0, the admitted file only
  python v0.1/release.py                                       # writes dist/ and prints the SHA-256 of each file

The build is reproducible: all file times come from the commit (SOURCE_DATE_EPOCH), and flit_core sets the
file permissions and owners. A second build of the same commit, on any machine, gives the same SHA-256.
The script refuses a working tree with uncommitted changes, and a build backend other than the pinned one.
"""
import hashlib, os, shutil, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PINNED = "3.12.0"

def git(*args):
    return subprocess.run(["git", "-C", ROOT, *args], capture_output=True, text=True, check=True).stdout.strip()

def main():
    if git("status", "--porcelain", "--untracked-files=no"):
        sys.exit("error: the working tree has uncommitted changes; commit them first")
    import flit_core
    if flit_core.__version__ != PINNED:
        sys.exit(f"error: flit_core {flit_core.__version__} is installed; the build needs {PINNED} "
                 "(pip install --require-hashes -r build-requirements.txt)")
    from flit_core import buildapi
    os.environ["SOURCE_DATE_EPOCH"] = git("log", "-1", "--format=%ct")
    dist = os.path.join(ROOT, "dist")
    shutil.rmtree(dist, ignore_errors=True)
    os.makedirs(dist)
    os.chdir(ROOT)
    files = [buildapi.build_wheel(dist), buildapi.build_sdist(dist)]
    print(f"commit {git('rev-parse', 'HEAD')}  SOURCE_DATE_EPOCH {os.environ['SOURCE_DATE_EPOCH']}")
    for f in files:
        with open(os.path.join(dist, f), "rb") as fh:
            print(f"{hashlib.sha256(fh.read()).hexdigest()}  dist/{f}")

if __name__ == "__main__":
    main()
