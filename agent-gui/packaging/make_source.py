"""The agent's source package for Linux, macOS (packaging/macos/install-macos.sh) and the network agent: dist/eagleeye-agent-<version>.tar.gz.

Everything a Linux computer needs to run the agent as a service, and to build the network agent's
Docker image (packaging/network-agent), without the tests or the Windows packaging. Published next
to the Windows installer (AGENT_SETUP_GUIDE.md, "Publishing a new version"); the dashboard offers
the newest upload of each.

It carries:
  * the build stamp (eagleeye/_build.py, packaging/buildstamp.py), so the dashboard can tell builds apart;
  * wheels/: the Python libraries the agent needs on Linux (keyring, truststore, cryptography and what
    they need, and setuptools to build the agent), for Python 3.12-3.14 on x86-64 and ARM64, so an
    update from the dashboard installs without PyPI (pip install --no-index --find-links wheels .);
  * and, next to it, a signed manifest for those updates (packaging/sign_package.py).

    python packaging/make_source.py              # from agent-gui/
    python packaging/make_source.py --no-wheels  # smaller, for a quick test copy
"""

from __future__ import annotations

import io
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from eagleeye import VERSION  # noqa: E402
import buildstamp  # noqa: E402

INCLUDE = [
    "eagleeye", "pyproject.toml", "README.md", ".dockerignore",
    "packaging/network-agent", "packaging/eagleeye.service", "packaging/macos", "packaging/THIRD-PARTY-NOTICES.txt",
]
SKIP_PARTS = {"__pycache__", ".pytest_cache"}
SKIP_FILES = {"eagleeye/_build.py"}                      # the stamp is written into the package below
# keyring's Linux-only needs (SecretStorage, jeepney) are named: pip judges markers by the build machine
REQUIREMENTS = ["keyring>=25.0", "truststore>=0.10", "cryptography>=42", "setuptools>=68",
                "SecretStorage>=3.2", "jeepney>=0.4.2"]
PYTHONS = ["3.12", "3.13", "3.14"]
PLATFORMS = {
    "x86_64": ["manylinux_2_28_x86_64", "manylinux_2_17_x86_64", "manylinux2014_x86_64", "musllinux_1_2_x86_64"],
    "aarch64": ["manylinux_2_28_aarch64", "manylinux_2_17_aarch64", "manylinux2014_aarch64", "musllinux_1_2_aarch64"],
}
WHEEL_CACHE = ROOT / "dist" / "wheels-cache"


def wanted(path: Path) -> bool:
    return not (SKIP_PARTS & set(path.parts)) and path.suffix not in (".pyc", ".pyo") and path.as_posix() not in SKIP_FILES


def download_wheels() -> list[Path]:
    """Linux wheels for every Python and machine the agent supports (cached between builds)."""
    WHEEL_CACHE.mkdir(parents=True, exist_ok=True)
    for py in PYTHONS:
        for arch, tags in PLATFORMS.items():
            cmd = [sys.executable, "-m", "pip", "download", "--quiet", "--disable-pip-version-check",
                   "--dest", str(WHEEL_CACHE), "--only-binary=:all:", "--implementation", "cp",
                   "--python-version", py] + [a for t in tags for a in ("--platform", t)] + REQUIREMENTS
            r = subprocess.run(cmd, capture_output=True, text=True)
            if r.returncode != 0:
                raise SystemExit(f"pip download failed for Python {py} {arch}:\n{(r.stdout + r.stderr)[-1500:]}")
    return sorted(WHEEL_CACHE.glob("*.whl"))


def main(argv: list[str]) -> int:
    name = f"eagleeye-agent-{VERSION}"
    out = ROOT / "dist" / f"{name}.tar.gz"
    out.parent.mkdir(exist_ok=True)
    build = buildstamp.stamp()
    wheels = [] if "--no-wheels" in argv else download_wheels()

    def reset(info: tarfile.TarInfo) -> tarfile.TarInfo:     # no build machine's user names in it
        info.uid = info.gid = 0
        info.uname = info.gname = ""
        # Built on Windows the files come out writable by everyone (0666); unpacked as root for a
        # root service, any local user could then change the code it runs. Owner-writable only.
        info.mode = 0o755 if info.isdir() or info.name.endswith(".sh") else 0o644
        return info

    count = 0
    with tarfile.open(out, "w:gz") as tar:
        for item in INCLUDE:
            src = ROOT / item
            files = [src] if src.is_file() else sorted(p for p in src.rglob("*") if p.is_file())
            for f in files:
                rel = f.relative_to(ROOT)
                if wanted(rel):
                    tar.add(f, arcname=f"{name}/{rel.as_posix()}", filter=reset)
                    count += 1
        stamp = buildstamp.module_text(build).encode("utf-8")
        info = reset(tarfile.TarInfo(f"{name}/eagleeye/_build.py"))
        info.size = len(stamp)
        tar.addfile(info, io.BytesIO(stamp))
        count += 1
        for w in wheels:
            tar.add(w, arcname=f"{name}/wheels/{w.name}", filter=reset)
            count += 1
    print(f"{out} (build {build}, {count} files, {len(wheels)} wheels, {out.stat().st_size / 2**20:.1f} MB)")

    r = subprocess.run([sys.executable, str(Path(__file__).with_name("sign_package.py")), "source", str(out), build])
    if r.returncode != 0:
        print("Not signed: agents will not update to this build from the dashboard (a manual install still works).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
