"""Sign an agent package for the dashboard's update channel (eagleeye/update).

    python packaging/sign_package.py windows dist/EagleEyeAgent-Setup-0.1.0.exe <build>
    python packaging/sign_package.py source  dist/eagleeye-agent-0.1.0.tar.gz   <build>

Writes <package>.manifest.json next to it: the file name, build, size and SHA-256, signed with the
project's Ed25519 key. Upload both (AGENT_SETUP_GUIDE.md, "Publishing a new version"); agents refuse
a package whose manifest is missing or not signed with a key in eagleeye/update/keys.py.

The private key stays on the build machine: %USERPROFILE%\\.eagleeye-signing\\agent-ed25519.pem (or
EAGLEEYE_SIGNING_KEY). Keep a backup somewhere safe and offline; losing it means shipping a build that
trusts a new key, and leaking it lets anyone push a program to every agent.
"""

from __future__ import annotations

import base64
import hashlib
import json
import os
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
from eagleeye.update import ed25519  # noqa: E402
from eagleeye.update.keys import PUBLIC_KEYS  # noqa: E402
from eagleeye.update.package import FORMAT, KINDS, build_time, signed_message  # noqa: E402


def key_path() -> Path:
    env = os.environ.get("EAGLEEYE_SIGNING_KEY")
    return Path(env) if env else Path.home() / ".eagleeye-signing" / "agent-ed25519.pem"


def main(argv: list[str]) -> int:
    if len(argv) != 3 or argv[0] not in KINDS:
        print(__doc__)
        return 2
    kind, file, build = argv[0], Path(argv[1]), argv[2]
    if build_time(build) is None:
        print(f"Not a release build stamp: {build!r}")
        return 2
    from cryptography.hazmat.primitives import serialization as s
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    key = s.load_pem_private_key(key_path().read_bytes(), password=None)
    if not isinstance(key, Ed25519PrivateKey):
        print("The signing key is not an Ed25519 key")
        return 2
    public = base64.b64encode(key.public_key().public_bytes(s.Encoding.Raw, s.PublicFormat.Raw)).decode()
    key_id = next((k for k, v in PUBLIC_KEYS.items() if v == public), None)
    if key_id is None:
        print("This signing key is not one the agent trusts (eagleeye/update/keys.py)")
        return 2
    data = file.read_bytes()
    sha, size = hashlib.sha256(data).hexdigest(), len(data)
    message = signed_message(kind, file.name, build, sha, size)
    signature = key.sign(message)
    assert ed25519.verify(base64.b64decode(public), message, signature)      # the agent's own check
    manifest = {"format": FORMAT, "kind": kind, "file": file.name, "build": build, "sha256": sha, "size": size,
                "key": key_id, "signature": base64.b64encode(signature).decode()}
    out = file.with_name(file.name + ".manifest.json")
    out.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    print(f"{out} ({kind}, build {build}, {size / 2**20:.1f} MB)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
