"""The keys an update package must be signed with (Ed25519, raw public key, base64).

The private key never leaves the build machine (packaging/sign_package.py reads it from
%USERPROFILE%\\.eagleeye-signing). A package signed with any other key is refused. To replace the
key, ship a build that lists both, then one that lists only the new one.
"""

PUBLIC_KEYS: dict[str, str] = {
    "umeagleeye-2026-11": "QJUj4uIoI/Abc9dhFxn69OKi+eiwaPIosIA24zgUymg=",
}
