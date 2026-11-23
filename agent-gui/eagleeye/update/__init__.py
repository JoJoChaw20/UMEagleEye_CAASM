"""Agent updates started from the dashboard (an `update` job).

  package.py   what makes a package acceptable: a manifest signed with the project's Ed25519 key
               (keys.py), the right kind, a newer build, the signed size and SHA-256
  ed25519.py   the signature check, in pure Python
  install.py   download, check and install it (Windows installer; Linux new folder + switch with
               rollback), and report how it went
"""
