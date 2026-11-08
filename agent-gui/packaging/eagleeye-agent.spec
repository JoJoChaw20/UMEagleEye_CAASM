# PyInstaller spec: one folder with two programs sharing the same libraries.
#   EagleEyeAgent.exe  the desktop app (no console window)
#   eagleeye.exe       the command line (check-deps, inventory, run, ...)
# Build with packaging/build.ps1, which runs: pyinstaller packaging/eagleeye-agent.spec
# A one-folder build (not one-file) keeps PySide6 as separate, replaceable DLLs (LGPL).
#
# scapy (GPL-2.0-only) is NOT bundled: passive listening uses the built-in capture and
# decoding (eagleeye/passive/capture.py, decode.py). Set EAGLEEYE_WITH_SCAPY=1 to build
# the old way, with scapy for the Npcap capture; that build ships its own notices.

import os
import shutil
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).parent
ICON = ROOT / "build" / "eagleeye.ico"
WITH_SCAPY = os.environ.get("EAGLEEYE_WITH_SCAPY") == "1"
NOTICES = ROOT / "packaging" / "THIRD-PARTY-NOTICES.txt"
if WITH_SCAPY:   # installed under the same name (a datas destination is a folder, not a file name)
    NOTICES = ROOT / "build" / "notices-scapy" / "THIRD-PARTY-NOTICES.txt"
    NOTICES.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(ROOT / "packaging" / "THIRD-PARTY-NOTICES-scapy.txt", NOTICES)

datas = [
    (str(ROOT / "eagleeye" / "collectors" / "windows_inventory.ps1"), "eagleeye/collectors"),
    (str(NOTICES), "."),
    (str(ROOT / "eagleeye" / "gui" / "assets"), "eagleeye/gui/assets"),   # logo, fonts (OFL)
    (str(ROOT / "eagleeye" / "data" / "ieee_oui.tsv.gz"), "eagleeye/data"),   # MAC vendors (IEEE registry)
]
datas += copy_metadata("keyring")                # keyring finds its backends through package metadata

hiddenimports = (
    collect_submodules("keyring.backends")
    + ["win32ctypes.core", "truststore"]       # truststore: imported inside httpclient.tls_context
)
if WITH_SCAPY:
    hiddenimports += collect_submodules("scapy.layers") + ["scapy.libs.manuf"]   # vendor.py loads it by name

excludes = ["tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore",
            "PySide6.QtMultimedia", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtPdf", "pytest",
            # Test-only dependencies whose licences cannot be combined with scapy (GPL-2.0-only):
            # python-nmap (GPL-3.0) and requests (Apache-2.0, with its helpers). Never bundle them.
            "nmap", "requests", "urllib3", "charset_normalizer", "chardet", "idna", "certifi",
            # Build tooling, not needed at run time; setuptools also vendors Apache-2.0 code.
            "setuptools", "pkg_resources", "_distutils_hack", "wheel",
            # The network agent's AES (netagent/, the `network` extra): it ships as its own package,
            # not in the desktop installer.
            "cryptography", "cffi",
            # SNMP moved to the network agent (its own client); pysnmp is only a test dependency.
            "pysnmp", "pyasn1"]
if not WITH_SCAPY:
    excludes += ["scapy"]


def analysis(script):
    return Analysis(
        [str(ROOT / "packaging" / script)],
        pathex=[str(ROOT)],
        datas=datas,
        hiddenimports=hiddenimports,
        excludes=excludes,
        noarchive=False,
    )


# Qt parts a widgets app never loads, which PySide6's hooks still collect (44 MB of the
# 128 MB folder, measured 2026-11-07; the app starts and uses the same memory without
# them): the software OpenGL renderer, QML/Quick and the virtual keyboard built on it,
# Qt PDF and its image plugin, and Qt's own translations (the app is English).
UNUSED_QT = ("opengl32sw.dll", "qt6pdf.dll", "qt6qml", "qt6quick", "qt6virtualkeyboard", "qpdf.dll",
             "platforminputcontexts/", "pyside6/translations/")


def used(toc):
    """The entries of a TOC (destination name first) that are not in UNUSED_QT."""
    return [entry for entry in toc
            if not any(part in entry[0].lower().replace("\\", "/") for part in UNUSED_QT)]


gui_a = analysis("gui_entry.py")
cli_a = analysis("cli_entry.py")
for a in (gui_a, cli_a):
    a.binaries, a.datas = used(a.binaries), used(a.datas)

gui_exe = EXE(
    PYZ(gui_a.pure), gui_a.scripts, [], exclude_binaries=True,
    name="EagleEyeAgent", console=False, icon=str(ICON) if ICON.exists() else None,
    version=None, uac_admin=False,
)
cli_exe = EXE(
    PYZ(cli_a.pure), cli_a.scripts, [], exclude_binaries=True,
    name="eagleeye", console=True, icon=str(ICON) if ICON.exists() else None,
)

coll = COLLECT(
    gui_exe, gui_a.binaries, gui_a.datas,
    cli_exe, cli_a.binaries, cli_a.datas,
    name="EagleEyeAgent", strip=False, upx=False,
)
