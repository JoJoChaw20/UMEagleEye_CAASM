# PyInstaller spec: one folder with two programs sharing the same libraries.
#   EagleEyeAgent.exe  the desktop app (no console window)
#   eagleeye.exe       the command line (check-deps, inventory, run, ...)
# Build with packaging/build.ps1, which runs: pyinstaller packaging/eagleeye-agent.spec
# A one-folder build (not one-file) keeps PySide6 as separate, replaceable DLLs (LGPL).

from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules, copy_metadata

ROOT = Path(SPECPATH).parent
ICON = ROOT / "build" / "eagleeye.ico"

datas = [
    (str(ROOT / "eagleeye" / "collectors" / "windows_inventory.ps1"), "eagleeye/collectors"),
    (str(ROOT / "packaging" / "THIRD-PARTY-NOTICES.txt"), "."),
]
datas += collect_data_files("pysnmp")            # MIB modules are loaded from files at run time
datas += copy_metadata("keyring")                # keyring finds its backends through package metadata

hiddenimports = (
    collect_submodules("keyring.backends")
    + collect_submodules("pysnmp.smi.mibs")
    + collect_submodules("scapy.layers")
    + ["win32ctypes.core"]
)

excludes = ["tkinter", "PySide6.QtWebEngineCore", "PySide6.QtWebEngineWidgets", "PySide6.Qt3DCore",
            "PySide6.QtMultimedia", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtPdf", "pytest",
            # Test-only dependencies whose licences cannot be combined with scapy (GPL-2.0-only):
            # python-nmap (GPL-3.0) and requests (Apache-2.0, with its helpers). Never bundle them.
            "nmap", "requests", "urllib3", "charset_normalizer", "chardet", "idna", "certifi",
            # Build tooling, not needed at run time; setuptools also vendors Apache-2.0 code.
            "setuptools", "pkg_resources", "_distutils_hack", "wheel"]


def analysis(script):
    return Analysis(
        [str(ROOT / "packaging" / script)],
        pathex=[str(ROOT)],
        datas=datas,
        hiddenimports=hiddenimports,
        excludes=excludes,
        noarchive=False,
    )


gui_a = analysis("gui_entry.py")
cli_a = analysis("cli_entry.py")

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
