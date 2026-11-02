# PyInstaller spec: one folder with a windowed SimplySec.exe and a console simplysec-cli.exe.
# Build with scripts/build.ps1. Manifest is asInvoker (no uac_admin): read-only scans work for
# standard users and SimplySec elevates on demand.
# -*- mode: python ; coding: utf-8 -*-
import sys
from pathlib import Path

from PyInstaller.utils.win32.versioninfo import (
    FixedFileInfo, StringFileInfo, StringStruct, StringTable, VarFileInfo, VarStruct, VSVersionInfo,
)

ROOT = Path(SPECPATH).parent
SRC = ROOT / "src"
sys.path.insert(0, str(SRC))
import simplysec  # noqa: E402

VERSION = simplysec.__version__
parts = tuple(int(x) for x in VERSION.split(".")) + (0,) * (4 - len(VERSION.split(".")))
PKG = SRC / "simplysec"
ICON = str(PKG / "resources" / "simplysec.ico")

datas = [
    (str(PKG / "core" / "knowledge" / "*.toml"), "simplysec/core/knowledge"),
    (str(PKG / "windows" / "scripts" / "*.ps1"), "simplysec/windows/scripts"),
    (str(PKG / "core" / "report" / "templates" / "*.j2"), "simplysec/core/report/templates"),
    (str(PKG / "resources" / "oui.csv.gz"), "simplysec/resources"),
    (str(PKG / "resources" / "simplysec.ico"), "simplysec/resources"),
]
hidden = ["win32com.shell.shell", "win32timezone", "win32security", "win32service", "win32net", "pythoncom"]
excludes = ["tkinter", "PySide6.QtWebEngineCore", "PySide6.QtQml", "PySide6.QtQuick", "PySide6.QtNetwork"]


def version_info(name, description):
    return VSVersionInfo(
        ffi=FixedFileInfo(filevers=parts[:4], prodvers=parts[:4]),
        kids=[
            StringFileInfo([
                StringTable("040904B0", [
                    StringStruct("CompanyName", "SimplySec"),
                    StringStruct("FileDescription", description),
                    StringStruct("FileVersion", VERSION),
                    StringStruct("InternalName", name),
                    StringStruct("OriginalFilename", f"{name}.exe"),
                    StringStruct("ProductName", "SimplySec"),
                    StringStruct("ProductVersion", VERSION),
                    StringStruct("LegalCopyright", "MIT License"),
                ])
            ]),
            VarFileInfo([VarStruct("Translation", [1033, 1200])]),
        ],
    )


def analysis(script):
    return Analysis(
        [str(Path(SPECPATH) / script)],
        pathex=[str(SRC)],
        datas=datas,
        hiddenimports=hidden,
        excludes=excludes,
        noarchive=False,
    )


a_gui = analysis("gui_entry.py")
a_cli = analysis("cli_entry.py")
pyz_gui = PYZ(a_gui.pure)
pyz_cli = PYZ(a_cli.pure)

exe_gui = EXE(
    pyz_gui, a_gui.scripts, [],
    exclude_binaries=True, name="SimplySec", console=False, icon=ICON,
    version=version_info("SimplySec", "SimplySec security checks"), uac_admin=False,
)
exe_cli = EXE(
    pyz_cli, a_cli.scripts, [],
    exclude_binaries=True, name="simplysec-cli", console=True, icon=ICON,
    version=version_info("simplysec-cli", "SimplySec command line"), uac_admin=False,
)
coll = COLLECT(
    exe_gui, a_gui.binaries, a_gui.datas,
    exe_cli, a_cli.binaries, a_cli.datas,
    strip=False, upx=False, name="SimplySec",
)
