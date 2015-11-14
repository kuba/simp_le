# -*- mode: python -*-
import os
import pkg_resources
import sys

sys.path.insert(0, '.')
import entrypoints

TMP_ENTRY_POINTS_PATH = os.path.join(workpath, 'entry_points.json')
ENTRY_POINTS = [('entry_points.json', TMP_ENTRY_POINTS_PATH, 'DATA')]
entrypoints.dump_entry_points(
    TMP_ENTRY_POINTS_PATH,
    'cryptography',
)

_CRYPTOGRAPHY_BACKENDS = [
    ep.module_name for ep in pkg_resources.iter_entry_points(
    'cryptography.backends')
]
_HIDDEN_IMPORTS = _CRYPTOGRAPHY_BACKENDS + [
    'cffi',
    'werkzeug.exceptions',
]

block_cipher = None

MAIN = Analysis(
    [os.path.join('..', 'simp_le.py')],
    binaries=None,
    datas=None,
    hiddenimports=_HIDDEN_IMPORTS,
    hookspath=[],
    runtime_hooks=['rthook-entrypoints.py'],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
)

MAIN_PYZ = PYZ(
    MAIN.pure,
    MAIN.zipped_data,
    cipher=block_cipher,
)

MAIN_EXE = EXE(
    MAIN_PYZ,
    MAIN.scripts,
    MAIN.binaries,
    MAIN.zipfiles,
    MAIN.datas,
    ENTRY_POINTS,
    name='simp_le',
    debug=False,
    strip=False,
    upx=True,
    console=True,
)
