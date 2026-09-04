# -*- mode: python ; coding: utf-8 -*-


a = Analysis(
    ['main.py'],
    pathex=[],
    binaries=[],
    datas=[('trackers.txt', '.')],
    # The updater is imported lazily (About -> Qt & WebEngine…); name its
    # modules so a frozen build still bundles them -- it can at least show the
    # diagnostics report and the "rebuild required" refusal.
    hiddenimports=[
        'updater', 'updater.models', 'updater.versions', 'updater.pypi',
        'updater.compatibility', 'updater.backup', 'updater.manager',
        'updater.apply', 'updater.diagnostics', 'updater_ui',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='Vodou',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=['vodou.ico'],
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='Vodou',
)
