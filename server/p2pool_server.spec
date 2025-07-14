# -*- mode: python ; coding: utf-8 -*-

# The main entry point for your application.
# This should be 'main.py' as it's the script that starts your Flask app and threads.
block_cipher = None


a = Analysis(
    ['p2pool_server.py'], # <--- Changed to 'main.py' as the primary entry point
    pathex=['.'], # The current directory where your Python files reside
    binaries=[],
    datas=[
        ('icons', 'icons'),
        ('p2pool-dashboard/dist', 'p2pool-dashboard/dist'),
        ('client_data.py', '.'),            # Include app.py
        ('p2pool_data.py', '.'), # Include p2pool_handler.py
    ],
    hiddenimports=[
        'flask',          # Explicitly include Flask
        'psutil',         # Explicitly include psutil
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=[],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='server',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
