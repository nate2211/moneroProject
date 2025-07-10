# -*- mode: python ; coding: utf-8 -*-

# The main entry point for your application.
# This should be 'main.py' as it's the script that starts your Flask app and threads.
block_cipher = None


a = Analysis(
    ['p2pool_server.py'], # <--- Changed to 'main.py' as the primary entry point
    pathex=['.'], # The current directory where your Python files reside
    binaries=[],
    datas=[
        ('templates', 'templates'),
        ('static', 'static'),
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

# This section creates the executable.
# `--onefile` creates a single executable file.
# `console=True` will show a console window for P2Pool output and debugging.
# Change to `console=False` (or use `--windowed` flag) to hide the console.
exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='P2PoolMonitor', # Name of your executable
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True, # Set to True for console output (recommended for P2Pool logs)
    disable_windowed_traceback=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    cipher=block_cipher,
    version=None,
)
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
