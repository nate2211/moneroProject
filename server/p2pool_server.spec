# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['p2pool_server.py'],
    pathex=['.'],
    binaries=[],
    datas=[
        ('icons', 'icons'),
        ('tools', 'tools'),
        ('../client/tools/Wireshark', 'tools/Wireshark'),
        ('p2pool-dashboard/dist', 'p2pool-dashboard/dist'),
        ('client_data.py', '.'),
        ('p2pool_data.py', '.'),
        ('p2pool_helper.py', '.'),
        ('p2pool_gui.py', '.'),
        ('p2pool_ai.py', '.'),
        ('p2pool_router_managers.py', '.'),
        ('p2pool_router_managers_2.py', '.'),
        ('p2pool_tools.py', '.'),
        ('p2pool_sniffer.py', '.'),
        ('p2pool_gui_elements.py', '.'),
        ('p2pool_endpoints.py', '.'),
    ],
    hiddenimports=[
        'flask',
        'psutil',
        'waitress', # Added waitress as it's used to serve the Flask app
        'flask_cors', # Added Flask-Cors
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
    console=False, # Set to False for a GUI application
    uac_admin=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
