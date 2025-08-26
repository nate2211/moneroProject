# -*- mode: python ; coding: utf-8 -*-
import os
import ast
from PyInstaller.utils.hooks import collect_all

# --- Script to automatically find all imports ---
def get_imports_from_file(filepath):
    """
    Parses a Python file and returns a set of full imported module paths.
    e.g., 'from PyQt5.QtCore import QTimer' -> 'PyQt5.QtCore'
    e.g., 'import scapy.all' -> 'scapy.all'
    """
    imports = set()
    try:
        with open(filepath, 'r', encoding='utf-8') as f:
            tree = ast.parse(f.read(), filename=filepath)
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    # Add the full module name, e.g., 'scapy.all'
                    imports.add(alias.name)
            elif isinstance(node, ast.ImportFrom):
                if node.module:
                    # Add the module from the 'from' statement, e.g., 'scapy.all'
                    imports.add(node.module)
    except Exception as e:
        print(f"Warning: Could not parse {filepath} for imports. Error: {e}")
    return imports

# List of all data files to be included.
datas_list = [
    ('icons', 'icons'),
    ('tools', 'tools'),
    ('../client/tools/Wireshark', 'tools/Wireshark'),
    ('p2pool-dashboard/dist', 'p2pool-dashboard/dist'),
    ('client_data.py', '.'),
    ('p2pool_data.py', '.'),
    ('p2pool_helper.py', '.'),
    ('p2pool_gui.py', '.'),
    ('p2pool_ai.py', '.'),
    ('p2pool_managers.py', '.'),
    ('p2pool_router_managers.py', '.'),
    ('p2pool_router_managers_2.py', '.'),
    ('p2pool_tools.py', '.'),
    ('p2pool_sniffer.py', '.'),
    ('p2pool_gui_elements.py', '.'),
    ('p2pool_endpoints.py', '.'),
    ('p2pool_hyperv.py', '.'),
    ('p2pool_java.py', '.'),
]

# Identify all Python files to scan for imports.
files_to_scan = ['p2pool_server.py'] + [item[0] for item in datas_list if item[0].endswith('.py')]

# --- Directory switching and import scanning logic ---
original_dir = os.getcwd()
# Assume the 'server' directory is a sibling to the current directory (e.g., '.venv')
server_dir = os.path.abspath(os.path.join(original_dir, '..', 'moneroProject/server'))
all_found_imports = set()

try:
    print(f"Attempting to switch from '{original_dir}' to '{server_dir}' for import scanning.")
    if os.path.isdir(server_dir):
        os.chdir(server_dir)
        print(f"Successfully changed directory to: {os.getcwd()}")
    else:
        print(f"Warning: Server directory not found at '{server_dir}'. Scanning from current directory.")

    # Gather all unique imports from the files.
    for py_file_name in files_to_scan:
        if os.path.exists(py_file_name):
            all_found_imports.update(get_imports_from_file(py_file_name))
        else:
            print(f"Warning: File '{py_file_name}' not found in '{os.getcwd()}', skipping import scan.")
finally:
    # CRITICAL: Change back to the original directory so PyInstaller can function correctly.
    os.chdir(original_dir)
    print(f"Returned to original directory: {os.getcwd()}")
# --- End of directory switching logic ---

scapy_datas, scapy_binaries, scapy_hidden = collect_all('scapy')
block_cipher = None

# Combine automatically found imports with manually specified ones and scapy's hidden imports.
# This ensures critical modules that static analysis might miss are still included.
manual_hiddenimports = [
    'waitress',
    'flask_cors',
    'geoip2.database',
    'playwright.async_api',
    'greenlet',
    'Crypto.Cipher',
    'xml.etree.ElementTree',
    'win32api',
]

# Create the final list of hidden imports, removing duplicates.
final_hiddenimports = list(all_found_imports) + manual_hiddenimports + scapy_hidden

print("-" * 50)
print("Automatically detected and included imports:")
print(sorted(list(all_found_imports)))
print("-" * 50)


a = Analysis(
    ['p2pool_server.py'],
    pathex=['.'],
    binaries=[],
    datas=datas_list, # Use the list defined above
    hiddenimports=final_hiddenimports, # Use the combined list
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
    console=True, # Set to False for a GUI application
    uac_admin=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)