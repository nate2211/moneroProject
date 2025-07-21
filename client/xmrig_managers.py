import ctypes
import asyncio
import ctypes
import ctypes.wintypes as wt
import re
import tempfile
import time
import urllib

import psutil
from typing import Optional, Union, AnyStr
import os
import subprocess
import sys

from threading import Thread, Event


from cpuinfo import cpuinfo


class AsyncLinuxManager:
    """
    An asynchronous manager for executing commands within the
    Windows Subsystem for Linux (WSL). It handles checking for,
    installing, and repairing the WSL installation.
    """

    def __init__(self, logger):
        """
        Initializes the manager with a logger instance.

        Args:
            logger: An object with a `log_message(str)` method.
        """
        self.logger = logger
        self.wsl_path = self._find_wsl_executable()
        self.is_initialized = False

    async def initialize(self):
        """
        Ensures WSL is installed and functional. If not, it attempts to install or repair it.
        This must be awaited before using run_command.
        """
        self.logger.log_message("🚀 Initializing AsyncLinuxManager...")

        if not self.wsl_path:
            self.logger.log_message("⚠️ WSL executable not found. Attempting installation...")
            install_success = await self._install_wsl()
            if install_success:
                self.logger.log_message(
                    "   -> WSL installation process started. Please restart your computer to complete the setup.")
            else:
                self.logger.log_message("❌ WSL installation failed. Please install it manually.")
            self.is_initialized = False
            return

        # If wsl.exe exists, perform a functional check
        self.logger.log_message("   - WSL executable found. Performing functional check...")
        is_functional = await self._check_wsl_functionality()

        if is_functional:
            self.logger.log_message("✅ WSL is already installed and functional.")
            self.is_initialized = True
        else:
            self.logger.log_message(
                "⚠️ WSL functional check failed. The installation may be corrupt. Attempting re-installation...")
            reinstall_success = await self._install_wsl()
            if reinstall_success:
                self.logger.log_message("   -> WSL re-installation process started. A system restart is required.")
            else:
                self.logger.log_message("❌ WSL re-installation failed.")
            self.is_initialized = False

    def _find_wsl_executable(self):
        """Finds the full path to wsl.exe."""
        wsl_path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe")
        if os.path.exists(wsl_path):
            return wsl_path
        return None

    def _is_admin(self):
        """Checks for administrator privileges (Windows only)."""
        try:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    async def _check_wsl_functionality(self) -> bool:
        """Runs a simple command to verify that WSL is working correctly."""
        try:
            process = await asyncio.create_subprocess_exec(
                self.wsl_path, "-l", "-v",  # List distributions verbose
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            return process.returncode == 0
        except Exception:
            return False

    async def _install_wsl(self) -> bool:
        """
        Programmatically launches the interactive installer for WSL using the Command Prompt.
        The window will remain open for user configuration.
        Requires administrator privileges.
        """
        if not self._is_admin():
            self.logger.log_message(
                "❌ ERROR: WSL installation requires administrator privileges. Please re-run as admin.")
            return False

        self.logger.log_message("   - Launching the interactive WSL installer in a new Command Prompt window...")

        # Use /k to keep the window open after the command finishes.
        # This allows the user to see the output and complete the Ubuntu setup.
        command = 'start cmd.exe /k "wsl --install"'

        try:
            # Use Popen for a non-blocking call that opens a new window.
            subprocess.Popen(command, shell=True)
            self.logger.log_message(
                "✅ SUCCESS: WSL installation process launched. Please complete the setup in the new window.")
            return True
        except Exception as e:
            self.logger.log_message(f"❌ An unexpected error occurred during WSL installation: {e}")
            return False

    async def run_command(self, command: str, log_output: bool = True) -> tuple[bool, str, str]:
        """
        Executes a command string inside the WSL terminal.
        """
        if not self.is_initialized:
            self.logger.log_message("[!] Cannot run WSL command: Manager not initialized or WSL requires a restart.")
            return False, "", "Manager not initialized"

        full_command = [self.wsl_path, 'bash', '-c', command]

        if log_output:
            self.logger.log_message(f"🐧 Executing in WSL: `{command}`")

        try:
            process = await asyncio.create_subprocess_exec(
                *full_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await process.communicate()
            stdout_str = stdout.decode('utf-8', errors='replace').strip()
            stderr_str = stderr.decode('utf-8', errors='replace').strip()
            success = process.returncode == 0

            if log_output:
                if stdout_str: self.logger.log_message(f"   [stdout]\n{stdout_str}")
                if stderr_str: self.logger.log_message(f"   [stderr]\n{stderr_str}")
                self.logger.log_message(f"   -> Exited with code: {process.returncode}")

            return success, stdout_str, stderr_str
        except Exception as e:
            self.logger.log_message(f"❌ An unexpected error occurred while running WSL command: {e}")
            return False, "", str(e)

    async def close(self):
        """
        Shuts down all running WSL instances to ensure a clean exit.
        """
        if not self.is_initialized:
            return

        self.logger.log_message("⏹️ Shutting down WSL instance...")
        try:
            process = await asyncio.create_subprocess_exec(
                self.wsl_path, "--shutdown",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            await process.wait()
            if process.returncode == 0:
                self.logger.log_message("   - WSL shutdown successful.")
            else:
                _, stderr = await process.communicate()
                self.logger.log_message(
                    f"   - WSL shutdown command failed: {stderr.decode('utf-8', errors='replace').strip()}")
        except Exception as e:
            self.logger.log_message(f"❌ An error occurred during WSL shutdown: {e}")

class AsyncTSharkManager:
    """
    Manages a bundled tshark instance asynchronously for monitoring mining operations.
    It handles the automatic download and installation of the Npcap dependency
    and provides a simplified, powerful method to scan for security threats.

    Requires the application to be run with Administrator privileges.
    """
    NPCAP_URL = "https://nmap.org/npcap/dist/npcap-1.80.exe"
    NPCAP_INSTALLER_FILENAME = "npcap-installer.exe"

    def __init__(self, logger, flask_server_url: str, pool_url: str):
        self.logger = logger
        self.flask_server_url = flask_server_url
        self.pool_url = pool_url
        self.tshark_path = self._get_resource_path(os.path.join("tools", "wireshark", "tshark.exe"))
        self.is_initialized = False
        self._active_captures = {}  # Stores name -> (task, process)
        self._known_hosts = self._get_known_hosts()

    @property
    def is_scanning(self):
        """Returns True if a scan is currently active."""
        return bool(self._active_captures)

    async def initialize(self):
        """
        Asynchronously ensures all dependencies are met. This must be called
        and awaited before starting any captures.
        """
        if not self._is_admin():
            self.logger.log_message("❌ ERROR: TSharkManager requires Administrator privileges.")
            return

        if not os.path.exists(self.tshark_path):
            self.logger.log_message(f"❌ ERROR: Bundled tshark not found at: {self.tshark_path}")
            return

        self.logger.log_message("🚀 Initializing AsyncTSharkManager...")
        if await self._check_npcap_installed():
            self.is_initialized = True
        else:
            if await self._download_and_install_npcap():
                if await self._check_npcap_installed():
                    self.is_initialized = True
                else:
                    self.logger.log_message("❌ ERROR: Npcap installation ran, but the driver is still not functional.")
            else:
                self.is_initialized = False

        if self.is_initialized:
            self.logger.log_message("✅ TSharkManager initialization successful. Ready to capture.")
        else:
            self.logger.log_message("❌ TSharkManager initialization failed.")

    def _is_admin(self):
        try:
            return os.getuid() == 0
        except AttributeError:
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0

    def _get_resource_path(self, relative_path):
        try:
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)

    async def _check_npcap_installed(self):
        self.logger.log_message("   - Checking for functional Npcap driver...")
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tshark_path, "-D",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,creationflags=subprocess.CREATE_NO_WINDOW
            )
            await proc.wait()
            if proc.returncode == 0:
                self.logger.log_message("   - Npcap is already installed and functional.")
                return True
        except (FileNotFoundError, subprocess.CalledProcessError):
            pass
        self.logger.log_message("   - Npcap not found or not functional. Attempting installation.")
        return False

    async def _download_and_install_npcap(self):
        loop = asyncio.get_running_loop()
        temp_dir = tempfile.gettempdir()
        installer_path = os.path.join(temp_dir, self.NPCAP_INSTALLER_FILENAME)
        try:
            self.logger.log_message(f"   - Downloading Npcap from {self.NPCAP_URL}...")
            await loop.run_in_executor(None, lambda: urllib.request.urlretrieve(self.NPCAP_URL, installer_path))

            self.logger.log_message("   - Running Npcap installer...")
            proc = await asyncio.create_subprocess_exec(installer_path, "", creationflags=subprocess.CREATE_NO_WINDOW)
            await proc.wait()

            await asyncio.sleep(5)
            self.logger.log_message("   - Npcap installation command executed.")
            return True
        except Exception as e:
            self.logger.log_message(f"❌ ERROR: Failed to download or install Npcap: {e}")
            return False
        finally:
            if os.path.exists(installer_path):
                os.remove(installer_path)

    def _get_known_hosts(self):
        """Extracts known hosts from the provided URLs to build filters."""
        known_hosts = set()
        if self.flask_server_url:
            if match := re.search(r'https?://([^:/]+)', self.flask_server_url):
                known_hosts.add(match.group(1))
        if self.pool_url:
            if match := re.search(r'([^:/]+)', self.pool_url):
                known_hosts.add(match.group(1))
        return list(known_hosts)

    async def _find_wifi_interface(self) -> Optional[int]:
        """
        Automatically finds the interface number for the 'Wi-Fi' adapter.
        """
        self.logger.log_message("   - Searching for Wi-Fi interface...")
        try:
            proc = await asyncio.create_subprocess_exec(
                self.tshark_path, "-D",
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW
            )
            stdout, _ = await proc.communicate()
            if proc.returncode == 0:
                interfaces = stdout.decode('utf-8', errors='replace').splitlines()
                for line in interfaces:
                    # Look for 'wi-fi' case-insensitively
                    if 'wi-fi' in line.lower():
                        # Extract the number at the start of the line (e.g., "1. ...")
                        match = re.match(r'^(\d+)\.', line.strip())
                        if match:
                            interface_id = int(match.group(1))
                            self.logger.log_message(f"   - Found Wi-Fi interface: {interface_id} ('{line.strip()}')")
                            return interface_id
                self.logger.log_message("   - ⚠️ No active Wi-Fi interface found.")
                return None
            return None
        except Exception as e:
            self.logger.log_message(f"❌ Error while searching for Wi-Fi interface: {e}")
            return None

    async def start_comprehensive_scan(self):
        """
        Starts three concurrent, asynchronous captures on the auto-detected
        Wi-Fi interface to monitor for security threats.
        """
        if not self.is_initialized:
            self.logger.log_message("Cannot start scan: Manager not initialized.")
            return

        if self.is_scanning:
            self.logger.log_message("A comprehensive scan is already running.")
            return

        interface_number = await self._find_wifi_interface()
        if interface_number is None:
            self.logger.log_message("❌ Cannot start scan: Could not automatically find a Wi-Fi interface.")
            return

        self.logger.log_message(f"\n🛡️ Starting Comprehensive Security Scan on Wi-Fi interface {interface_number}...")

        # Anomalous Traffic
        exclusion_filter = f"not ({' or '.join([f'host {h}' for h in self._known_hosts])})"
        proc_anomalous = await self._start_capture_process(interface_number, exclusion_filter, "Anomalous Traffic")
        if proc_anomalous:
            task = asyncio.create_task(self._monitor_anomalous_traffic(proc_anomalous))
            self._active_captures["Anomalous Traffic"] = (task, proc_anomalous)

        # DNS Queries
        proc_dns = await self._start_capture_process(interface_number, "dns.qr == 0", "DNS Queries")
        if proc_dns:
            task = asyncio.create_task(self._monitor_dns_queries(proc_dns))
            self._active_captures["DNS Queries"] = (task, proc_dns)

        # TLS Handshakes
        proc_tls = await self._start_capture_process(interface_number, "tls.handshake.type == 1", "TLS Analysis")
        if proc_tls:
            task = asyncio.create_task(self._monitor_tls_handshakes(proc_tls))
            self._active_captures["TLS Analysis"] = (task, proc_tls)

        self.logger.log_message(f"   - Launched {len(self._active_captures)} monitoring tasks.")

    async def _monitor_anomalous_traffic(self, proc: asyncio.subprocess.Process):
        """Task to log any traffic not directed to known hosts."""
        async for line_bytes in proc.stdout:
            line = line_bytes.decode('utf-8', errors='replace')
            self.logger.log_message(f"🚨 [SECURITY WARNING] Anomalous traffic detected: {line.strip()}")

    async def _monitor_dns_queries(self, proc: asyncio.subprocess.Process):
        """Task to log any DNS queries for domains not on the known hosts list."""
        async for line_bytes in proc.stdout:
            line = line_bytes.decode('utf-8', errors='replace')
            if not any(host in line for host in self._known_hosts):
                self.logger.log_message(f"⚠️ [SECURITY INFO] Suspicious DNS query detected: {line.strip()}")

    async def _monitor_tls_handshakes(self, proc: asyncio.subprocess.Process):
        """Task to log the start of all TLS handshakes for auditing."""
        async for line_bytes in proc.stdout:
            line = line_bytes.decode('utf-8', errors='replace')
            self.logger.log_message(f"🔒 [SECURITY INFO] New TLS connection initiated: {line.strip()}")

    async def _start_capture_process(self, interface_number, capture_filter, name):
        """Internal helper to launch and return an asyncio tshark process."""
        self.logger.log_message(f"   - Starting capture task: {name}")
        command = [self.tshark_path, "-i", str(interface_number), "-f", capture_filter, "-l"]
        try:
            # FIX: Removed encoding and errors parameters
            return await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW
            )
        except Exception as e:
            self.logger.log_message(f"❌ Failed to start capture task '{name}': {e}")
            return None

    async def stop_all_captures(self):
        """Stops all currently running capture tasks and their subprocesses."""
        if not self.is_scanning:
            self.logger.log_message("No active captures to stop.")
            return

        self.logger.log_message("\n⏹️ Stopping all capture tasks and processes...")

        # Terminate subprocesses first
        for name, (task, proc) in self._active_captures.items():
            if proc.returncode is None:
                try:
                    proc.terminate()
                    self.logger.log_message(f"   - Terminated tshark process for '{name}' (PID: {proc.pid})")
                except ProcessLookupError:
                    pass
                except Exception as e:
                    self.logger.log_message(f"   - Error terminating process for '{name}': {e}")

        # Wait for processes to exit and cancel tasks
        tasks = [task for task, proc in self._active_captures.values()]
        for task in tasks:
            task.cancel()

        await asyncio.gather(*tasks, return_exceptions=True)

        self._active_captures = {}
        self.logger.log_message("All capture tasks have been stopped.")


import os
import ctypes
import subprocess
import time


class WinRingManager:
    """
    Manages the WinRing0 kernel driver.

    If the driver service is already running, this class will use the existing
    instance without disturbing it. Otherwise, it will install and start the
    driver as a demand-start service using the 'sc' command-line tool.

    Requires Administrator privileges for installation and removal.
    """

    def __init__(self, driver_path: str, logger, *,
                 svc_name: str = "WinRing0_1_2_0",
                 display_name: str = "WinRing0 Driver"):
        self.logger = logger
        self.service_name = svc_name
        self.display_name = display_name
        self.driver_path = os.path.abspath(driver_path)
        self.initialized = False
        # This flag tracks if this instance is responsible for the driver's lifecycle.
        self.managed_by_this_instance = False

        if not self._is_admin():
            self.logger.log_message("[!] Admin rights are required to manage WinRing0 driver.")
            return

        if not os.path.exists(self.driver_path):
            self.logger.log_message(f"[!] Driver not found at '{self.driver_path}'")
            return

        # --- KEY LOGIC CHANGE ---
        # First, check if the service is already up and running.
        if self._is_service_running():
            self.logger.log_message(f"[*] Found existing '{self.service_name}' service is already running.")
            self.logger.log_message("[+] Will use the running driver instance. No changes were made.")
            self.initialized = True
            # We did not start it, so we will not manage its lifecycle.
            self.managed_by_this_instance = False
            return
        # --- END OF KEY LOGIC CHANGE ---

        # If not running, proceed with our own installation.
        self._force_cleanup_existing_service()

        if self._install_service() and self._start_service():
            self.initialized = True
            # We successfully started it, so we are responsible for cleanup.
            self.managed_by_this_instance = True
            self.logger.log_message(f"[+] Driver '{self.service_name}' loaded successfully by this instance.")

    def cleanup(self) -> None:
        """
        Public method to be called on application exit.

        Only stops and uninstalls the driver if it was started by this
        specific instance of the manager.
        """
        if self.initialized and self.managed_by_this_instance:
            self._stop_service()
            self._uninstall_service()
            self.logger.log_message(f"[+] Driver '{self.service_name}' unloaded by this instance.")
        elif self.initialized:
            self.logger.log_message(f"[*] Not unloading '{self.service_name}' as it was managed by another process.")

    @staticmethod
    def _is_admin() -> bool:
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except Exception:
            return False

    def _run_command(self, command: list) -> (bool, str):
        """Helper to run a subprocess command and capture its output."""
        try:
            # CREATE_NO_WINDOW flag prevents the cmd window from flashing
            result = subprocess.run(command, capture_output=True, text=True, check=False,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            output = result.stdout + result.stderr
            return result.returncode == 0, output
        except FileNotFoundError:
            self.logger.log_message(f"[!] Error: Command '{command[0]}' not found. Is it in your system's PATH?")
            return False, "Command not found"
        except Exception as e:
            self.logger.log_message(f"[!] An unexpected error occurred while running command: {e}")
            return False, str(e)

    def _service_exists(self) -> bool:
        """Checks if the service is registered (not necessarily running)."""
        success, output = self._run_command(['sc', 'query', self.service_name])
        # 'sc query' returns a non-zero exit code (1060) if the service doesn't exist.
        return "1060" not in output

    def _is_service_running(self) -> bool:
        """Checks if the service is currently in the 'RUNNING' state."""
        success, output = self._run_command(['sc', 'query', self.service_name])
        # Check for successful command and the state string.
        # The key line in a successful query is "STATE              : 4  RUNNING"
        return success and "RUNNING" in output

    def _force_cleanup_existing_service(self):
        """Stops and deletes any existing, non-running service instance."""
        self.logger.log_message(f"[*] Checking for and cleaning up any existing '{self.service_name}' service...")
        if self._service_exists():
            self.logger.log_message("   - Found existing service registration. Attempting to delete...")
            # A stop is attempted just in case, but it's unlikely to be running
            # if we passed the _is_service_running check.
            self._run_command(['sc', 'stop', self.service_name])
            time.sleep(1)
            success, output = self._run_command(['sc', 'delete', self.service_name])
            if success:
                self.logger.log_message("   - Service successfully marked for deletion.")
            else:
                self.logger.log_message(f"   - Failed to delete service: {output}")

            self.logger.log_message("   - Waiting for service to be fully removed...")
            for _ in range(10):  # Wait up to 5 seconds
                if not self._service_exists():
                    self.logger.log_message("   - Service has been fully removed.")
                    return
                time.sleep(0.5)
            self.logger.log_message("   - ⚠️ Timed out waiting for service to be removed.")
        else:
            self.logger.log_message("   - No pre-existing service found.")

    def _install_service(self) -> bool:
        self.logger.log_message(f"[+] Creating service '{self.service_name}'...")
        command = [
            'sc', 'create', self.service_name,
            'binPath=', self.driver_path,
            'type=', 'kernel',
            'start=', 'demand',
            'DisplayName=', self.display_name
        ]
        success, output = self._run_command(command)
        if success:
            self.logger.log_message("[+] Service created successfully.")
            return True
        else:
            self.logger.log_message(f"[!] Failed to create service: {output}")
            return False

    def _start_service(self) -> bool:
        self.logger.log_message(f"[+] Starting service '{self.service_name}'...")
        for attempt in range(5):
            success, output = self._run_command(['sc', 'start', self.service_name])
            if success:
                self.logger.log_message("[+] Service started successfully.")
                return True

            if "183" in output or "already exists" in output.lower():
                self.logger.log_message(f"   - Start failed with race condition. Retrying... (Attempt {attempt + 1}/5)")
                time.sleep(1)
                continue

            self.logger.log_message(f"[!] Failed to start service: {output}")
            return False

        self.logger.log_message("[!] Failed to start service after multiple retries.")
        return False

    def _stop_service(self) -> None:
        self._run_command(['sc', 'stop', self.service_name])

    def _uninstall_service(self) -> None:
        self._run_command(['sc', 'delete', self.service_name])

class AsyncPsutilManager:

    def __init__(self,
                 proc: Union[int, psutil.Process],
                 logger: AnyStr = None,):
        self.proc: psutil.Process = proc if isinstance(proc, psutil.Process) else psutil.Process(proc)
        self.log  = logger.log_message if logger else print          # fall back to print

    # -------------------------------------------------------------------------
    # Priority helpers
    # -------------------------------------------------------------------------
    async def set_high_priority(self) -> bool:
        """Windows: HIGH_PRIORITY_CLASS, POSIX: nice ‑10."""
        try:
            await asyncio.to_thread(self.proc.nice,
                                     psutil.HIGH_PRIORITY_CLASS
                                        if psutil.WINDOWS else -10)
            self.log(f"[+] Set process {self.proc.pid} to high priority.")
            return True
        except Exception as e:
            self.log(f"[!] Failed to raise priority for {self.proc.pid}: {e}")
            return False


    async def set_cpu_affinity(self, cores: int) -> bool:
        """
        Bind the process to *exactly* the cores passed in.
        Example: await mgr.set_cpu_affinity([0,1,2,3])
        """
        try:
            await asyncio.to_thread(self.proc.cpu_affinity, list(range(cores)))
            self.log(f"[+] Set affinity of {self.proc.pid} → {list(range(cores))}")
            return True
        except Exception as e:
            self.log(f"[!] Failed affinity set for {self.proc.pid}: {e}")
            return False

    async def set_io_priority(self, prio) -> bool:
        """
        Windows: use psutil.IOPRIO_* constants.
        Linux  : (class, level) tuple, e.g. (psutil.IOPRIO_CLASS_IDLE, 0)
        """

        try:
            await asyncio.to_thread(self.proc.ionice, prio)
            self.log(f"[+] Set I/O niceness of {self.proc.pid} → {str(prio)}")
            return True
        except AttributeError:
            self.log("[!] ionice not supported on this platform.")
            return False
        except Exception as e:
            self.log(f"[!] Failed I/O priority set for {self.proc.pid}: {e}")
            return False


class AsyncRyzenSMUManager:
    """
    An asynchronous version of RyzenSMUManager.
    """
    # MSR addresses and other constants...
    SMU_MSR_CMD  = 0xC001_0304
    SMU_MSR_ARG0 = 0xC001_0305
    SMU_MSR_RSP  = 0xC001_0308
    SMC_MSG_SetSustainedPptLimit = 0x1A
    SMC_MSG_SetFastPptLimit      = 0x1B
    SMC_MSG_SetSlowPptLimit      = 0x1C
    SMC_MSG_EnableFeatures       = 0x05
    PPT_FEATURE_BIT              = 1 << 3
    EXECUTE_BIT = 1 << 31
    SMU_RSP_OK            = (0x00, 0x01)
    SMU_RSP_UNKNOWN_CMD   = 0xFF
    SMU_RSP_CMD_REJECTED  = 0xFE
    SMU_RSP_CMD_PREREQ    = 0xFD

    def __init__(self, logger, tools_dir: str = "tools"):
        self.logger = logger
        self.core0  = ["-p", "0"]
        root = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
        self.cmd_path = os.path.join(root, tools_dir, "msr-cmd.exe")
        self.initialized = os.path.isfile(self.cmd_path)
        self.ppt_feature_on = False
        if self.initialized:
            logger.log_message(f"[+] AsyncRyzenSMUManager found → {self.cmd_path}")
        else:
            logger.log_message(f"[!] msr-cmd not found at {self.cmd_path}")

    async def _run_msr(self, extra_args, *args) -> Optional[str]:
        if not self.initialized: return None
        cmd = [self.cmd_path] + extra_args + list(args)
        try:
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=2.0)
            if process.returncode:
                self.logger.log_message(f"[!] msr-cmd exit {process.returncode}: {stderr.decode().strip()}")
                return None
            return stdout.decode().strip()
        except asyncio.TimeoutError:
            self.logger.log_message(f"[!] msr-cmd execution timed out")
            return None
        except Exception as e:
            self.logger.log_message(f"[!] msr-cmd exception: {e}")
            return None

    async def _write_msr(self, addr: int, val: int) -> bool:
        lo, hi = val & 0xFFFFFFFF, (val >> 32) & 0xFFFFFFFF
        res = await self._run_msr(self.core0, "write", hex(addr), hex(hi), hex(lo))
        return res is not None

    async def _read_msr(self, addr: int) -> Optional[int]:
        out = await self._run_msr(self.core0 + ["-d"], "read", hex(addr))
        if not out: return None
        try:
            edx, eax = out.split()[-2:]
            return (int(edx, 16) << 32) | int(eax, 16)
        except Exception:
            return None

    async def _wait_for_smu(self, timeout_ms: int = 100) -> bool:
        for _ in range(timeout_ms):
            status = await self._read_msr(self.SMU_MSR_CMD)
            if status is None: return False
            if not (status & self.EXECUTE_BIT): return True
            await asyncio.sleep(0.001)
        self.logger.log_message("[*] Mailbox stuck → forcing clear")
        return await self._force_clear_mailbox()

    async def _force_clear_mailbox(self) -> bool:
        if not await self._write_msr(self.SMU_MSR_CMD, 0): return False
        await asyncio.sleep(0.001)
        status = await self._read_msr(self.SMU_MSR_CMD)
        return status is not None and not (status & self.EXECUTE_BIT)

    async def _send_mp1(self, msg_id: int, arg0: int = 0) -> Optional[int]:
        if not await self._wait_for_smu():
            self.logger.log_message("[!] SMU busy – giving up")
            return None
        if not (await self._write_msr(self.SMU_MSR_RSP, 0) and
                await self._write_msr(self.SMU_MSR_ARG0, arg0) and
                await self._write_msr(self.SMU_MSR_CMD, msg_id)):
            self.logger.log_message("[!] MSR write sequence failed")
            return None
        if not await self._wait_for_smu():
            self.logger.log_message("[!] SMU never cleared EXECUTE_BIT")
            return None
        cmd_val = await self._read_msr(self.SMU_MSR_RSP)
        return (cmd_val & 0xFF) if cmd_val is not None else None

    async def _enable_ppt_feature(self) -> bool:
        if self.ppt_feature_on: return True
        rsp = await self._send_mp1(self.SMC_MSG_EnableFeatures, self.PPT_FEATURE_BIT)
        ok = rsp is not None and (rsp & 0xFF) in self.SMU_RSP_OK
        if ok:
            self.ppt_feature_on = True
        else:
            self.logger.log_message("[!] Could not enable PPT feature")
        return ok

    async def set_ppt_limit(self, watts: int, kind: str = "fast") -> bool:
        """Asynchronously sets the PPT limit (fast, slow, or sustained)."""
        if not self.initialized:
            self.logger.log_message("[!] SMU Manager not initialized")
            return False

        ids = {"sustained": self.SMC_MSG_SetSustainedPptLimit, "fast": self.SMC_MSG_SetFastPptLimit, "slow": self.SMC_MSG_SetSlowPptLimit}
        msg = ids.get(kind.lower())
        if msg is None:
            self.logger.log_message("[!] PPT kind must be fast/slow/sustained")
            return False
        if not await self._enable_ppt_feature():
            return False

        mw = watts * 1000
        self.logger.log_message(f"[*] Setting {kind} PPT → {watts} W")
        rsp = await self._send_mp1(msg, mw)

        if rsp in self.SMU_RSP_OK:
            self.logger.log_message(f"[+] {kind.capitalize()} PPT now {watts} W")
            return True

        errmsg = {
            self.SMU_RSP_UNKNOWN_CMD: "Unknown command",
            self.SMU_RSP_CMD_REJECTED: "Rejected (locked in BIOS)",
            self.SMU_RSP_CMD_PREREQ: "Prerequisite missing",
        }.get(rsp, f"SMU responded 0x{rsp:02X}" if rsp is not None else "timeout")
        self.logger.log_message(f"[!] PPT write failed: {errmsg}")
        return False


class AsyncMSRManager:
    """
    An asynchronous version of MSRManager that uses asyncio.subprocess
    to avoid blocking the event loop when calling msr-cmd.exe.
    """

    def __init__(self, logger):
        self.logger = logger
        self.initialized = False
        self.base_path = ""
        self.MSR_RAPL_POWER_LIMIT = 0x610
        try:
            # Determine the correct path for msr-cmd.exe whether running as a script or a frozen executable
            if getattr(sys, 'frozen', False):
                self.base_path = os.path.join(sys._MEIPASS, 'tools')
            else:
                self.base_path = os.path.join(os.path.dirname(__file__), 'tools')

            self.cmd_path = os.path.join(self.base_path, "msr-cmd.exe")

            if not os.path.exists(self.cmd_path):
                raise FileNotFoundError(f"msr-cmd.exe not found at {self.cmd_path}")

            self.logger.log_message("[+] AsyncMSRManager initialized: msr-cmd.exe found")
            self.initialized = True
        except Exception as e:
            self.logger.log_message(f"[!] AsyncMSRManager init failed: {e}")
            self.initialized = False

    async def _run(self, args):
        """Asynchronously runs msr-cmd.exe and captures its output."""
        if not self.initialized:
            return None
        try:
            process = await asyncio.create_subprocess_exec(
                self.cmd_path,
                *args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                creationflags=subprocess.CREATE_NO_WINDOW,
                cwd=self.base_path
            )
            stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=2.0)

            if process.returncode != 0:
                self.logger.log_message(f"[!] msr-cmd failed: {stderr.decode().strip()}")
                return None
            return stdout.decode().strip()
        except asyncio.TimeoutError:
            self.logger.log_message(f"[!] msr-cmd execution timed out")
            return None
        except Exception as e:
            self.logger.log_message(f"[!] msr-cmd execution error: {e}")
            return None

    async def write_to_msr(self, index, low, high):
        """Asynchronously writes a 64-bit value to an MSR."""
        result = await self._run(["write", hex(index), hex(high), hex(low)])
        return result is not None

    async def set_pl1_pl2(self, power_watts: int):
        """Asynchronously sets the PL1 and PL2 power limits."""
        if not self.initialized:
            self.logger.log_message(f"[!] PL1/PL2 set failed (not initialized).")
            return False

        power_unit = 0.125
        raw_limit = int(power_watts / power_unit) & 0x7FFF
        value = raw_limit | (1 << 15) | (raw_limit << 32) | (1 << 47)
        low = value & 0xFFFFFFFF
        high = (value >> 32) & 0xFFFFFFFF

        self.logger.log_message(f"[*] Setting PL1/PL2 to {power_watts}W → EDX={high:#010x}, EAX={low:#010x}")
        return await self.write_to_msr(self.MSR_RAPL_POWER_LIMIT, low, high)


class ProcessManager:
    """A helper class to manage Windows process attributes using the Windows API."""

    def __init__(self, logger):
        self.logger = logger
        # Define necessary Windows API components
        self.kernel32 = ctypes.WinDLL('kernel32', use_last_error=True)
        self.PROCESS_SET_QUOTA = 0x0100
        self.PROCESS_QUERY_INFORMATION = 0x0400
        self.PROCESS_SET_INFORMATION = 0x0200


    def recommend_max_memory(self):
        """
        Calculates a recommended max working set size based on total system RAM.
        Returns the recommended size in megabytes (MB).
        """
        # Prepare a variable to hold the result from the API call
        total_ram_kb = ctypes.c_ulonglong()

        # Call GetPhysicallyInstalledSystemMemory to get total RAM in kilobytes
        if not self.kernel32.GetPhysicallyInstalledSystemMemory(ctypes.byref(total_ram_kb)):
            self.logger.log_message(f"[!] Could not get total system memory. Error: {ctypes.get_last_error()}")
            return None # Return None on failure

        total_ram_mb = total_ram_kb.value / 1024
        self.logger.log_message(f"[*] Total system RAM detected: {total_ram_mb:.0f} MB")

        recommended_mb = total_ram_mb


        return int(recommended_mb)

    async def set_priority_boost_async(self, pid: int, enable_boost: bool) -> bool:
        """
        Awaitable version of set_priority_boost().
        Runs the blocking work in a default ThreadPoolExecutor.
        """
        return await asyncio.to_thread(self.set_priority_boost, pid, enable_boost)

    async def set_working_set_size_async(self,
                                         pid: int,
                                         min_size_mb: int,
                                         max_size_mb: int) -> bool:
        """
        Awaitable version of set_working_set_size().
        """
        return await asyncio.to_thread(self.set_working_set_size,
                                       pid, min_size_mb, max_size_mb)

    def set_priority_boost(self, pid, enable_boost):
        """
        Enables or disables dynamic priority boosting for a process's threads.
        :param pid: The process ID.
        :param enable_boost: Set to True to enable boosting, False to disable it.
        """
        if not pid:
            self.logger.log_message("[!] Cannot set priority boost: Invalid PID.")
            return False

        h_process = self.kernel32.OpenProcess(self.PROCESS_SET_INFORMATION, False, pid)

        if not h_process:
            self.logger.log_message(
                f"[!] Set priority boost: Failed to get handle for PID {pid}. Error: {ctypes.get_last_error()}")
            return False

        success = False
        try:
            # Determine the state for logging purposes based on the new parameter
            state = "enabled" if enable_boost else "disabled"


            # Call the API with the inverse of the enable_boost flag
            if self.kernel32.SetProcessPriorityBoost(h_process, not enable_boost):
                success = True
            else:
                self.logger.log_message(
                    f"[!] Failed to set priority boost for PID {pid}. Error: {ctypes.get_last_error()}")
        finally:
            self.kernel32.CloseHandle(h_process)

        return success

    def set_working_set_size(self, pid, min_size_mb, max_size_mb):
        """
        Suggests a memory working set size for a given process ID.
        This is a suggestion to the kernel, not a strict limit.
        """
        if not pid:
            self.logger.log_message("[!] Cannot set working set: Invalid PID.")
            return False

        min_bytes = int(min_size_mb * 1024 * 1024)
        max_bytes = int(max_size_mb * 1024 * 1024)

        # Get a handle to the process with the required permissions
        h_process = self.kernel32.OpenProcess(
            self.PROCESS_SET_QUOTA | self.PROCESS_QUERY_INFORMATION,
            False,
            pid
        )

        if not h_process:
            self.logger.log_message(f"[!] Failed to get handle for PID {pid}. Error: {ctypes.get_last_error()}")
            return False

        success = False
        try:
            self.logger.log_message(f"[*] Suggesting working set for PID {pid}: Min {min_size_mb}MB, Max {max_size_mb}MB.")
            # Call the SetProcessWorkingSetSizeEx API function
            if self.kernel32.SetProcessWorkingSetSizeEx(h_process,
                                                      ctypes.c_size_t(min_bytes),
                                                      ctypes.c_size_t(max_bytes),
                                                      0): # Flags=0 for soft limits
                self.logger.log_message(f"[+] Successfully sent working set size suggestion for PID {pid}.")
                success = True
            else:
                self.logger.log_message(f"[!] Failed to set working set size for PID {pid}. Error: {ctypes.get_last_error()}")
        finally:
            # Always ensure the handle is closed
            self.kernel32.CloseHandle(h_process)

        return success
