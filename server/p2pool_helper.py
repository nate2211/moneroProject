# p2pool_helper.py
import asyncio
import os
import threading
import time
from socket import AF_INET, SOCK_DGRAM, socket

import psutil
import requests

from p2pool_data import P2poolData, EventProcessor, RawLogProcessor, P2PoolProcessor
from client_data import ClientData
from p2pool_managers import WiresharkManager, PacketManager, PythonRouterManager



class _PrintLogger:
    """A simple, GUI-agnostic fallback logger that uses the standard print() function."""

    def log_message(self, msg):
        print(str(msg))


class _PrintNetworkLogger:
    """A fallback logger specifically for network messages."""

    def log_message(self, msg):
        # Add a prefix to distinguish network logs in the console before the GUI is ready
        print(f"[Net] {str(msg)}")


class P2PoolHelper:
    def __init__(self):
        # --- Constants and State ---
        self.ELECTRICITY_RATE_PER_KWH = 0.13
        self.COMMAND_QUEUE = {}
        self.asyncio_main_loop = None

        # --- Instantiate with safe, temporary loggers FIRST ---
        self.logger = _PrintLogger()
        self.wireshark_logger = _PrintNetworkLogger()
        self.packet_logger = _PrintLogger()
        self.router_logger = _PrintLogger()
        # Event to signal P2Pool-related threads to stop
        self.p2pool_stop_event = threading.Event()

        # --- Pass the appropriate loggers to all child classes ---
        self.p2pooldata = P2poolData(self.logger)
        self.clientdata = ClientData(self.logger)
        self.event_processor = EventProcessor(self.p2pooldata, self.logger, self.p2pool_stop_event)
        self.raw_log_processor = RawLogProcessor(self.p2pooldata, self.logger, self.p2pool_stop_event)
        self.processor = P2PoolProcessor(self.p2pooldata, self.logger, self.p2pool_stop_event)

        # --- Pass the dedicated network logger to the Wireshark Manager ---
        self.wireshark_manager = WiresharkManager(self.p2pooldata, self.wireshark_logger)
        self.process_manager = None
        self.packet_manager = PacketManager(self.packet_logger)
        self.router_manager = None

    def set_p2pool_stop_event(self, stop_event):
        self.p2pool_stop_event = stop_event
        self.event_processor.stop_event = self.p2pool_stop_event
        self.raw_log_processor.stop_event = self.p2pool_stop_event
        self.processor.stop_event = self.p2pool_stop_event

    def set_gui_logger(self, gui_logger):
        """Replaces the temporary main logger with the real GUI logger."""
        print("[+] GUI Logger activated.")
        self.logger = gui_logger
        # Propagate the real logger to all relevant child objects
        self.p2pooldata.logger = gui_logger
        self.clientdata.logger = gui_logger
        self.event_processor.logger = gui_logger
        self.raw_log_processor.logger = gui_logger
        self.processor.logger = gui_logger

    def set_wireshark_logger(self, wireshark_logger):
        """Replaces the temporary network logger with the real GUI network logger."""
        print("[+] GUI Network Logger activated.")
        self.wireshark_logger = wireshark_logger
        # Propagate the real network logger to the Wireshark Manager
        self.wireshark_manager.logger = wireshark_logger
    def set_packet_logger(self, packet_logger):
        """Replaces the temporary network logger with the real GUI network logger."""
        print("[+] GUI Network Logger activated.")
        self.packet_logger = packet_logger
        # Propagate the real network logger to the Wireshark Manager
        self.packet_manager.logger = packet_logger

    def set_router_logger(self, router_logger):
        """Replaces the temporary network logger with the real GUI network logger."""
        print("[+] GUI Network Logger activated.")
        self.router_logger = router_logger
        # Propagate the real network logger to the Wireshark Manager
        self.router_manager.logger = router_logger

    def queue_command(self, client_id, command_data):
        if client_id not in self.COMMAND_QUEUE:
            self.COMMAND_QUEUE[client_id] = []
        self.COMMAND_QUEUE[client_id].append(command_data)
        self.logger.log_message(f"[+] Queued command for '{client_id}': {command_data}")

    def clear_file_contents(self, filepath):
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.truncate(0)
            self.logger.log_message(f"[+] Cleared contents of: {filepath}")
        except Exception as e:
            self.logger.log_message(f"[!] Error clearing file {filepath}: {e}")

    def clear_all_client_data(self):
        self.logger.log_message("[!] Clearing all existing client data on startup...")
        self.clientdata.client_hashrates.clear()
        self.clientdata.client_newjobs.clear()
        self.clientdata.client_costs.clear()
        self.COMMAND_QUEUE.clear()
        self.p2pooldata.log_event_now("System Startup", "All client data cleared.")
        self.logger.log_message("[+] Client data cleared successfully.")

    def get_public_ip(self):
        """Fetches the current public IP address using an external service."""
        try:
            # Using a reliable service like ipify.org
            response = requests.get('https://api.ipify.org?format=json', timeout=5)
            response.raise_for_status()  # Raise an HTTPError for bad responses (4xx or 5xx)
            ip = response.json()['ip']
            return ip
        except requests.exceptions.RequestException as e:
            self.logger.log_message(f"[IP Check] Could not get public IP from ipify.org: {e}")
            return None

    def get_local_ip(self):
        """Find the local static IP address, preferring Wi-Fi and avoiding VPNs like ProtonVPN."""
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for interface_name, addresses in interfaces.items():
            if not stats.get(interface_name) or not stats[interface_name].isup:
                continue

            # Skip virtual and VPN interfaces
            lower_name = interface_name.lower()
            if any(v in lower_name for v in ['protonvpn', 'vpn', 'zerotier', 'tunnel', 'loopback', 'virtual']):
                continue

            # Prefer Wi-Fi or known interface names
            if not any(w in lower_name for w in ['wi-fi', 'wlan', 'wireless']):
                continue

            for addr in addresses:
                if addr.family == AF_INET:
                    return addr.address

        # Fallback: default route detection
        try:
            s = socket(AF_INET, SOCK_DGRAM)
            s.connect(('10.255.255.255', 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = '127.0.0.1'
        finally:
            s.close()
        return ip

class ProcessManager:
    def __init__(self, p2pool_data, flask_restart_callback, p2pool_processor, logger):
        self.p2pool_data = p2pool_data
        self.get_local_ip = p2pool_helper.get_local_ip
        self.flask_restart_callback = flask_restart_callback
        self.p2pool_processor = p2pool_processor
        self.logger = logger
        self.monitor_interval = 1000
        self._monitor_thread = None
        self._stop_event = threading.Event()
        self._current_ip = None

    def kill_flask_server(self ):
        """Attempts to kill any existing Flask server by scanning for the port."""
        """
          Attempts to gracefully terminate, then forcefully kill, any existing Flask server
          processes that are listening on port 5000.
          """
        print("[!] Checking for and terminating existing Flask server processes on port 5000...")

        current_script_pid = os.getpid()  # Get the PID of the current main script
        processes_to_terminate = []
        found_and_terminated = False

        # First pass: Identify and attempt to terminate processes
        # We ask for 'pid', 'name', 'cmdline' for better identification, and call 'connections' separately.
        for proc in psutil.process_iter(['pid', 'name', 'cmdline']):
            try:
                # Skip if the process is not running or is a zombie
                if not proc.is_running():
                    continue

                # Skip our own main application process
                if proc.pid == current_script_pid:
                    continue

                # Check if it's a Python process (Flask runs on Python)
                process_name_lower = proc.name().lower()
                if 'python' in process_name_lower or 'pythonw' in process_name_lower:
                    # Check command line arguments to narrow down to our Flask subprocess
                    cmdline = proc.cmdline()
                    if '--start-flask' in cmdline and 'p2pool_server.py' in cmdline[
                        0]:  # Check if it's our specific Flask runner
                        # Check its network connections for port 5000
                        for conn in proc.connections(kind='inet'):
                            if conn.laddr and conn.laddr.port == 5000 and conn.status == psutil.CONN_LISTEN:
                                print(
                                    f"    - Found Flask server process (PID: {proc.pid}, Name: {proc.name()}) listening on port 5000. Terminating...")
                                proc.terminate()  # Send SIGTERM
                                processes_to_terminate.append(proc)
                                found_and_terminated = True
                                break  # Found for this process, move to next proc in outer loop
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                # Ignore processes that no longer exist, or cannot be accessed, or are zombies
                continue
            except Exception as e:
                print(f"[!] Error inspecting process {proc.pid} for Flask server: {e}")

        if found_and_terminated:
            print("[!] Waiting for identified Flask server processes to terminate...")
            # Second pass: Wait for processes to actually terminate (with a timeout)

            # Give them a moment to react to terminate signal
            time.sleep(1)

            still_running_processes = []
            for _ in range(4):  # Re-check up to 4 times (total of 5 seconds wait with initial 1 sec)
                still_running_processes.clear()  # Clear list for current check
                for proc in processes_to_terminate:
                    try:
                        if proc.is_running():  # Check if the process is still running
                            still_running_processes.append(proc)
                    except (psutil.NoSuchProcess, psutil.ZombieProcess):
                        pass  # Already gone or just became zombie, good

                if not still_running_processes:
                    print("[+] All identified Flask server processes terminated gracefully.")
                    return  # All gone, success

                print(f"[!] {len(still_running_processes)} Flask server processes still running. Re-checking...")
                time.sleep(1)  # Wait a bit before re-checking

            # If loop finishes and processes are still there, try to kill forcefully
            for proc in still_running_processes:
                if proc.is_running():  # Double check before killing
                    print(f"[!] Flask server process (PID: {proc.pid}) still running. Forcing kill.")
                    try:
                        proc.kill()  # Send SIGKILL
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        pass  # Already gone or inaccessible

        if not found_and_terminated:
            print("[+] No existing Flask server processes found to terminate on port 5000.")

    def start(self):
        self._current_ip = p2pool_helper.get_public_ip()
        self.logger.log_message(f"[ProcessManager] Initial IP: {self._current_ip}")
        self._monitor_thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._monitor_thread.start()

    def stop(self):
        self._stop_event.set()
        self.logger.log_message("[ProcessManager] Stopping IP monitor...")

    def _monitor_loop(self):
        while not self._stop_event.is_set():
            try:
                current_ip = p2pool_helper.get_public_ip()
                if current_ip != self._current_ip:
                    self.logger.log_message(f"[ProcessManager] Detected IP change: {self._current_ip} → {current_ip}")
                    self._current_ip = current_ip
                    asyncio.run(self._restart_services())
                threading.Event().wait(self.monitor_interval)
            except Exception as e:
                self.logger.log_message(f"[ProcessManager] Error in monitor loop: {e}")

    async def _restart_services(self):
        self.logger.log_message("[ProcessManager] Restarting Flask server and P2Pool...")
        await self.p2pool_processor.stop_p2pool()
        await self.p2pool_processor.start_p2pool()
        self.kill_flask_server()
        threading.Thread(target=self.flask_restart_callback, daemon=True).start()
# Create a single, importable instance of the now-independent helper
p2pool_helper = P2PoolHelper()
