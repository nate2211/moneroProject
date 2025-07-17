import asyncio
import ctypes
import subprocess
import sys
import clr
import os
from threading import Thread, Event

try:
    clr.AddReference("LibreHardwareMonitorLib")
    from LibreHardwareMonitor.Hardware import Computer, HardwareType, SensorType
except Exception as e:
    print(f"[!] FATAL: Could not load LibreHardwareMonitorLib: {e}")
    sys.exit(1)

class MSRManager:
    """
    Provides access to MSR registers using WinRing0x64.dll for Intel chips.
    If the DLL cannot be found or initialized, the manager will be disabled.
    """

    def __init__(self, logger):
        self.logger = logger
        self.wr0 = None
        self.initialized = False

        try:
            if getattr(sys, 'frozen', False):
                # Running from a PyInstaller bundle
                base_bath = sys._MEIPASS
            else:
                # Running in a development environment
                base_path = os.path.dirname(os.path.abspath(__file__))

            self.dll_path = os.path.join(base_path, "WinRing0x64.dll")
            if not os.path.exists(self.dll_path):
                # Raise an exception to be caught by the outer block
                raise FileNotFoundError(f"WinRing0x64.dll not found at {self.dll_path}")
            else:
                self.logger.log_message("WinRing0x64.dll Found")
            self.wr0 = ctypes.WinDLL(self.dll_path)

            # Check driver status
            if not self.wr0.InitializeOls():
                self.logger.log_message("[!] Failed to initialize WinRing0 driver. MSRManager is disabled.")
                # No need to raise, just leave self.initialized as False
            else:
                self.logger.log_message("[+] WinRing0 driver initialized successfully.")
                self.initialized = True

        except FileNotFoundError as e:
            self.logger.log_message(f"[!] {e}. MSR functionality will be disabled.")
        except Exception as e:
            self.logger.log_message(f"[!] An unexpected error occurred during MSRManager setup: {e}. MSRManager is disabled.")


    def __del__(self):
        # Only deinitialize if the driver was successfully loaded
        if self.initialized:
            self.wr0.DeinitializeOls()

    def write_msr(self, index, low, high):
        """
        Writes to a Model-Specific Register.
        :param index: MSR index (e.g., 0x610 for RAPL power limits)
        :param low: Lower 32 bits of the value
        :param high: Upper 32 bits of the value
        :return: True if successful, False otherwise
        """
        if not self.initialized:
            self.logger.log_message("[!] MSR write aborted: driver not initialized.")
            return False

        success = self.wr0.WriteMsr(index, ctypes.c_ulong(low), ctypes.c_ulong(high))
        if not success:
            self.logger.log_message(f"[!] Failed to write MSR 0x{index:X}")
        return bool(success)

    def read_msr(self, index):
        """
        Reads a Model-Specific Register.
        :return: A tuple (low, high) of 32-bit values, or (None, None) on failure.
        """
        if not self.initialized:
            self.logger.log_message("[!] MSR read aborted: driver not initialized.")
            return None, None

        low = ctypes.c_ulong()
        high = ctypes.c_ulong()
        if self.wr0.ReadMsr(index, ctypes.byref(low), ctypes.byref(high)):
            return low.value, high.value

        self.logger.log_message(f"[!] Failed to read MSR 0x{index:X}")
        return None, None

    def set_pl1_pl2(self, power_watts):
        """
        Sets PL1 and PL2 to the same value using the MSR 0x610 register.
        This method also enables both power limits. A more advanced implementation
        would first read the MSR to preserve existing time window settings.

        :param power_watts: Desired power limit in watts
        :return: True if successful, False otherwise
        """
        if not self.initialized:
            # No need to log here, as write_msr will handle it.
            return False

        MSR_RAPL_POWER_LIMIT = 0x610

        # NOTE: The power unit is typically 0.125W, but this is not guaranteed.
        # A fully robust solution would first read MSR 0x606 (MSR_RAPL_POWER_UNIT)
        # to determine the actual power unit, which is 1.0 / (2^power_unit_bits).
        power_unit = 0.125  # Watts per unit (typical for Intel)

        # Calculate the raw limit value based on the power unit
        limit_raw = int(power_watts / power_unit)

        # The power limit value is a 15-bit field
        power_limit_val = limit_raw & 0x7FFF

        # Construct the 64-bit value for MSR 0x610 (MSR_PKG_POWER_LIMIT)
        # MSR Layout:
        # [14:0]  -> Power Limit 1 (PL1)
        # [15]    -> PL1 Enable
        # [46:32] -> Power Limit 2 (PL2)
        # [47]    -> PL2 Enable

        value = power_limit_val         # Set PL1 value
        value |= (1 << 15)              # Enable PL1
        value |= (power_limit_val << 32)# Set PL2 value
        value |= (1 << 47)              # Enable PL2

        low = value & 0xFFFFFFFF
        high = (value >> 32) & 0xFFFFFFFF

        self.logger.log_message(f"[*] Setting PL1 and PL2 to {power_watts}W")
        return self.write_msr(MSR_RAPL_POWER_LIMIT, low, high)



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

        # --- Recommendation Logic ---
        # A safe heuristic to avoid system instability.
        if total_ram_mb > 16000: # Over 16GB
            # Recommend 50% of total RAM
            recommended_mb = total_ram_mb * 0.50
        elif total_ram_mb > 8000: # Over 8GB
            # Recommend 40% of total RAM
            recommended_mb = total_ram_mb * 0.40
        else: # 8GB or less
            # Recommend a more conservative 25% for low-memory systems
            recommended_mb = total_ram_mb * 0.25

        return int(recommended_mb)

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
            self.logger.log_message(f"[*] Setting priority boost for PID {pid} to {state}.")

            # Call the API with the inverse of the enable_boost flag
            if self.kernel32.SetProcessPriorityBoost(h_process, not enable_boost):
                self.logger.log_message(f"[+] Successfully {state} priority boost for PID {pid}.")
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

class HardwareMonitor(Thread):
    """
    A dedicated, self-healing thread to safely manage LibreHardwareMonitor.
    It can now recover from internal library crashes by re-initializing.
    It also handles GPU detection to avoid resource conflicts.
    """

    def __init__(self, logger):
        super().__init__(daemon=True)
        self.logger = logger
        self._stop_event = Event()

        # Public attributes to hold the latest data
        self.cpu_temperature_formatted = "N/A"
        self.total_power_draw = "N/A"
        self.has_nvidia_gpu = False  # Flag for GPU detection
        self.tuner = {
                        "index": 0,
                        "affinity": -1,
                        "dataset_host": False
                    }
        # Internal state
        self.computer = None
        self._cpu_temp_sensors = []
        self._power_sensors = []
        self._unique_hardware = set()

    def _initialize(self):
        """(Re)Initializes the Computer object and finds all necessary sensors."""
        try:
            self.logger.log_message("[+] Initializing hardware monitor...")
            self.computer = Computer()
            self.computer.IsCpuEnabled = True
            self.computer.IsGpuEnabled = True
            self.computer.Open()

            # Clear previous state
            self._cpu_temp_sensors.clear()
            self._power_sensors.clear()
            self._unique_hardware.clear()
            self.has_nvidia_gpu = False  # Reset flag on re-initialization
            self.gpu_name = None
            self.vram_mb = 0
            # Find sensors and their parent hardware
            for hardware in self.computer.Hardware:
                hardware.Update()

                # Consolidated check for NVIDIA GPU
                if "nvidia" in str(hardware.HardwareType).lower():
                    self.has_nvidia_gpu = True
                    self.gpu_name = hardware.Name.lower()
                    hardware.Update()
                    for sensor in hardware.Sensors:
                        if sensor.SensorType == SensorType.SmallData and "memory total" in sensor.Name.lower():
                            if sensor.Value is not None:
                                self.vram_mb = int(sensor.Value)  # Usually reported in MB
                    self.logger.log_message(f"[+] Detected GPU: {self.gpu_name}, VRAM: {self.vram_mb}MB")

                    # Heuristic logic
                    if "1050" in self.gpu_name:
                        self.tuner.update(dict(threads=1, blocks=32, bfactor=7, bsleep=30))
                    elif "2060" in self.gpu_name or "3050" in self.gpu_name:
                        self.tuner.update(dict(threads=2, blocks=40, bfactor=6, bsleep=25))
                    elif "3060" in self.gpu_name:
                        self.tuner.update(dict(threads=1, blocks=44, bfactor=5, bsleep=15))
                    elif "3070" in self.gpu_name or "3080" in self.gpu_name:
                        self.tuner.update(dict(threads=2, blocks=56, bfactor=5, bsleep=20))
                    elif "1660" in self.gpu_name:
                        self.tuner.update(dict(threads=2, blocks=40, bfactor=6, bsleep=20))
                    elif self.vram_mb >= 16000:
                        self.tuner.update(dict(threads=2, blocks=72, bfactor=4, bsleep=10))
                    elif self.vram_mb >= 12000:
                        self.tuner.update(dict(threads=2, blocks=64, bfactor=5, bsleep=12))
                    elif self.vram_mb >= 8000:
                        self.tuner.update(dict(threads=2, blocks=48, bfactor=5, bsleep=15))
                    elif self.vram_mb >= 6000:
                        self.tuner.update(dict(threads=2, blocks=40, bfactor=6, bsleep=20))
                    else:
                        self.tuner.update(dict(threads=1, blocks=32, bfactor=6, bsleep=30))

                for sensor in hardware.Sensors:
                    if sensor.SensorType == SensorType.Temperature and "cpu" in str(hardware.HardwareType).lower():
                        self._cpu_temp_sensors.append(sensor)
                    elif sensor.SensorType == SensorType.Power:
                        self._power_sensors.append(sensor)
                for subhardware in hardware.SubHardware:
                    subhardware.Update()
                    for sensor in subhardware.Sensors:
                        if sensor.SensorType == SensorType.Power and sensor.Value is not None:
                            self._power_sensors.append(sensor)

            self._unique_hardware = {s.Hardware for s in self._cpu_temp_sensors + self._power_sensors}
            self.logger.log_message("[+] Hardware monitor initialized successfully.")
            if self.has_nvidia_gpu:
                self.logger.log_message("[+] NVIDIA GPU detected by hardware monitor.")
            return True
        except Exception as e:
            self.logger.log_message(f"[!] Critical error during hardware monitor initialization: {e}")
            self._close()
            return False

    def _close(self):
        """Safely closes the computer object to release resources."""
        if self.computer:
            try:
                self.computer.Close()
                self.logger.log_message("[+] Hardware monitor resources released.")
            except Exception as e:
                self.logger.log_message(f"[!] Error closing hardware monitor: {e}")
            finally:
                self.computer = None

    def _perform_update(self):
        """Performs one update cycle. Returns False if a critical error occurs."""
        try:
            for hardware in self._unique_hardware:
                hardware.Update()

            cpu_temps = [s.Value for s in self._cpu_temp_sensors if s.Value is not None]
            if cpu_temps:
                max_temp_c = max(cpu_temps)
                max_temp_f = (max_temp_c * 9 / 5) + 32
                self.cpu_temperature_formatted = f"{max_temp_c:.1f}°C / {max_temp_f:.1f}°F"

            power_vals = [s.Value for s in self._power_sensors if s.Value is not None]
            if power_vals:
                self.total_power_draw = f"{sum(power_vals):.2f} W"

            return True
        except Exception as e:
            self.logger.log_message(f"[!] Unrecoverable error in hardware monitor update: {e}")
            self.logger.log_message("[!] The hardware monitor will now attempt to restart.")
            return False

    def run(self):
        """The main self-healing loop for the monitoring thread."""
        # Initial initialization attempt
        if not self._initialize():
            # If it fails right away, wait before entering the main loop
            self._stop_event.wait(30)

        while not self._stop_event.is_set():
            if self.computer is None:
                if not self._initialize():
                    self._stop_event.wait(30)
                    continue

            if not self._perform_update():
                self._close()
                self._stop_event.wait(15)
                continue

            self._stop_event.wait(2)

        # Final cleanup once the stop event is set
        self._close()

    def stop(self):
        """Signals the thread to stop."""
        self._stop_event.set()

    def deinitialize(self):
        """Public method to stop and clean up the hardware monitor thread."""
        self.logger.log_message("[*] Deinitializing hardware monitor...")
        self.stop()
        self.join(timeout=5)  # Ensure cleanup finishes
        self.logger.log_message("[+] Hardware monitor shut down cleanly.")

    def get_max_power_draw(self):
        """
        Attempts to find the CPU's power limit from sensors.
        If not found, falls back to a heuristic based on the CPU name.
        Returns an integer value in Watts.
        """
        if not self.computer:
            self.logger.log_message("[!] Cannot get max power draw: Hardware monitor not initialized.")
            return 125  # Return a safe default if not initialized

        # --- Fallback Method: Heuristic based on CPU name ---
        cpu_name = ""
        try:
            for hardware in self.computer.Hardware:
                if "cpu" in str(hardware.HardwareType).lower():
                    cpu_name = hardware.Name.lower()
                    break
        except Exception:
            # If LHM fails, try cpuinfo as a backup
            try:
                import cpuinfo
                cpu_name = cpuinfo.get_cpu_info().get('brand_raw', '').lower()
            except Exception as e:
                self.logger.log_message(f"[!] Could not determine CPU name for power heuristic: {e}")
                return 125 # Fallback to default

        self.logger.log_message(f"[*] No power limit sensor found. Using heuristic for CPU: '{cpu_name}'")

        if "i9" in cpu_name or "ryzen 9" in cpu_name:
            return 170
        if "i7" in cpu_name or "ryzen 7" in cpu_name:
            return 120
        if "i5" in cpu_name or "ryzen 5" in cpu_name:
            return 80
        if "i3" in cpu_name or "ryzen 3" in cpu_name:
            return 45

        self.logger.log_message("[!] CPU model not recognized for power heuristic, returning default.")
        return 125 # Default for unknown CPUs


class XmrigData:
    def __init__(self, Logger):
        self.xmrig_process = None
        self.output_queue = asyncio.Queue()
        self.FLASK_SERVER_URL = None
        self.client_id = None
        self.miner_lock = asyncio.Lock()
        self.last_known_pool_url = None
        self.last_known_thread_count = None
        self.custom_pool_url = None
        self.client_status = "Stopped"
        self.threads = None
        self.aiohttp_client_session = None
        self._latest_hashrate = 0.0
        self._latest_cpu_accepted_shares = 0
        self._latest_nvidia_accepted_shares = 0
        self._latest_gpu_temp = "N/A"
        self._latest_gpu_fan = "N/A"
        self.XMRIG_PATH = os.path.join(os.path.dirname(sys.executable), "xmrig.exe")
        self.CONFIG_PATH = os.path.join(os.path.dirname(sys.executable), "config.json")
        self.logger = Logger

        self.hardware_monitor = HardwareMonitor(self.logger)
        self.process_manager = ProcessManager(self.logger)
        self.msr_manager = MSRManager(self.logger)

    async def get_power_draw_async(self):
        """Async wrapper to get total power draw from the monitor thread."""
        if self.hardware_monitor:
            return self.hardware_monitor.total_power_draw
        return "N/A"

    async def get_cpu_temperature_async(self):
        """Async wrapper to get CPU temperature from the monitor thread."""
        if self.hardware_monitor:
            return self.hardware_monitor.cpu_temperature_formatted
        return "N/A"

    async def has_nvidia_gpu_async(self):
        """Async wrapper to check if an NVIDIA GPU was detected."""
        if self.hardware_monitor:
            return self.hardware_monitor.has_nvidia_gpu
        return False

