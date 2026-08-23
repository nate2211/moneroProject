import asyncio
import os
import sys
import time
from threading import Event, Thread

import clr
import cpuinfo

from xmrig_managers import (
    ProcessManager,
    AsyncMSRManager,
    AsyncRyzenSMUManager,
    AsyncTSharkManager,
)

try:
    clr.AddReference("LibreHardwareMonitorLib")
    from LibreHardwareMonitor.Hardware import Computer, SensorType
except Exception as e:
    print(f"[!] FATAL: Could not load LibreHardwareMonitorLib: {e}")
    sys.exit(1)


class HardwareMonitor(Thread):
    """
    Self-healing LibreHardwareMonitor thread.
    """

    def __init__(self, logger):
        super().__init__(daemon=True)
        self.logger = logger
        self._stop_event = Event()

        self.cpu_temperature_formatted = "N/A"
        self.total_power_draw = "N/A"
        self.has_nvidia_gpu = False
        self.gpu_name = None
        self.vram_mb = 0
        self.tuner = {
            "index": 0,
            "affinity": -1,
            "dataset_host": False,
        }

        self.computer = None
        self._cpu_temp_sensors = []
        self._power_sensors = []
        self._unique_hardware = set()

    def _initialize(self):
        try:
            self.logger.log_message("[+] Initializing hardware monitor...")
            self.computer = Computer()
            self.computer.IsCpuEnabled = True
            self.computer.IsGpuEnabled = True
            self.computer.Open()

            self._cpu_temp_sensors.clear()
            self._power_sensors.clear()
            self._unique_hardware.clear()
            self.has_nvidia_gpu = False
            self.gpu_name = None
            self.vram_mb = 0
            self.cpu_temperature_formatted = "N/A"
            self.total_power_draw = "N/A"

            for hardware in self.computer.Hardware:
                hardware.Update()

                if "nvidia" in str(hardware.HardwareType).lower():
                    self.has_nvidia_gpu = True
                    self.gpu_name = hardware.Name.lower()
                    hardware.Update()

                    for sensor in hardware.Sensors:
                        if sensor.SensorType == SensorType.SmallData and "memory total" in sensor.Name.lower():
                            if sensor.Value is not None:
                                self.vram_mb = int(sensor.Value)

                    self.logger.log_message(
                        f"[+] Detected GPU: {self.gpu_name}, VRAM: {self.vram_mb}MB"
                    )
                    self._apply_gpu_tuner_heuristic()

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

    def _apply_gpu_tuner_heuristic(self):
        name = self.gpu_name or ""
        if "1050" in name:
            self.tuner.update(dict(threads=1, blocks=32, bfactor=7, bsleep=30))
        elif "2060" in name or "3050" in name:
            self.tuner.update(dict(threads=2, blocks=40, bfactor=6, bsleep=25))
        elif "3060" in name:
            self.tuner.update(dict(threads=1, blocks=44, bfactor=5, bsleep=15))
        elif "3070" in name or "3080" in name:
            self.tuner.update(dict(threads=2, blocks=56, bfactor=5, bsleep=20))
        elif "1660" in name:
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

    def _close(self):
        if self.computer:
            try:
                self.computer.Close()
                self.logger.log_message("[+] Hardware monitor resources released.")
            except Exception as e:
                self.logger.log_message(f"[!] Error closing hardware monitor: {e}")
            finally:
                self.computer = None

    def _perform_update(self):
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
        if not self._initialize():
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

        self._close()

    def stop(self):
        self._stop_event.set()

    def deinitialize(self):
        self.logger.log_message("[*] Deinitializing hardware monitor...")
        self.stop()
        self.join(timeout=5)
        self.logger.log_message("[+] Hardware monitor shut down cleanly.")

    def get_max_power_draw(self):
        if not self.computer:
            self.logger.log_message("[!] Cannot get max power draw: Hardware monitor not initialized.")
            return 125

        cpu_name = ""
        try:
            for hardware in self.computer.Hardware:
                if "cpu" in str(hardware.HardwareType).lower():
                    cpu_name = hardware.Name.lower()
                    break
        except Exception:
            try:
                cpu_name = cpuinfo.get_cpu_info().get("brand_raw", "").lower()
            except Exception as e:
                self.logger.log_message(f"[!] Could not determine CPU name for power heuristic: {e}")
                return 125

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
        return 220


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
        self.wallet = ""
        self.effective_wallet = ""
        self.wallet_difficulty = 0
        self.client_status = "Stopped"
        self.threads = None
        self.aiohttp_client_session = None

        self._latest_hashrate = 0.0
        self._latest_cpu_accepted_shares = 0
        self._latest_nvidia_accepted_shares = 0
        self._latest_gpu_temp = "N/A"
        self._latest_gpu_fan = "N/A"

        # reconnect / health tracking
        self.last_pool_job_at = 0.0
        self.last_pool_error_at = 0.0
        self.last_pool_error = ""
        self.last_server_ok_at = 0.0
        self.last_server_error_at = 0.0
        self.last_server_error = ""

        root_dir = getattr(sys, "_MEIPASS", os.path.abspath(os.path.dirname(__file__)))
        self.tools_dir = os.path.join(root_dir, "tools")
        self.XMRIG_PATH = os.path.join(self.tools_dir, "xmrig.exe")
        self.CONFIG_PATH = os.path.join(self.tools_dir, "config.json")
        self.logger = Logger

        try:
            brand_raw = cpuinfo.get_cpu_info().get("brand_raw", "").lower()
        except Exception:
            brand_raw = ""
        self.brand = "intel" if "intel" in brand_raw else "ryzen"

        self.hardware_monitor = HardwareMonitor(self.logger)
        self.process_manager = ProcessManager(self.logger)
        self.msr_manager = AsyncMSRManager(self.logger)
        self.ryzen_manager = AsyncRyzenSMUManager(self.logger)
        self.winring_manager = None
        self.tshark_manager = None
        self.linux_manager = None

    async def get_power_draw_async(self):
        if self.hardware_monitor:
            return self.hardware_monitor.total_power_draw
        return "N/A"

    async def get_cpu_temperature_async(self):
        if self.hardware_monitor:
            return self.hardware_monitor.cpu_temperature_formatted
        return "N/A"

    async def has_nvidia_gpu_async(self):
        if self.hardware_monitor:
            return self.hardware_monitor.has_nvidia_gpu
        return False

    def mark_server_ok(self):
        self.last_server_ok_at = time.monotonic()
        self.last_server_error = ""

    def mark_server_error(self, message: str):
        self.last_server_error_at = time.monotonic()
        self.last_server_error = str(message or "")

    def mark_pool_error(self, message: str):
        self.last_pool_error_at = time.monotonic()
        self.last_pool_error = str(message or "")