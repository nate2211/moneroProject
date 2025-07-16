import asyncio
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

