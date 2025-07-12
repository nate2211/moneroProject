import asyncio
import sys
import clr
import json
import os

import asyncio
import sys
import clr
import json
import os
import time
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
    """

    def __init__(self, logger):
        super().__init__(daemon=True)
        self.logger = logger
        self._stop_event = Event()

        # Public attributes to hold the latest data
        self.cpu_temperature_formatted = "N/A"
        self.total_power_draw = "N/A"

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

            # Clear previous sensor lists to prevent duplicates
            self._cpu_temp_sensors.clear()
            self._power_sensors.clear()
            self._unique_hardware.clear()

            # Find sensors and their parent hardware
            for hardware in self.computer.Hardware:
                hardware.Update()
                for sensor in hardware.Sensors:
                    if sensor.SensorType == SensorType.Temperature and "cpu" in str(hardware.HardwareType).lower():
                        self._cpu_temp_sensors.append(sensor)
                    elif sensor.SensorType == SensorType.Power and sensor.Value is not None:
                        self._power_sensors.append(sensor)
                for subhardware in hardware.SubHardware:
                    subhardware.Update()
                    for sensor in subhardware.Sensors:
                        if sensor.SensorType == SensorType.Power and sensor.Value is not None:
                            self._power_sensors.append(sensor)

            self._unique_hardware = {s.Hardware for s in self._cpu_temp_sensors + self._power_sensors}
            self.logger.log_message("[+] Hardware monitor initialized successfully.")
            return True
        except Exception as e:
            self.logger.log_message(f"[!] Critical error during hardware monitor initialization: {e}")
            self._close()  # Ensure we clean up even if init fails
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
            # Update each unique hardware object ONCE to prevent race conditions
            for hardware in self._unique_hardware:
                hardware.Update()

            # Read sensor values now that hardware is updated
            cpu_temps = [s.Value for s in self._cpu_temp_sensors if s.Value is not None]
            if cpu_temps:
                max_temp_c = max(cpu_temps)
                max_temp_f = (max_temp_c * 9 / 5) + 32
                self.cpu_temperature_formatted = f"{max_temp_c:.1f}°C / {max_temp_f:.1f}°F"

            power_vals = [s.Value for s in self._power_sensors if s.Value is not None]
            if power_vals:
                self.total_power_draw = f"{sum(power_vals):.2f} W"

            return True  # Success
        except Exception as e:
            # A NullReferenceException from the DLL will be caught here
            self.logger.log_message(f"[!] Unrecoverable error in hardware monitor update: {e}")
            self.logger.log_message("[!] The hardware monitor will now attempt to restart.")
            return False  # Failure

    def run(self):
        """The main self-healing loop for the monitoring thread."""
        while not self._stop_event.is_set():
            if self.computer is None:
                # Attempt to initialize if not already running
                if not self._initialize():
                    # If initialization fails, wait 30 seconds before retrying
                    self._stop_event.wait(30)
                    continue

            # Perform the update; if it fails, the loop will cycle and trigger re-initialization.
            if not self._perform_update():
                self._close()
                # Wait 15 seconds after a crash before trying to restart
                self._stop_event.wait(15)
                continue

            # On success, wait the normal 2-second interval
            self._stop_event.wait(2)

    def stop(self):
        """Signals the thread to stop and cleans up resources."""
        self._stop_event.set()
        self._close()
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
        self._latest_cpu_temp = "N/A"
        self._latest_power_draw_value = "N/A"
        self.XMRIG_PATH = os.path.join(os.getcwd(), "xmrig.exe")
        self.CONFIG_PATH = os.path.join(os.getcwd(), "config.json")
        self.logger = Logger
        self.hardware_monitor = HardwareMonitor(self.logger)
        self.hardware_monitor.start()
    async def get_power_draw_async(self):
        """Wrapper to run synchronous get_power_draw in a separate thread."""
        return self.hardware_monitor.total_power_draw


    async def get_cpu_temperature_async(self):
        """Wrapper to run synchronous get_cpu_temperature_lhm in a separate thread."""
        return self.hardware_monitor.cpu_temperature_formatted

    def check_nvidia_gpu_sync(self):
        """
        Synchronous function to check for NVIDIA GPU using LibreHardwareMonitorLib.
        """
        try:
            c = Computer()
            c.IsCpuEnabled = False
            c.IsGpuEnabled = True
            c.Open()

            found_nvidia = False
            for hardware in c.Hardware:
                if "nvidia" in str(hardware.HardwareType).lower():
                    found_nvidia = True
                    break
            c.Close()
            return found_nvidia
        except Exception as e:
            self.logger.log_message(f"[!] Error checking for NVIDIA GPU: {e}")
            return False
