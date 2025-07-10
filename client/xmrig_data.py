import asyncio
import sys
import clr
import json
import os

try:
    clr.AddReference("LibreHardwareMonitorLib")
except Exception as e:
    print(f"[!] Could not load LibreHardwareMonitorLib: {e}")
    sys.exit(1)

from LibreHardwareMonitor.Hardware import Computer, HardwareType, SensorType

class XmrigData:
    def __init__(self):
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

    async def get_power_draw_async(self):
        """Wrapper to run synchronous get_power_draw in a separate thread."""
        return await asyncio.to_thread(self.get_power_draw_sync)

    def get_power_draw_sync(self):
        """
        Synchronous function to get total power draw using LibreHardwareMonitorLib.
        This function is intended to be run in a separate thread via asyncio.to_thread.
        """
        try:
            c = Computer()
            c.IsCpuEnabled = True
            c.IsGpuEnabled = True
            c.IsMemoryEnabled = True
            c.IsMotherboardEnabled = True
            c.IsControllerEnabled = True
            c.IsNetworkEnabled = True
            c.IsStorageEnabled = True
            c.Open()

            total_power_draw = 0.0
            found_power_sensor = False

            for hardware in c.Hardware:
                # --- Add error handling for each piece of hardware ---
                try:
                    hardware.Update()
                except Exception as update_error:
                    print(f"[!] Could not update hardware {hardware.Name}: {update_error}")
                    continue  # Skip to the next piece of hardware
                # --------------------------------------------------------

                for sensor in hardware.Sensors:
                    if sensor.SensorType == SensorType.Power:
                        if sensor.Value is not None:
                            total_power_draw += sensor.Value
                            found_power_sensor = True

                for subhardware in hardware.SubHardware:
                    try:
                        subhardware.Update()
                    except:
                        continue  # Also skip failing sub-hardware

                    for sensor in subhardware.Sensors:
                        if sensor.SensorType == SensorType.Power and sensor.Value is not None:
                            total_power_draw += sensor.Value
                            found_power_sensor = True

            c.Close()
            return round(total_power_draw, 2) if found_power_sensor else "N/A"

        except Exception as e:
            print(f"[!] Power draw error: {e}")
            return "N/A"

    async def get_cpu_temperature_async(self):
        """Wrapper to run synchronous get_cpu_temperature_lhm in a separate thread."""
        return await asyncio.to_thread(self.get_cpu_temperature_lhm_sync)

    def get_cpu_temperature_lhm_sync(self):
        """
        Gets CPU temperatures using LibreHardwareMonitorLib.
        Opens Computer, reads CPU temperature sensors, and closes Computer.
        Returns the maximum observed CPU core temperature.
        """
        try:
            c = Computer()
            c.IsCpuEnabled = True  # Only enable CPU for CPU temp reading
            c.Open()

            cpu_temperatures = []
            for hardware in c.Hardware:
                if hardware.HardwareType == HardwareType.Cpu:
                    # Add error handling around the Update() call
                    try:
                        hardware.Update()
                    except Exception as update_error:
                        print(f"[!] Could not update CPU hardware {hardware.Name}: {update_error}", file=sys.stderr)
                        continue  # Skip this faulty hardware component

                    for sensor in hardware.Sensors:
                        if sensor.SensorType == SensorType.Temperature and sensor.Value is not None:
                            cpu_temperatures.append(sensor.Value)
            c.Close()

            if not cpu_temperatures:
                return "N/A"

            max_temp_celsius = max(cpu_temperatures)
            max_temp_fahrenheit = (max_temp_celsius * 9 / 5) + 32

            return f"{max_temp_celsius:.1f}°C / {max_temp_fahrenheit:.1f}°F"

        except Exception as e:
            print(f"[!] Error getting CPU temp via LibreHardwareMonitorLib: {e}", file=sys.stderr)
            return "N/A"

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
            print(f"[!] Error checking for NVIDIA GPU: {e}")
            return False
