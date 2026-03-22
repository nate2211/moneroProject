from __future__ import annotations

import asyncio
import os
import threading
from socket import AF_INET, SOCK_DGRAM, socket
from typing import Optional

import psutil
import requests

from p2pool_data import P2poolData, EventProcessor, RawLogProcessor, P2PoolProcessor
from client_data import ClientData
from p2pool_managers import WiresharkManager, PacketManager


class _PrintLogger:
    def log_message(self, msg):
        print(str(msg))


class _PrintNetworkLogger:
    def log_message(self, msg):
        print(f"[Net] {str(msg)}")


class P2PoolHelper:
    def __init__(self):
        self.ELECTRICITY_RATE_PER_KWH = 0.13
        self.COMMAND_QUEUE = {}
        self.asyncio_main_loop = None

        self.logger = _PrintLogger()
        self.wireshark_logger = _PrintNetworkLogger()
        self.packet_logger = _PrintLogger()
        self.router_logger = _PrintLogger()

        self.p2pool_stop_event = threading.Event()

        self.p2pooldata = P2poolData(self.logger)
        self.clientdata = ClientData(self.logger)
        self.event_processor = EventProcessor(self.p2pooldata, self.logger, self.p2pool_stop_event)
        self.raw_log_processor = RawLogProcessor(self.p2pooldata, self.logger, self.p2pool_stop_event)
        self.processor = P2PoolProcessor(self.p2pooldata, self.logger, self.p2pool_stop_event)

        self.wireshark_manager = WiresharkManager(self.p2pooldata, self.wireshark_logger)
        self.packet_manager = PacketManager(self.packet_logger)
        self.router_manager = None
        self.process_manager = None

    def set_asyncio_main_loop(self, loop):
        self.asyncio_main_loop = loop

    def create_process_manager(self, flask_restart_callback=None, asyncio_main_loop=None):
        if asyncio_main_loop is not None:
            self.asyncio_main_loop = asyncio_main_loop

        if self.asyncio_main_loop is None:
            raise RuntimeError("asyncio_main_loop must be set before creating ProcessManager.")

        self.process_manager = ProcessManager(
            helper=self,
            p2pool_data=self.p2pooldata,
            flask_restart_callback=flask_restart_callback,
            p2pool_processor=self.processor,
            logger=self.logger,
            asyncio_loop=self.asyncio_main_loop,
        )
        return self.process_manager

    def set_p2pool_stop_event(self, stop_event):
        self.p2pool_stop_event = stop_event
        self.event_processor.stop_event = self.p2pool_stop_event
        self.raw_log_processor.stop_event = self.p2pool_stop_event
        self.processor.stop_event = self.p2pool_stop_event

    def set_gui_logger(self, gui_logger):
        print("[+] GUI Logger activated.")
        self.logger = gui_logger
        self.p2pooldata.logger = gui_logger
        self.clientdata.logger = gui_logger
        self.event_processor.logger = gui_logger
        self.raw_log_processor.logger = gui_logger
        self.processor.logger = gui_logger
        if self.process_manager is not None:
            self.process_manager.logger = gui_logger

    def set_wireshark_logger(self, wireshark_logger):
        print("[+] GUI Network Logger activated.")
        self.wireshark_logger = wireshark_logger
        self.wireshark_manager.logger = wireshark_logger

    def set_packet_logger(self, packet_logger):
        print("[+] GUI Packet Logger activated.")
        self.packet_logger = packet_logger
        self.packet_manager.logger = packet_logger

    def set_router_logger(self, router_logger):
        print("[+] GUI Router Logger activated.")
        self.router_logger = router_logger
        if self.router_manager is not None:
            self.router_manager.logger = router_logger

    def queue_command(self, client_id, command_data):
        if client_id not in self.COMMAND_QUEUE:
            self.COMMAND_QUEUE[client_id] = []
        self.COMMAND_QUEUE[client_id].append(command_data)
        self.logger.log_message(f"[+] Queued command for '{client_id}': {command_data}")

    def clear_file_contents(self, filepath):
        try:
            os.makedirs(os.path.dirname(filepath), exist_ok=True)
            with open(filepath, "w", encoding="utf-8") as f:
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

    def get_public_ip(self) -> Optional[str]:
        services = (
            ("https://api.ipify.org?format=json", lambda r: (r.json() or {}).get("ip")),
            ("https://api64.ipify.org?format=json", lambda r: (r.json() or {}).get("ip")),
        )

        last_error = None
        headers = {"User-Agent": "P2PoolHelper/1.0"}

        for url, extractor in services:
            try:
                response = requests.get(url, timeout=5, headers=headers)
                response.raise_for_status()
                ip = extractor(response)
                if ip:
                    return ip
            except requests.exceptions.RequestException as e:
                last_error = e
            except Exception as e:
                last_error = e

        self.logger.log_message(f"[IP Check] Could not get public IP: {last_error}")
        return None

    def get_local_ip(self) -> str:
        interfaces = psutil.net_if_addrs()
        stats = psutil.net_if_stats()

        for interface_name, addresses in interfaces.items():
            nic_stats = stats.get(interface_name)
            if not nic_stats or not nic_stats.isup:
                continue

            lower_name = interface_name.lower()
            if any(v in lower_name for v in ["protonvpn", "vpn", "zerotier", "tunnel", "loopback", "virtual"]):
                continue

            if not any(w in lower_name for w in ["wi-fi", "wifi", "wlan", "wireless", "ethernet", "eth"]):
                continue

            for addr in addresses:
                if addr.family == AF_INET and addr.address and not addr.address.startswith("127."):
                    return addr.address

        try:
            s = socket(AF_INET, SOCK_DGRAM)
            s.connect(("10.255.255.255", 1))
            ip = s.getsockname()[0]
        except Exception:
            ip = "127.0.0.1"
        finally:
            try:
                s.close()
            except Exception:
                pass

        return ip


class ProcessManager:
    """
    Watches for public IP transitions and restarts only P2Pool.

    Flask stays in-process and must not be restarted, otherwise the frontend loses
    access to the live shared p2pool_helper state.
    """

    def __init__(
        self,
        helper: P2PoolHelper,
        p2pool_data,
        flask_restart_callback,
        p2pool_processor: P2PoolProcessor,
        logger,
        asyncio_loop,
        monitor_interval: int = 10,
        required_confirmations: int = 2,
    ):
        self.helper = helper
        self.p2pool_data = p2pool_data
        self.flask_restart_callback = flask_restart_callback
        self.p2pool_processor = p2pool_processor
        self.logger = logger
        self.asyncio_loop = asyncio_loop

        self.monitor_interval = max(2, int(monitor_interval))
        self.required_confirmations = max(1, int(required_confirmations))

        self._monitor_thread = None
        self._stop_event = threading.Event()
        self._restart_lock = threading.Lock()

        self._current_ip = None
        self._pending_ip = None
        self._pending_hits = 0
        self._public_ip_missing = False
        self._last_restart_reason = None

    def _manual_stop_latched(self) -> bool:
        try:
            return bool(self.p2pool_processor.manual_stop_latched())
        except Exception:
            return False

    def start(self):
        if self.asyncio_loop is None:
            raise RuntimeError("ProcessManager requires a valid asyncio loop.")

        self._current_ip = self.helper.get_public_ip()
        self._public_ip_missing = self._current_ip is None
        self.logger.log_message(f"[ProcessManager] Initial public IP: {self._current_ip}")

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            daemon=True,
            name="P2Pool-IP-Monitor",
        )
        self._monitor_thread.start()

    def stop(self):
        self._stop_event.set()
        self.logger.log_message("[ProcessManager] Stopping IP monitor...")
        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=3)

    def _monitor_loop(self):
        while not self._stop_event.wait(self.monitor_interval):
            try:
                current_ip = self.helper.get_public_ip()

                if self._manual_stop_latched():
                    self._pending_ip = None
                    self._pending_hits = 0
                    if current_ip:
                        self._current_ip = current_ip
                        self._public_ip_missing = False
                    else:
                        self._public_ip_missing = True
                    continue

                if not current_ip:
                    if not self._public_ip_missing:
                        self.logger.log_message(
                            f"[ProcessManager] Public IP became unavailable. Last known IP was {self._current_ip}."
                        )
                    self._public_ip_missing = True
                    self._pending_ip = None
                    self._pending_hits = 0
                    continue

                restart_needed = self._public_ip_missing or (current_ip != self._current_ip)
                if not restart_needed:
                    self._pending_ip = None
                    self._pending_hits = 0
                    self._public_ip_missing = False
                    continue

                if self._pending_ip != current_ip:
                    self._pending_ip = current_ip
                    self._pending_hits = 1
                    self.logger.log_message(
                        f"[ProcessManager] Observed candidate public IP transition: {self._current_ip} -> {current_ip}"
                    )
                    continue

                self._pending_hits += 1
                if self._pending_hits < self.required_confirmations:
                    continue

                if not self._restart_lock.acquire(blocking=False):
                    continue

                old_ip = self._current_ip
                new_ip = current_ip
                reason = "public_ip_reacquired" if self._public_ip_missing else "public_ip_changed"

                try:
                    self.logger.log_message(
                        f"[ProcessManager] Confirmed public IP transition: {old_ip} -> {new_ip} ({reason})"
                    )

                    fut = asyncio.run_coroutine_threadsafe(
                        self._restart_services(old_ip, new_ip, reason),
                        self.asyncio_loop,
                    )
                    restart_ok = fut.result(timeout=180)

                    if restart_ok:
                        self._current_ip = new_ip
                        self._public_ip_missing = False
                        self._last_restart_reason = reason
                        self.logger.log_message(
                            f"[ProcessManager] P2Pool restart completed successfully for IP transition {old_ip} -> {new_ip}."
                        )
                    else:
                        self.logger.log_message(
                            f"[ProcessManager] P2Pool restart failed for IP transition {old_ip} -> {new_ip}."
                        )
                except Exception as e:
                    self.logger.log_message(f"[ProcessManager] Restart workflow error: {e}")
                finally:
                    self._pending_ip = None
                    self._pending_hits = 0
                    self._restart_lock.release()

            except Exception as e:
                self.logger.log_message(f"[ProcessManager] Error in monitor loop: {e}")

    async def _restart_services(self, old_ip, new_ip, reason) -> bool:
        if self._manual_stop_latched():
            self.logger.log_message(
                f"[ProcessManager] Skipping P2Pool restart because manual stop latch is active ({reason})."
            )
            return False

        self.logger.log_message(
            f"[ProcessManager] Restarting P2Pool because {reason}: {old_ip} -> {new_ip}"
        )

        try:
            await self.p2pool_processor.stop_p2pool(reason=f"{reason}:{old_ip}->{new_ip}")
        except Exception as e:
            self.logger.log_message(f"[ProcessManager] Error while stopping P2Pool: {e}")

        start_ok = await self.p2pool_processor.start_p2pool()
        if not start_ok:
            self.logger.log_message("[ProcessManager] Failed to restart P2Pool.")
            return False

        return True


p2pool_helper = P2PoolHelper()