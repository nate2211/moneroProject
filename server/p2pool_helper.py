from __future__ import annotations

import asyncio
import ctypes
import os
import queue
import threading
import time
import traceback
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
        self._router_manager_lock = threading.RLock()
        self._router_manager_last_error = ""
        self._router_manager_attempts = 0
        self.process_manager = None

    def set_asyncio_main_loop(self, loop):
        self.asyncio_main_loop = loop

    def ensure_router_manager(self, router_logger=None):
        """Create and publish PythonRouterManager exactly once.

        Construction is protected by a lock because the asyncio startup thread and
        the Qt Start Router worker may race.  A failed attempt is logged and may be
        retried later without terminating the main application worker.
        """
        current = self.router_manager
        if current is not None:
            return current

        with self._router_manager_lock:
            if self.router_manager is not None:
                return self.router_manager
            logger = router_logger or self.router_logger or self.logger
            self._router_manager_attempts += 1
            attempt = self._router_manager_attempts
            try:
                from p2pool_managers import PythonRouterManager
                manager = PythonRouterManager(logger)
                self.router_manager = manager
                self.packet_manager.router = manager
                self._router_manager_last_error = ""
                if self.process_manager is not None:
                    try:
                        self.process_manager.bind_router(manager)
                    except Exception as exc:
                        logger.log_message(
                            f"[Main] ⚠️ Router created but ProcessManager binding failed: {exc}"
                        )
                try:
                    logger.log_message(
                        f"[Main] ✅ Router manager ready (attempt {attempt})."
                    )
                except Exception:
                    pass
                return manager
            except Exception as exc:
                self._router_manager_last_error = (
                    f"{type(exc).__name__}: {exc}"
                )
                detail = traceback.format_exc()
                try:
                    logger.log_message(
                        f"[Main] ❌ Router manager initialization failed on attempt {attempt}: "
                        f"{self._router_manager_last_error}\n{detail}"
                    )
                except Exception:
                    print(detail)
                return None

    def router_manager_status(self):
        return {
            "available": self.router_manager is not None,
            "attempts": int(self._router_manager_attempts),
            "last_error": self._router_manager_last_error,
        }

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
        if self.router_manager is not None:
            self.process_manager.bind_router(self.router_manager)
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
            self.router_manager.router_logger = router_logger
        if self.process_manager is not None:
            self.process_manager.router_logger = router_logger

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
    NativePacketCallback = ctypes.CFUNCTYPE(None, ctypes.c_void_p, ctypes.c_size_t)

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

        # Native/C++ process-output packet bridge. Producers never block the
        # process or the router; the oldest packet is evicted under pressure.
        self.router_manager = getattr(helper, "router_manager", None)
        self.router_logger = getattr(helper, "router_logger", logger)
        self._packet_queue: "queue.Queue[dict]" = queue.Queue(maxsize=8192)
        self._packet_thread = None
        self._native_callbacks = {}
        self._packet_stats = {
            "received": 0, "queued": 0, "routed": 0, "dropped": 0,
            "errors": 0, "bytes": 0,
        }
        self._packet_routing_enabled = threading.Event()
        self._packet_routing_enabled.set()
        self._native_sources = []

    def bind_router(self, router_manager) -> None:
        feed = getattr(router_manager, "feed_interface_packet", None)
        enqueue = getattr(router_manager, "enqueue_ingress_packet", None)
        if router_manager is None or not (callable(feed) or callable(enqueue)):
            raise ValueError("ProcessManager requires a router packet ingress method.")
        self.router_manager = router_manager
        try:
            self.router_logger = getattr(router_manager, "router_logger", self.router_logger)
            setattr(router_manager, "_process_manager_bridge", self)
        except Exception:
            pass
        self.resume_router_packets(router_manager)

    def _discover_native_sources(self):
        router = self.router_manager or getattr(self.helper, "router_manager", None)
        if router is None:
            return []
        return [
            (getattr(router, "process_packet_tap", None), "ProcessPacketTap.dll"),
            (getattr(router, "parallel_python", None), "ParallelPython.dll"),
        ]

    def _bind_native_sources(self) -> None:
        self._native_sources = []
        for source_obj, source_name in self._discover_native_sources():
            setter = getattr(source_obj, "set_packet_callback", None)
            if not callable(setter):
                continue
            try:
                try:
                    setter(self.submit_process_packet, source=source_name, pid=None)
                except TypeError:
                    setter(self.submit_process_packet)
                self._native_sources.append((source_obj, source_name))
            except Exception:
                self._packet_stats["errors"] += 1

    def _detach_native_sources(self) -> None:
        sources = list(self._native_sources) or self._discover_native_sources()
        for source_obj, _source_name in sources:
            setter = getattr(source_obj, "set_packet_callback", None)
            if callable(setter):
                try:
                    setter(None)
                except Exception:
                    pass
            detach = getattr(source_obj, "detach_packet_callback", None)
            if callable(detach):
                try:
                    detach()
                except Exception:
                    pass
        self._native_sources = []

    def _discard_packet_queue(self) -> int:
        dropped = 0
        while True:
            try:
                self._packet_queue.get_nowait()
                dropped += 1
            except queue.Empty:
                break
            except Exception:
                break
        if dropped:
            self._packet_stats["dropped"] += dropped
        return dropped

    def pause_router_packets(self) -> None:
        self._packet_routing_enabled.clear()
        self._detach_native_sources()
        self._discard_packet_queue()

    def resume_router_packets(self, router_manager=None) -> None:
        if router_manager is not None:
            self.router_manager = router_manager
        self._packet_routing_enabled.set()
        self._bind_native_sources()

    @staticmethod
    def _coerce_native_packet(payload, length: Optional[int] = None):
        if payload is None:
            return None
        raw_length = getattr(length, "value", length)
        try:
            normalized_length = int(raw_length) if raw_length is not None else None
        except Exception:
            normalized_length = None
        if isinstance(payload, bytes):
            return payload[:normalized_length] if normalized_length is not None else payload
        if isinstance(payload, (bytearray, memoryview)):
            data = bytes(payload)
            return data[:normalized_length] if normalized_length is not None else data
        if isinstance(payload, (list, tuple)):
            try:
                data = bytes(payload)
                return data[:normalized_length] if normalized_length is not None else data
            except Exception:
                return payload
        pointer_value = payload if isinstance(payload, int) else getattr(payload, "value", None)
        if isinstance(pointer_value, int) and pointer_value and normalized_length and normalized_length > 0:
            # Intended for ctypes callbacks from trusted bundled C/C++ helpers.
            return ctypes.string_at(pointer_value, normalized_length)
        return payload

    def submit_process_packet(
            self, payload, length: Optional[int] = None, *, source: str = "NativeProcessDLL",
            pid: Optional[int] = None, metadata: Optional[dict] = None,
    ) -> bool:
        if self._stop_event.is_set() or not self._packet_routing_enabled.is_set():
            self._packet_stats["dropped"] += 1
            return False
        packet = self._coerce_native_packet(payload, length)
        if packet is None:
            return False
        try:
            size = len(bytes(packet))
        except Exception:
            try:
                size = len(packet)
            except Exception:
                size = 0
        item = {
            "packet": packet, "source": str(source or "NativeProcessDLL"),
            "pid": int(pid) if pid is not None else None,
            "metadata": dict(metadata or {}), "ts": time.time(), "size": int(size),
        }
        self._packet_stats["received"] += 1
        self._packet_stats["bytes"] += int(size)
        try:
            self._packet_queue.put_nowait(item)
            self._packet_stats["queued"] += 1
            return True
        except queue.Full:
            try:
                self._packet_queue.get_nowait()
                self._packet_stats["dropped"] += 1
                self._packet_queue.put_nowait(item)
                self._packet_stats["queued"] += 1
                return True
            except Exception:
                self._packet_stats["dropped"] += 1
                return False

    # Compatibility aliases for native DLL wrappers and ProcessTab callers.
    submit_native_packet = submit_process_packet
    submit_packet = submit_process_packet

    def make_native_packet_callback(self, source: str = "NativeProcessDLL", pid: Optional[int] = None):
        def _callback(payload, length=None, **callback_fields):
            callback_source = str(callback_fields.pop("source", source) or source)
            callback_pid = callback_fields.pop("pid", pid)
            callback_metadata = callback_fields.pop("metadata", None)
            metadata = dict(callback_metadata or {})
            metadata.update(callback_fields)
            return self.submit_process_packet(
                payload,
                length,
                source=callback_source,
                pid=callback_pid,
                metadata=metadata,
            )
        self._native_callbacks[str(source)] = _callback
        return _callback

    def make_ctypes_packet_callback(self, source: str = "NativeProcessDLL", pid: Optional[int] = None):
        @self.NativePacketCallback
        def _callback(payload_ptr, payload_length):
            self.submit_process_packet(
                payload_ptr, payload_length, source=source, pid=pid,
                metadata={"callback_abi": "void_ptr_size_t"},
            )
        self._native_callbacks[f"{source}:ctypes"] = _callback
        return _callback

    def register_native_packet_source(self, source_obj, *, source: str = "NativeProcessDLL", pid: Optional[int] = None) -> bool:
        callback = self.make_native_packet_callback(source=source, pid=pid)
        for method_name in (
                "set_packet_callback", "register_packet_callback",
                "add_packet_callback", "set_output_callback",
        ):
            method = getattr(source_obj, method_name, None)
            if not callable(method):
                continue
            try:
                method(callback)
            except (TypeError, ctypes.ArgumentError):
                native_callback = self.make_ctypes_packet_callback(source=source, pid=pid)
                method(native_callback)
            return True
        return False

    def _router_log(self, message: str) -> None:
        target = self.router_logger or self.logger
        try:
            target.log_message(str(message))
        except Exception:
            try:
                self.logger.log_message(str(message))
            except Exception:
                pass

    def _packet_loop(self) -> None:
        while not self._stop_event.is_set():
            try:
                item = self._packet_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if self._stop_event.is_set() or not self._packet_routing_enabled.is_set():
                self._packet_stats["dropped"] += 1
                continue
            try:
                router = self.router_manager or getattr(self.helper, "router_manager", None)
                if router is None:
                    self._packet_stats["dropped"] += 1
                    continue
                packet = item["packet"]
                metadata = dict(item.get("metadata") or {})
                metadata.update({
                    "source": item["source"],
                    "producer": item["source"],
                    "pid": item.get("pid"),
                    "capture_ts": item.get("ts"),
                    "native_process_output": True,
                    "interface_name": "ProcessInterface",
                    "component": "process-output-dll",
                    "path_stage": "router-ingress",
                })
                try:
                    setattr(packet, "_process_interface_packet", True)
                    setattr(packet, "_process_interface_pid", item.get("pid"))
                    setattr(packet, "_process_interface_metadata", metadata)
                    setattr(packet, "_router_ingress_owner", "ProcessManager")
                except Exception:
                    pass

                feed = getattr(router, "feed_interface_packet", None)
                if callable(feed):
                    accepted = bool(feed(
                        packet, "ProcessInterface", metadata=metadata,
                        owner="ProcessManager",
                    ))
                else:
                    accepted = bool(router.enqueue_ingress_packet(packet, "ProcessInterface"))
                self._packet_stats["routed"] += int(accepted)
                if not accepted:
                    self._packet_stats["dropped"] += 1
            except Exception:
                self._packet_stats["errors"] += 1

    def packet_stats(self) -> dict:
        out = dict(self._packet_stats)
        out.update({"queue": self._packet_queue.qsize(), "queue_max": self._packet_queue.maxsize})
        return out

    def _manual_stop_latched(self) -> bool:
        try:
            return bool(self.p2pool_processor.manual_stop_latched())
        except Exception:
            return False

    def start(self):
        if self.asyncio_loop is None:
            raise RuntimeError("ProcessManager requires a valid asyncio loop.")
        if self._monitor_thread and self._monitor_thread.is_alive():
            self.resume_router_packets(self.router_manager or getattr(self.helper, "router_manager", None))
            return
        self._stop_event.clear()
        router = self.router_manager or getattr(self.helper, "router_manager", None)
        if router is not None:
            self.bind_router(router)
        if self._packet_thread is None or not self._packet_thread.is_alive():
            self._packet_thread = threading.Thread(
                target=self._packet_loop, daemon=True, name="ProcessNativePacketRouter",
            )
            self._packet_thread.start()

        self._current_ip = self.helper.get_public_ip()
        self._public_ip_missing = self._current_ip is None
        self.logger.log_message(f"[ProcessManager] Initial public IP: {self._current_ip}")

        self._monitor_thread = threading.Thread(
            target=self._monitor_loop, daemon=True, name="P2Pool-IP-Monitor",
        )
        self._monitor_thread.start()

    def stop(self):
        if self._stop_event.is_set() and not (
            (self._monitor_thread and self._monitor_thread.is_alive())
            or (self._packet_thread and self._packet_thread.is_alive())
        ):
            return
        self._stop_event.set()
        self.pause_router_packets()
        self.logger.log_message("[ProcessManager] Stopping background workers...")
        for thread in (self._monitor_thread, self._packet_thread):
            if thread and thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=3.0)
        self._monitor_thread = None
        self._packet_thread = None
        self.logger.log_message(f"[ProcessManager] Stopped. stats={self.packet_stats()}")

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