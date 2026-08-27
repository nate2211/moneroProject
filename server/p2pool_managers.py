import asyncio
import collections
from collections import deque
import base64
import ctypes
import hashlib
import logging
import os
import platform
import socket
import string
import traceback
import uuid
import warnings
from pathlib import Path
from typing import Optional, List, Any
import geoip2.database
import geoip2.errors
import ipaddress
import re
import shutil
import subprocess
import sys
import threading
import json
import time
import psutil
import requests
from PyQt5.QtCore import QObject, pyqtSignal
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from scapy.arch import get_if_hwaddr
from scapy.compat import raw
from scapy.config import conf
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3
from scapy.contrib.ikev2 import IKEv2
from scapy.layers.dhcp import DHCP
from scapy.layers.dhcp6 import DHCP6, DHCP6_Renew, DHCP6_Solicit, DHCP6_InfoRequest, DHCP6_Reply
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import TCP, ICMP
from scapy.layers.inet6 import IPv6, ICMPv6EchoRequest, ICMPv6EchoReply, ICMPv6ND_NS, ICMPv6ND_NA, ICMPv6DestUnreach, \
    ICMPv6TimeExceeded, ICMPv6ParamProblem, IPv6ExtHdrHopByHop
from scapy.layers.ipsec import ESP, AH
from scapy.layers.isakmp import ISAKMP
from scapy.layers.l2 import Ether, GRE, ARP
from scapy.layers.tls.handshake import TLSClientHello, TLSFinished, TLSServerHello
from scapy.layers.tls.record import TLS
from scapy.packet import Packet, Raw
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict
import xml.etree.ElementTree as ET

from scapy.sendrecv import sr1, send
from scapy.sessions import TCPSession
from p2pool_sniffer import SnifferSoftware, ICMPv6
from p2pool_router_managers_2 import ARPManager, OutboundLoadBalancer, DNSManager, RIPManager, IGMPManager, \
    LinkAggregationManager, FirewallManager, DHCPServer, HandshakeManager, NATManager, mDNSManager, \
    StratumManager, StratumConnectionManager, MoneroDaemonManager, TLSRecordManager, BroadcastManager, NDPManager, \
    P2PPeerManager, NetRouteManager, HostConnectivityBoundaryManager, LanManager, GatewayManager, UplinkManager, UpstreamManager, \
    HyperVRouterManager, PeerInterfaceManager, PythonServerManager,ScrapeWebsiteManager, WifiManager
from p2pool_router_managers import PacketSigningManager, PacketWriter, SendBackManager, PacketCatcherManager, \
    ICMPManager, EthernetBridgeManager, ForwardingManager, KerberosManager, EthernetL2Manager, \
    TransportManager, SYNScanner, NotificationManager, RouterRandomMessages, FunctionCallTracker, ISAKMPManager, \
    ESPManager, SocketInterface
from p2pool_tools import ParallelPythonTool
from p2pool_hyperv import HyperVManager, WinDivertManager, WinTunManager
from p2pool_router_managers_3 import CodeOutputManager
from p2pool_pipeline import PacketPipelineBlock, create_pipeline_extras
from tools.pythontools import start_cpu_boost, stop_cpu_boost,  yield_no_gil, burn_no_gil, unhinge_process
import struct
try:
    from p2pool_ollama import install_ollama_on_router
except Exception:
    install_ollama_on_router = None


class CodeOutputInterfaceManager:
    """Own the server-side CodeOutput virtual interface.

    The interface is a real Hyper-V Internal switch created through PowerShell.
    It is registered in the router's shared interface map, RIP table, LAN transit
    set, PacketWriter view, and capture workers. PacketLab can also inject
    synthetic packets through the logical ``CodeOutput`` ingress without waiting
    for a physical frame to appear on the adapter.
    """

    LOGICAL_IFACE = "CodeOutput"
    DEFAULT_SWITCH_NAME = "CodeOutput"
    DEFAULT_ADAPTER_NAME = "CodeOutput"
    DEFAULT_IPV4 = "172.30.253.1"
    DEFAULT_PREFIX_LENGTH = 30

    def __init__(self, router_manager, logger):
        self.router_manager = router_manager
        self.logger = logger
        self._lock = threading.RLock()
        self.enabled = False
        self.remove_on_shutdown = False
        self.switch_name = self.DEFAULT_SWITCH_NAME
        self.adapter_name = self.DEFAULT_ADAPTER_NAME
        self.interface_alias = self.DEFAULT_ADAPTER_NAME
        self.interface_full_name = None
        self.interface_ipv4 = self.DEFAULT_IPV4
        self.prefix_length = self.DEFAULT_PREFIX_LENGTH
        self.network = ipaddress.ip_network(
            f"{self.interface_ipv4}/{self.prefix_length}", strict=False
        )
        self.interface_index = None
        self.interface_mac = None
        self.interface_ready = False
        self.interface_created_by_manager = False
        self.capture_started = False
        self.last_error = ""

    def _log(self, message: str) -> None:
        try:
            self.logger.log_message(str(message))
        except Exception:
            pass

    @staticmethod
    def _ps_literal(value: str) -> str:
        return str(value or "").replace("'", "''")

    @staticmethod
    def _validate_name(value: str, label: str) -> str:
        text = str(value or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9_.() '\-]{1,64}", text):
            raise ValueError(f"{label} contains unsupported characters.")
        return text

    def _run_powershell(self, script: str, *, timeout: float = 55.0):
        if os.name != "nt":
            return False, "CodeOutput interface requires Windows PowerShell.", ""
        try:
            result = subprocess.run(
                [
                    "powershell.exe", "-NoLogo", "-NoProfile", "-NonInteractive",
                    "-ExecutionPolicy", "Bypass", "-Command", script,
                ],
                capture_output=True,
                text=True,
                timeout=max(1.0, float(timeout)),
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()
            return result.returncode == 0, stderr or stdout, stdout
        except subprocess.TimeoutExpired:
            return False, "PowerShell operation timed out.", ""
        except Exception as exc:
            return False, str(exc), ""

    def bind_router(self, router_manager) -> None:
        """Bind this interface directly to the owning PythonRouterManager."""
        if router_manager is None or not callable(getattr(router_manager, "process_packet", None)):
            raise ValueError("CodeOutputInterface requires a router with process_packet().")
        self.router_manager = router_manager

    def submit_packet(self, packet, metadata: Optional[dict] = None, *, phase: str = "interface") -> dict:
        """Feed one CodeOutput packet through the router's bounded ingress queue."""
        router = self.router_manager
        ingest = getattr(router, "ingest_codeoutput_packet", None)
        if not callable(ingest):
            raise RuntimeError("CodeOutputInterface is not linked to PythonRouterManager.ingest_codeoutput_packet().")
        metadata = dict(metadata or {})
        metadata.setdefault("phase", phase)
        ingress = self.interface_full_name or self.interface_alias or self.LOGICAL_IFACE
        if phase in {"packetlab", "logical", "chat"}:
            ingress = self.LOGICAL_IFACE
        accepted = bool(ingest(
            packet,
            source_iface=ingress,
            direction=str(metadata.get("direction") or "wan-in"),
            metadata=metadata,
        ))
        return {
            "status": "QUEUED" if accepted else "REJECTED",
            "interface": ingress,
            "summary": packet.summary(),
        }

    def configure(self, **settings) -> dict:
        with self._lock:
            if "enabled" in settings:
                self.enabled = bool(settings.get("enabled"))
            if "interface_enabled" in settings:
                self.enabled = bool(settings.get("interface_enabled"))
            self.remove_on_shutdown = bool(
                settings.get("remove_on_shutdown", settings.get("interface_remove_on_shutdown", self.remove_on_shutdown))
            )
            if settings.get("switch_name") or settings.get("interface_switch_name"):
                self.switch_name = self._validate_name(
                    settings.get("switch_name") or settings.get("interface_switch_name"),
                    "CodeOutput switch name",
                )
            if settings.get("adapter_name") or settings.get("interface_adapter_name"):
                self.adapter_name = self._validate_name(
                    settings.get("adapter_name") or settings.get("interface_adapter_name"),
                    "CodeOutput adapter name",
                )
            if settings.get("ipv4") or settings.get("interface_ipv4"):
                self.interface_ipv4 = str(ipaddress.IPv4Address(
                    settings.get("ipv4") or settings.get("interface_ipv4")
                ))
            if settings.get("prefix_length") is not None or settings.get("interface_prefix_length") is not None:
                value = settings.get("prefix_length", settings.get("interface_prefix_length"))
                value = int(value)
                if not 1 <= value <= 30:
                    raise ValueError("CodeOutput prefix length must be between 1 and 30.")
                self.prefix_length = value
            self.network = ipaddress.ip_network(
                f"{self.interface_ipv4}/{self.prefix_length}", strict=False
            )
        return self.status()

    def create_interface(
            self,
            *,
            switch_name: str | None = None,
            adapter_name: str | None = None,
            ipv4: str | None = None,
            prefix_length: int | None = None,
            start_capture: bool = True,
    ) -> dict:
        self.configure(
            enabled=True,
            switch_name=switch_name or self.switch_name,
            adapter_name=adapter_name or self.adapter_name,
            ipv4=ipv4 or self.interface_ipv4,
            prefix_length=self.prefix_length if prefix_length is None else prefix_length,
        )
        with self._lock:
            switch_name = self.switch_name
            adapter_name = self.adapter_name
            ip_text = self.interface_ipv4
            prefix_length = self.prefix_length
            network = self.network

        ps_switch = self._ps_literal(switch_name)
        ps_adapter = self._ps_literal(adapter_name)
        ps_ip = self._ps_literal(ip_text)
        expected_alias = self._ps_literal(f"vEthernet ({switch_name})")
        script = rf"""
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop
$switchName = '{ps_switch}'
$adapterName = '{ps_adapter}'
$expectedAlias = '{expected_alias}'
$created = $false
$switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if (-not $switch) {{
    $switch = New-VMSwitch -Name $switchName -SwitchType Internal -ErrorAction Stop
    $created = $true
}}
$deadline = (Get-Date).AddSeconds(20)
do {{
    $adapter = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
    if (-not $adapter) {{ $adapter = Get-NetAdapter -Name $expectedAlias -ErrorAction SilentlyContinue }}
    if (-not $adapter) {{ Start-Sleep -Milliseconds 250 }}
}} while (-not $adapter -and (Get-Date) -lt $deadline)
if (-not $adapter) {{ throw "Hyper-V created '$switchName' but its management adapter did not appear." }}
if ($adapter.Name -ne $adapterName) {{
    $existingTarget = Get-NetAdapter -Name $adapterName -ErrorAction SilentlyContinue
    if ($existingTarget -and $existingTarget.ifIndex -ne $adapter.ifIndex) {{
        throw "A different adapter already uses the name '$adapterName'."
    }}
    Rename-NetAdapter -Name $adapter.Name -NewName $adapterName -Confirm:$false -ErrorAction Stop
    $adapter = Get-NetAdapter -Name $adapterName -ErrorAction Stop
}}
Enable-NetAdapter -Name $adapterName -Confirm:$false -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceAlias $adapterName -AddressFamily IPv4 -Dhcp Disabled -ErrorAction SilentlyContinue
$existing = Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -ErrorAction SilentlyContinue
$existing | Where-Object {{ $_.IPAddress -ne '{ps_ip}' }} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
$current = Get-NetIPAddress -InterfaceAlias $adapterName -AddressFamily IPv4 -IPAddress '{ps_ip}' -ErrorAction SilentlyContinue
if (-not $current) {{
    New-NetIPAddress -InterfaceAlias $adapterName -IPAddress '{ps_ip}' -PrefixLength {prefix_length} -Type Unicast -ErrorAction Stop | Out-Null
}}
Set-NetIPInterface -InterfaceAlias $adapterName -AddressFamily IPv4 -Forwarding Enabled -InterfaceMetric 6 -ErrorAction SilentlyContinue
$adapter = Get-NetAdapter -Name $adapterName -ErrorAction Stop
[PSCustomObject]@{{
    Alias = [string]$adapter.Name
    IfIndex = [int]$adapter.ifIndex
    Status = [string]$adapter.Status
    MacAddress = [string]$adapter.MacAddress
    Created = [bool]$created
}} | ConvertTo-Json -Compress
"""
        self._log(
            f"[CodeOutputInterface] Creating/enabling '{adapter_name}' on Hyper-V switch "
            f"'{switch_name}' at {ip_text}/{prefix_length}..."
        )
        ok, detail, stdout = self._run_powershell(script)
        if not ok:
            with self._lock:
                self.last_error = detail or "unknown PowerShell failure"
                self.interface_alias = self.LOGICAL_IFACE
                self.interface_full_name = self.LOGICAL_IFACE
                self.interface_index = None
                self.interface_mac = None
                self.interface_created_by_manager = False
                self.interface_ready = True
                self.enabled = True
            self._register_router_interface(start_capture=False)
            self._log(
                "[CodeOutputInterface] ⚠️ Hyper-V adapter unavailable; using logical "
                f"virtual-WAN ingress instead. PowerShell: {detail or 'unknown failure'}"
            )
            return self.status()

        payload = {}
        for line in reversed((stdout or "").splitlines()):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
                break
            except Exception:
                continue

        with self._lock:
            self.interface_alias = str(payload.get("Alias") or adapter_name)
            self.interface_index = payload.get("IfIndex")
            self.interface_mac = str(payload.get("MacAddress") or "").replace("-", ":").lower() or None
            self.interface_created_by_manager = bool(payload.get("Created", False))
            self.interface_ready = True
            self.enabled = True
            self.network = network
            self.last_error = ""

        self._resolve_capture_interface()
        self._register_router_interface(start_capture=start_capture)
        self._log(
            f"[CodeOutputInterface] ✅ Ready: {self.interface_alias} "
            f"({self.interface_ipv4}/{self.prefix_length}); capture={self.interface_full_name or 'pending'}."
        )
        return self.status()

    def _resolve_capture_interface(self) -> str | None:
        router = self.router_manager
        if router is None:
            return None
        try:
            router._initialize_interface_discovery()
        except Exception:
            pass
        alias_key = str(self.interface_alias or self.adapter_name).casefold()
        best = None
        for item in list(getattr(router, "_discovered_tshark_interfaces", []) or []):
            friendly = str(item.get("friendly_name") or "")
            full = str(item.get("full_name") or "")
            if friendly.casefold() == alias_key:
                best = full or friendly
                break
            if alias_key and (alias_key in friendly.casefold() or alias_key in full.casefold()):
                best = full or friendly
        with self._lock:
            self.interface_full_name = best or self.interface_alias
        return self.interface_full_name

    def _register_router_interface(self, *, start_capture: bool = True) -> None:
        router = self.router_manager
        if router is None:
            return
        with self._lock:
            network = self.network
            alias = self.interface_alias
            full_name = self.interface_full_name or alias
            ip_text = self.interface_ipv4
            if_index = self.interface_index
            mac = self.interface_mac
        logical_config = {
            "friendly_name": alias,
            "physical_iface": full_name,
            "ip_addr": ip_text,
            "network": network,
            "network_text": str(network),
            "netmask": str(network.netmask),
            "broadcast": str(network.broadcast_address),
            "gateway": None,
            "if_index": if_index,
            "mac": mac,
            "is_default_gateway_iface": False,
            "logical_codeoutput_interface": True,
            "logical_only": True,
            "programmatic_interface": True,
            "capture_capable": True,
            "route_capable": True,
            "wan_capable": True,
            "passive_observation_only": False,
            "routing_owner": "CodeOutputInterfaceManager",
            "dhcp_owner": "static-codeoutput-interface",
        }
        physical_config = dict(logical_config)
        physical_config.update({
            "friendly_name": alias,
            "logical_only": False,
            "capture_iface": full_name,
        })
        try:
            router._interfaces_config[self.LOGICAL_IFACE] = logical_config
            if full_name and full_name != self.LOGICAL_IFACE:
                router._interfaces_config[full_name] = physical_config
                if mac:
                    router.interface_macs[full_name] = mac
        except Exception:
            pass
        try:
            if router.lan_manager is not None:
                lan_ifaces = getattr(router.lan_manager, "lan_ifaces", None)
                if isinstance(lan_ifaces, set):
                    lan_ifaces.add(self.LOGICAL_IFACE)
                    if full_name and full_name != self.LOGICAL_IFACE:
                        lan_ifaces.add(full_name)
        except Exception:
            pass
        try:
            if router.rip_manager is not None:
                router.rip_manager.add_static_route(
                    network_str=str(network),
                    next_hop="0.0.0.0",
                    interface=(full_name if full_name and full_name != self.LOGICAL_IFACE else self.LOGICAL_IFACE),
                    cost=1,
                )
        except Exception as exc:
            self._log(f"[CodeOutputInterface] ⚠️ RIP registration failed: {exc}")
        if start_capture:
            self.start_capture_worker()

    def start_capture_worker(self) -> bool:
        router = self.router_manager
        if router is None or not bool(getattr(router, "started", False)):
            return False
        with self._lock:
            if self.interface_index is None or self.interface_alias == self.LOGICAL_IFACE:
                return False
        capture_name = self.interface_full_name or self._resolve_capture_interface()
        if not capture_name:
            return False
        try:
            with router._sniff_threads_lock:
                existing = router._sniff_threads.get(capture_name)
            if existing is not None and existing.is_alive():
                self.capture_started = True
                return True
            if getattr(router, "sniffer", None) is None:
                return False
            router._start_single_sniffer(capture_name, promisc=False)
            self.capture_started = True
            self._log(f"[CodeOutputInterface] 📡 Capture worker registered for {capture_name}.")
            return True
        except Exception as exc:
            self.last_error = str(exc)
            self._log(f"[CodeOutputInterface] ⚠️ Capture worker could not start: {exc}")
            return False

    def _unregister_router_interface(self) -> None:
        router = self.router_manager
        if router is None:
            return
        with self._lock:
            full_name = self.interface_full_name
            network = self.network
        try:
            router._interfaces_config.pop(self.LOGICAL_IFACE, None)
            if full_name:
                router._interfaces_config.pop(full_name, None)
        except Exception:
            pass
        try:
            if router.lan_manager is not None:
                lan_ifaces = getattr(router.lan_manager, "lan_ifaces", None)
                if isinstance(lan_ifaces, set):
                    lan_ifaces.discard(self.LOGICAL_IFACE)
                    if full_name:
                        lan_ifaces.discard(full_name)
        except Exception:
            pass
        try:
            if router.rip_manager is not None:
                router.rip_manager.remove_static_route(str(network))
        except Exception:
            pass

    def start(self) -> dict:
        if not self.enabled:
            return self.status()
        if not self.interface_ready:
            return self.create_interface(start_capture=False)
        self._resolve_capture_interface()
        self._register_router_interface(start_capture=False)
        return self.status()

    def remove_interface(self, *, force: bool = False) -> bool:
        with self._lock:
            switch_name = self.switch_name
            alias = self.interface_alias or self.adapter_name
            created = self.interface_created_by_manager
            logical_only = self.interface_index is None or alias == self.LOGICAL_IFACE
        if logical_only:
            self._unregister_router_interface()
            with self._lock:
                self.interface_ready = False
                self.capture_started = False
            self._log("[CodeOutputInterface] Logical virtual-WAN interface unregistered.")
            return True
        if not force and not created:
            self._log(
                "[CodeOutputInterface] Interface pre-existed this run; unregistering it but leaving Windows unchanged."
            )
            self._unregister_router_interface()
            return False
        script = rf"""
$ErrorActionPreference = 'Stop'
$alias = '{self._ps_literal(alias)}'
Get-NetIPAddress -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
$switch = Get-VMSwitch -Name '{self._ps_literal(switch_name)}' -ErrorAction SilentlyContinue
if ($switch) {{ Remove-VMSwitch -Name '{self._ps_literal(switch_name)}' -Force -Confirm:$false -ErrorAction Stop }}
"""
        ok, detail, _ = self._run_powershell(script, timeout=35.0)
        if not ok:
            self.last_error = detail
            self._log(f"[CodeOutputInterface] ⚠️ Removal failed: {detail}")
            return False
        self._unregister_router_interface()
        with self._lock:
            self.interface_ready = False
            self.interface_index = None
            self.interface_mac = None
            self.interface_full_name = None
            self.interface_created_by_manager = False
            self.capture_started = False
        self._log(f"[CodeOutputInterface] Removed Hyper-V switch '{switch_name}'.")
        return True

    def shutdown(self) -> None:
        if self.remove_on_shutdown:
            try:
                self.remove_interface(force=False)
                return
            except Exception as exc:
                self._log(f"[CodeOutputInterface] Shutdown removal failed: {exc}")
        self._unregister_router_interface()

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": bool(self.enabled),
                "ready": bool(self.interface_ready),
                "switch_name": self.switch_name,
                "adapter_name": self.adapter_name,
                "interface_alias": self.interface_alias,
                "interface_full_name": self.interface_full_name,
                "ipv4": self.interface_ipv4,
                "prefix_length": int(self.prefix_length),
                "network": str(self.network),
                "if_index": self.interface_index,
                "mac": self.interface_mac,
                "capture_started": bool(self.capture_started),
                "logical_only": bool(
                    self.interface_index is None
                    or self.interface_alias == self.LOGICAL_IFACE
                ),
                "remove_on_shutdown": bool(self.remove_on_shutdown),
                "last_error": self.last_error,
            }

class ProcessInterfaceManager:
    """Server-owned process docking/routing policy.

    The GUI process remains a completely separate Windows process. This manager
    owns only the network policy: it creates an Internal Hyper-V interface through
    PowerShell, watches the selected PID's live TCP/UDP sockets, and tags packets
    captured by the router's WinDivert/loopback ingress as ``ProcessInterface``.

    Windows does not provide a normal route-table entry that targets one PID. The
    PID boundary is therefore enforced by socket-tuple correlation before packets
    enter the router pipeline; no machine-wide default route is changed.
    """

    LOGICAL_IFACE = "ProcessInterface"
    DEFAULT_SWITCH_NAME = "ProcessInterface"
    DEFAULT_IPV4 = "172.30.254.1"
    DEFAULT_PREFIX_LENGTH = 30
    DEFAULT_STRATUM_PORTS = {
        3333, 3334, 4444, 5555, 7777,
        10001, 10128, 20128, 4242,
    }

    def __init__(self, router_manager, logger):
        self.router_manager = router_manager
        self.logger = logger
        self._lock = threading.RLock()
        self._stop_event = threading.Event()
        self._monitor_thread = None

        self.enabled = False
        self.mode = "stratum"
        self.selected_pid = None
        self.selected_process_name = ""
        self.selected_process_path = ""
        self.selected_process_created = None
        self.stratum_ports = set(self.DEFAULT_STRATUM_PORTS)

        self.switch_name = self.DEFAULT_SWITCH_NAME
        self.interface_alias = f"vEthernet ({self.switch_name})"
        self.interface_ipv4 = self.DEFAULT_IPV4
        self.prefix_length = self.DEFAULT_PREFIX_LENGTH
        self.network = ipaddress.ip_network(
            f"{self.interface_ipv4}/{self.prefix_length}",
            strict=False,
        )
        self.interface_ready = False
        self.interface_created_by_manager = False
        self.interface_index = None

        self._outbound_flows = set()
        self._flow_details = []
        self._last_refresh_at = 0.0
        self._last_refresh_error = ""
        self._seen_flow_logs = set()
        self._packets_tagged = 0
        self._refresh_interval = 0.25
        self._owns_windivert_lifecycle = False
        self.bundle_active = False
        self.bundle_profile = "balanced"
        self.bundle_router_pid = os.getpid()
        self.bundle_client_pid = None
        self._bundle_original = {}
        self._bundle_applied = {}

    def _log(self, message: str) -> None:
        try:
            self.logger.log_message(str(message))
        except Exception:
            pass

    @staticmethod
    def _powershell_literal(value: str) -> str:
        return str(value or "").replace("'", "''")

    @staticmethod
    def _normalize_ip(value) -> str:
        text = str(value or "").strip()
        if not text:
            return ""
        text = text.split("%", 1)[0]
        if text.lower().startswith("::ffff:"):
            text = text[7:]
        try:
            return str(ipaddress.ip_address(text))
        except Exception:
            return text.casefold()

    @staticmethod
    def _address_pair(address) -> tuple[str, int]:
        if not address:
            return "", 0
        try:
            return str(address.ip), int(address.port)
        except Exception:
            pass
        try:
            return str(address[0]), int(address[1])
        except Exception:
            return "", 0

    def _run_powershell(self, script: str, *, timeout: float = 45.0):
        if os.name != "nt":
            return False, "ProcessInterface requires Windows PowerShell.", ""
        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoLogo",
                    "-NoProfile",
                    "-NonInteractive",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", script,
                ],
                capture_output=True,
                text=True,
                timeout=max(1.0, float(timeout)),
                check=False,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()
            detail = stderr or stdout
            return result.returncode == 0, detail, stdout
        except subprocess.TimeoutExpired:
            return False, "PowerShell operation timed out.", ""
        except Exception as exc:
            return False, str(exc), ""

    def create_interface(
            self,
            *,
            switch_name: str = DEFAULT_SWITCH_NAME,
            ipv4: str = DEFAULT_IPV4,
            prefix_length: int = DEFAULT_PREFIX_LENGTH,
    ) -> dict:
        switch_name = str(switch_name or self.DEFAULT_SWITCH_NAME).strip()
        if not re.fullmatch(r"[A-Za-z0-9_.() -]{1,64}", switch_name):
            raise ValueError("ProcessInterface switch name contains unsupported characters.")
        ip_obj = ipaddress.IPv4Address(str(ipv4).strip())
        prefix_length = int(prefix_length)
        if not 1 <= prefix_length <= 30:
            raise ValueError("ProcessInterface prefix length must be between 1 and 30.")
        network = ipaddress.ip_network(f"{ip_obj}/{prefix_length}", strict=False)
        alias = f"vEthernet ({switch_name})"

        ps_switch = self._powershell_literal(switch_name)
        ps_alias = self._powershell_literal(alias)
        ps_ip = self._powershell_literal(str(ip_obj))
        script = rf'''
$ErrorActionPreference = 'Stop'
Import-Module Hyper-V -ErrorAction Stop
$switchName = '{ps_switch}'
$alias = '{ps_alias}'
$created = $false
$switch = Get-VMSwitch -Name $switchName -ErrorAction SilentlyContinue
if (-not $switch) {{
    $switch = New-VMSwitch -Name $switchName -SwitchType Internal -ErrorAction Stop
    $created = $true
}}
$deadline = (Get-Date).AddSeconds(20)
do {{
    $adapter = Get-NetAdapter -Name $alias -ErrorAction SilentlyContinue
    if (-not $adapter) {{ Start-Sleep -Milliseconds 250 }}
}} while (-not $adapter -and (Get-Date) -lt $deadline)
if (-not $adapter) {{ throw "Hyper-V created the switch but '$alias' did not appear." }}
Enable-NetAdapter -Name $alias -Confirm:$false -ErrorAction SilentlyContinue
Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Dhcp Disabled -ErrorAction SilentlyContinue
$existing = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -ErrorAction SilentlyContinue
$existing | Where-Object {{ $_.IPAddress -ne '{ps_ip}' }} | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
$current = Get-NetIPAddress -InterfaceAlias $alias -AddressFamily IPv4 -IPAddress '{ps_ip}' -ErrorAction SilentlyContinue
if (-not $current) {{
    New-NetIPAddress -InterfaceAlias $alias -IPAddress '{ps_ip}' -PrefixLength {prefix_length} -Type Unicast -ErrorAction Stop | Out-Null
}}
Set-NetIPInterface -InterfaceAlias $alias -AddressFamily IPv4 -Forwarding Enabled -InterfaceMetric 5 -ErrorAction SilentlyContinue
$adapter = Get-NetAdapter -Name $alias -ErrorAction Stop
[PSCustomObject]@{{
    Alias = $alias
    IfIndex = [int]$adapter.ifIndex
    Status = [string]$adapter.Status
    MacAddress = [string]$adapter.MacAddress
    Created = [bool]$created
}} | ConvertTo-Json -Compress
'''
        self._log(
            f"[ProcessInterface] Creating/enabling Hyper-V interface '{alias}' "
            f"at {ip_obj}/{prefix_length}..."
        )
        ok, detail, stdout = self._run_powershell(script, timeout=55.0)
        if not ok:
            with self._lock:
                self.switch_name = switch_name
                self.interface_alias = self.LOGICAL_IFACE
                self.interface_ipv4 = str(ip_obj)
                self.prefix_length = prefix_length
                self.network = network
                self.interface_index = None
                self.interface_created_by_manager = False
                self.interface_ready = True
            self._register_router_interface()
            self._log(
                "[ProcessInterface] ⚠️ Hyper-V adapter unavailable; using logical PID-scoped "
                f"interface instead. PowerShell: {detail or 'unknown failure'}"
            )
            return self.status()

        payload = {}
        for line in reversed((stdout or "").splitlines()):
            line = line.strip()
            if not line.startswith("{"):
                continue
            try:
                payload = json.loads(line)
                break
            except Exception:
                continue

        with self._lock:
            self.switch_name = switch_name
            self.interface_alias = str(payload.get("Alias") or alias)
            self.interface_ipv4 = str(ip_obj)
            self.prefix_length = prefix_length
            self.network = network
            self.interface_index = payload.get("IfIndex")
            self.interface_created_by_manager = bool(payload.get("Created", False))
            self.interface_ready = True
        self._register_router_interface()
        self._log(
            f"[ProcessInterface] ✅ Ready: {self.interface_alias} "
            f"({self.interface_ipv4}/{self.prefix_length})."
        )
        return self.status()

    def remove_interface(self, *, force: bool = False) -> bool:
        with self._lock:
            switch_name = self.switch_name
            alias = self.interface_alias
            created_by_manager = self.interface_created_by_manager
            logical_only = self.interface_index is None or alias == self.LOGICAL_IFACE
        if logical_only:
            self._unregister_router_interface()
            with self._lock:
                self.interface_ready = False
            self._log("[ProcessInterface] Logical PID-scoped interface unregistered.")
            return True
        if not force and not created_by_manager:
            self._log(
                "[ProcessInterface] Interface existed before this session; leaving it in place. "
                "Use force removal only when you own that Hyper-V switch."
            )
            self._unregister_router_interface()
            return False

        ps_switch = self._powershell_literal(switch_name)
        ps_alias = self._powershell_literal(alias)
        script = rf'''
$ErrorActionPreference = 'Stop'
$alias = '{ps_alias}'
Get-NetIPAddress -InterfaceAlias $alias -ErrorAction SilentlyContinue |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
$switch = Get-VMSwitch -Name '{ps_switch}' -ErrorAction SilentlyContinue
if ($switch) {{ Remove-VMSwitch -Name '{ps_switch}' -Force -Confirm:$false -ErrorAction Stop }}
'''
        ok, detail, _ = self._run_powershell(script, timeout=35.0)
        if not ok:
            self._log(f"[ProcessInterface] ⚠️ Interface removal failed: {detail}")
            return False
        with self._lock:
            self.interface_ready = False
            self.interface_index = None
            self.interface_created_by_manager = False
        self._unregister_router_interface()
        self._log(f"[ProcessInterface] Removed Hyper-V switch '{switch_name}'.")
        return True

    def _register_router_interface(self) -> None:
        router = self.router_manager
        if router is None:
            return
        with self._lock:
            network = self.network
            alias = self.interface_alias
            ip_text = self.interface_ipv4
            if_index = self.interface_index
        config = {
            "friendly_name": alias,
            "ip_addr": ip_text,
            "network": network,
            "network_text": str(network),
            "netmask": str(network.netmask),
            "broadcast": str(network.broadcast_address),
            "gateway": None,
            "if_index": if_index,
            "is_default_gateway_iface": False,
            "logical_process_interface": True,
            "logical_only": bool(if_index is None or alias == self.LOGICAL_IFACE),
            "programmatic_interface": True,
            "capture_capable": True,
            "route_capable": True,
            "wan_capable": True,
            "routing_owner": "ProcessInterfaceManager",
            "dhcp_owner": "static-process-interface",
        }
        try:
            router._interfaces_config[self.LOGICAL_IFACE] = config
        except Exception:
            pass
        try:
            if router.lan_manager is not None:
                lan_ifaces = getattr(router.lan_manager, "lan_ifaces", None)
                if isinstance(lan_ifaces, set):
                    lan_ifaces.add(self.LOGICAL_IFACE)
        except Exception:
            pass
        try:
            if router.rip_manager is not None:
                router.rip_manager.add_static_route(
                    network_str=str(network),
                    next_hop="0.0.0.0",
                    interface=self.LOGICAL_IFACE,
                    cost=1,
                )
        except Exception:
            pass

    def _unregister_router_interface(self) -> None:
        router = self.router_manager
        if router is None:
            return
        try:
            router._interfaces_config.pop(self.LOGICAL_IFACE, None)
        except Exception:
            pass
        try:
            if router.lan_manager is not None:
                lan_ifaces = getattr(router.lan_manager, "lan_ifaces", None)
                if isinstance(lan_ifaces, set):
                    lan_ifaces.discard(self.LOGICAL_IFACE)
        except Exception:
            pass
        try:
            if router.rip_manager is not None:
                router.rip_manager.remove_static_route(str(self.network))
        except Exception:
            pass

    def enable_process(
            self,
            pid: int,
            *,
            mode: str = "stratum",
            stratum_ports=None,
    ) -> dict:
        pid = int(pid)
        process = psutil.Process(pid)
        created = float(process.create_time())
        name = process.name()
        try:
            path = process.exe()
        except Exception:
            path = ""

        normalized_mode = str(mode or "stratum").strip().casefold()
        aliases = {
            "stratum only": "stratum",
            "stratum": "stratum",
            "all tcp/udp": "all",
            "all": "all",
            "observe only": "observe",
            "observe": "observe",
        }
        normalized_mode = aliases.get(normalized_mode, normalized_mode)
        if normalized_mode not in {"stratum", "all", "observe"}:
            raise ValueError("Process routing mode must be stratum, all, or observe.")

        ports = set()
        for value in (stratum_ports or self.DEFAULT_STRATUM_PORTS):
            try:
                port = int(value)
            except Exception:
                continue
            if 1 <= port <= 65535:
                ports.add(port)
        if not ports:
            ports = set(self.DEFAULT_STRATUM_PORTS)

        with self._lock:
            self.selected_pid = pid
            self.selected_process_name = str(name or f"PID {pid}")
            self.selected_process_path = str(path or "")
            self.selected_process_created = created
            self.mode = normalized_mode
            self.stratum_ports = ports
            self.enabled = True
            self._outbound_flows.clear()
            self._flow_details.clear()
            self._seen_flow_logs.clear()
            self._packets_tagged = 0
            self._last_refresh_error = ""
            self._stop_event.clear()

        self._register_router_interface()
        self._start_monitor()
        self._ensure_packet_capture()
        self._refresh_connections()
        self._log(
            f"[ProcessInterface] ✅ PID {pid} ({self.selected_process_name}) attached "
            f"in {normalized_mode} mode. The client remains a separate process."
        )
        return self.status()

    def bind_router(self, router_manager) -> None:
        """Bind this process interface directly to PythonRouterManager."""
        if router_manager is None or not callable(getattr(router_manager, "process_packet", None)):
            raise ValueError("ProcessInterface requires a router with process_packet().")
        self.router_manager = router_manager

    def submit_packet(self, packet, metadata: Optional[dict] = None) -> dict:
        """Feed a PID-owned packet through PythonRouterManager's bounded ingress queue."""
        router = self.router_manager
        enqueue = getattr(router, "enqueue_ingress_packet", None)
        if not callable(enqueue):
            raise RuntimeError("ProcessInterface is not linked to PythonRouterManager.enqueue_ingress_packet().")
        with self._lock:
            pid = self.selected_pid
            name = self.selected_process_name
        try:
            setattr(packet, "_process_interface_packet", True)
            setattr(packet, "_process_interface_pid", pid)
            setattr(packet, "_process_interface_name", name)
            setattr(packet, "_process_interface_metadata", dict(metadata or {}))
            setattr(packet, "_router_ingress_owner", "ProcessInterfaceManager")
        except Exception:
            pass
        accepted = bool(enqueue(packet, self.LOGICAL_IFACE))
        return {
            "status": "QUEUED" if accepted else "REJECTED",
            "interface": self.LOGICAL_IFACE,
            "pid": pid,
            "summary": packet.summary(),
        }

    @staticmethod
    def _priority_name(value) -> str:
        mapping = {
            getattr(psutil, "IDLE_PRIORITY_CLASS", object()): "idle",
            getattr(psutil, "BELOW_NORMAL_PRIORITY_CLASS", object()): "below-normal",
            getattr(psutil, "NORMAL_PRIORITY_CLASS", object()): "normal",
            getattr(psutil, "ABOVE_NORMAL_PRIORITY_CLASS", object()): "above-normal",
            getattr(psutil, "HIGH_PRIORITY_CLASS", object()): "high",
            getattr(psutil, "REALTIME_PRIORITY_CLASS", object()): "realtime",
        }
        return mapping.get(value, str(value))

    @staticmethod
    def _snapshot_process_tuning(process: psutil.Process) -> dict:
        snapshot = {"pid": process.pid, "create_time": float(process.create_time())}
        try:
            snapshot["affinity"] = list(process.cpu_affinity())
        except Exception:
            snapshot["affinity"] = None
        try:
            snapshot["priority"] = process.nice()
        except Exception:
            snapshot["priority"] = None
        try:
            snapshot["io_priority"] = process.ionice()
        except Exception:
            snapshot["io_priority"] = None
        return snapshot

    @staticmethod
    def _set_process_tuning(process: psutil.Process, *, affinity=None, priority=None, io_priority=None) -> dict:
        applied = {"pid": process.pid}
        if affinity:
            process.cpu_affinity(sorted({int(x) for x in affinity}))
            applied["affinity"] = list(process.cpu_affinity())
        if priority is not None:
            process.nice(priority)
            applied["priority"] = process.nice()
        if io_priority is not None:
            try:
                process.ionice(io_priority)
                applied["io_priority"] = process.ionice()
            except Exception:
                pass
        return applied

    def bundle_with_router(self, pid: int, *, profile: str = "balanced") -> dict:
        """Create a reversible managed bundle without merging address spaces.

        Both executables remain separate Windows processes. The bundle coordinates
        CPU affinity and priority so the packet router retains responsive cores
        while the client keeps the remaining compute capacity.
        """
        client = psutil.Process(int(pid))
        router_proc = psutil.Process(os.getpid())
        if client.pid == router_proc.pid:
            raise ValueError("Select a client process different from the router process.")
        profile_key = str(profile or "balanced").strip().casefold().replace(" ", "-")
        aliases = {
            "balanced-shared": "balanced",
            "balanced": "balanced",
            "split-cores": "split",
            "split": "split",
            "router-responsive": "router-responsive",
            "client-performance": "client-performance",
            "shared-all-cores": "shared",
            "shared": "shared",
        }
        profile_key = aliases.get(profile_key, profile_key)
        if profile_key not in {"balanced", "split", "router-responsive", "client-performance", "shared"}:
            raise ValueError("Unknown process bundle profile.")

        self.unbundle_processes(silent=True)
        total = max(1, int(psutil.cpu_count(logical=True) or 1))
        all_cores = list(range(total))
        reserve = max(1, min(4, total // 8 or 1))
        router_cores = all_cores[:reserve]
        client_cores = all_cores[reserve:] or all_cores
        if profile_key == "split":
            split_at = max(1, min(total - 1, total // 4)) if total > 1 else 1
            router_cores = all_cores[:split_at]
            client_cores = all_cores[split_at:] or all_cores
        elif profile_key == "router-responsive":
            reserve = max(2, min(6, total // 4 or 2)) if total >= 2 else 1
            router_cores = all_cores[:reserve]
            client_cores = all_cores[reserve:] or all_cores
        elif profile_key == "client-performance":
            router_cores = all_cores[:max(1, min(2, total))]
            client_cores = all_cores
        elif profile_key in {"balanced", "shared"}:
            router_cores = all_cores
            client_cores = all_cores

        router_priority = getattr(psutil, "ABOVE_NORMAL_PRIORITY_CLASS", None) if os.name == "nt" else 0
        client_priority = getattr(psutil, "NORMAL_PRIORITY_CLASS", None) if os.name == "nt" else 0
        if profile_key == "client-performance" and os.name == "nt":
            client_priority = getattr(psutil, "ABOVE_NORMAL_PRIORITY_CLASS", client_priority)
        io_normal = getattr(psutil, "IOPRIO_NORMAL", None) if os.name == "nt" else None

        original = {
            router_proc.pid: self._snapshot_process_tuning(router_proc),
            client.pid: self._snapshot_process_tuning(client),
        }
        # Store the snapshots before changing either process. If the second
        # update fails, unbundle_processes() can transactionally restore the
        # first process instead of leaving a half-applied performance profile.
        with self._lock:
            self.bundle_active = False
            self.bundle_profile = profile_key
            self.bundle_router_pid = router_proc.pid
            self.bundle_client_pid = client.pid
            self._bundle_original = original
            self._bundle_applied = {}
        try:
            applied = {
                router_proc.pid: self._set_process_tuning(
                    router_proc, affinity=router_cores, priority=router_priority, io_priority=io_normal,
                ),
                client.pid: self._set_process_tuning(
                    client, affinity=client_cores, priority=client_priority, io_priority=io_normal,
                ),
            }
        except Exception:
            self.unbundle_processes(silent=True)
            raise
        with self._lock:
            self.bundle_active = True
            self._bundle_applied = applied
        self._log(
            f"[ProcessBundle] ✅ Managed bundle active router={router_proc.pid} client={client.pid} "
            f"profile={profile_key} router_cores={router_cores} client_cores={client_cores}."
        )
        return self.status()

    def unbundle_processes(self, *, silent: bool = False) -> dict:
        with self._lock:
            originals = dict(self._bundle_original)
            was_active = bool(self.bundle_active)
        restored = {}
        for pid, snapshot in originals.items():
            try:
                process = psutil.Process(int(pid))
                if abs(float(process.create_time()) - float(snapshot.get("create_time") or 0.0)) > 0.001:
                    continue
                affinity = snapshot.get("affinity")
                if affinity:
                    process.cpu_affinity(list(affinity))
                if snapshot.get("priority") is not None:
                    process.nice(snapshot.get("priority"))
                if snapshot.get("io_priority") is not None:
                    try:
                        process.ionice(snapshot.get("io_priority"))
                    except Exception:
                        pass
                restored[pid] = True
            except Exception as exc:
                restored[pid] = str(exc)
        with self._lock:
            self.bundle_active = False
            self.bundle_profile = ""
            self.bundle_router_pid = None
            self.bundle_client_pid = None
            self._bundle_original = {}
            self._bundle_applied = {}
        if was_active and not silent:
            self._log(f"[ProcessBundle] ↔️ Bundle removed; original process settings restored: {restored}.")
        return self.status()

    def _ensure_packet_capture(self) -> None:
        router = self.router_manager
        manager = getattr(router, "windivert_manager", None) if router is not None else None
        if manager is None:
            self._log(
                "[ProcessInterface] ⚠️ WinDivertManager is unavailable; socket policy will "
                "remain ready until the router packet backend starts."
            )
            return
        try:
            already_running = any(bool(getattr(manager, attr, False)) for attr in (
                "running", "is_running", "started", "_running", "_started",
            ))
            manager.start()
            if not already_running and not bool(getattr(router, "hyperv_enabled", False)):
                self._owns_windivert_lifecycle = True
            self._log("[ProcessInterface] WinDivert packet ingress is active.")
        except Exception as exc:
            self._log(f"[ProcessInterface] ⚠️ Could not start WinDivert ingress: {exc}")

    def disable_process(self) -> None:
        self._stop_event.set()
        thread = self._monitor_thread
        if thread and thread.is_alive() and thread is not threading.current_thread():
            thread.join(timeout=2.0)
        router = self.router_manager
        manager = getattr(router, "windivert_manager", None) if router is not None else None
        if self._owns_windivert_lifecycle and manager is not None:
            try:
                manager.stop()
            except Exception as exc:
                self._log(f"[ProcessInterface] WinDivert stop warning: {exc}")
        self._owns_windivert_lifecycle = False
        with self._lock:
            pid = self.selected_pid
            self.enabled = False
            self.selected_pid = None
            self.selected_process_name = ""
            self.selected_process_path = ""
            self.selected_process_created = None
            self._outbound_flows.clear()
            self._flow_details.clear()
            self._seen_flow_logs.clear()
            self._monitor_thread = None
        self._log(f"[ProcessInterface] Process routing disabled for PID {pid or '-'}.")

    def shutdown(self, *, remove_interface: bool = False) -> None:
        self.unbundle_processes(silent=True)
        self.disable_process()
        if remove_interface:
            try:
                self.remove_interface(force=False)
            except Exception as exc:
                self._log(f"[ProcessInterface] Shutdown interface cleanup failed: {exc}")

    def _start_monitor(self) -> None:
        thread = self._monitor_thread
        if thread and thread.is_alive():
            return
        self._monitor_thread = threading.Thread(
            target=self._monitor_loop,
            name="ProcessInterfaceSocketMonitor",
            daemon=True,
        )
        self._monitor_thread.start()

    def _monitor_loop(self) -> None:
        while not self._stop_event.wait(self._refresh_interval):
            with self._lock:
                if not self.enabled:
                    return
            try:
                self._refresh_connections()
            except Exception as exc:
                with self._lock:
                    self._last_refresh_error = str(exc)
                time.sleep(0.5)

    def _refresh_connections(self) -> None:
        with self._lock:
            pid = self.selected_pid
            expected_created = self.selected_process_created
            mode = self.mode
            ports = set(self.stratum_ports)
        if not pid:
            return
        process = psutil.Process(pid)
        current_created = float(process.create_time())
        if expected_created is not None and abs(current_created - expected_created) > 0.001:
            raise RuntimeError("Selected PID was reused by a different process.")

        try:
            connections = process.net_connections(kind="inet")
        except AttributeError:
            connections = process.connections(kind="inet")

        flows = set()
        details = []
        for connection in connections:
            local_ip, local_port = self._address_pair(connection.laddr)
            remote_ip, remote_port = self._address_pair(connection.raddr)
            protocol = (
                "tcp" if connection.type == socket.SOCK_STREAM
                else "udp" if connection.type == socket.SOCK_DGRAM
                else ""
            )
            if not protocol or not local_ip or not local_port:
                continue
            if not remote_ip or not remote_port:
                if protocol != "udp":
                    continue
                remote_ip, remote_port = "*", 0
            if (
                    mode == "stratum"
                    and remote_port
                    and remote_port not in ports
                    and local_port not in ports
            ):
                continue
            family = 6 if connection.family == socket.AF_INET6 else 4
            key = (
                family,
                protocol,
                self._normalize_ip(local_ip),
                int(local_port),
                self._normalize_ip(remote_ip),
                int(remote_port),
            )
            flows.add(key)
            details.append({
                "family": family,
                "protocol": protocol,
                "local": f"{key[2]}:{key[3]}",
                "remote": f"{key[4]}:{key[5]}",
                "status": str(getattr(connection, "status", "") or ""),
            })

        with self._lock:
            self._outbound_flows = flows
            self._flow_details = details
            self._last_refresh_at = time.time()
            self._last_refresh_error = ""

    def classify_packet(self, packet, inbound_iface: str):
        with self._lock:
            if not self.enabled or not self.selected_pid:
                return None
            mode = self.mode
            flows = set(self._outbound_flows)
            pid = int(self.selected_pid)
        source_name = str(inbound_iface or "").casefold()
        # Physical LAN/WAN packets must never inherit a PID merely because their
        # tuple happens to match. Process attribution is only valid on host-local
        # capture paths.
        if not any(token in source_name for token in (
                "windivert", "loopback", "wire_shark", "wireshark", "host")):
            return None

        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if ip_layer is None:
            return None
        if packet.haslayer(TCP):
            transport = packet[TCP]
            protocol = "tcp"
        elif packet.haslayer(UDP):
            transport = packet[UDP]
            protocol = "udp"
        else:
            return None
        family = 6 if packet.haslayer(IPv6) else 4
        key = (
            family,
            protocol,
            self._normalize_ip(getattr(ip_layer, "src", "")),
            int(getattr(transport, "sport", 0) or 0),
            self._normalize_ip(getattr(ip_layer, "dst", "")),
            int(getattr(transport, "dport", 0) or 0),
        )
        if mode == "stratum" and key[3] not in self.stratum_ports and key[5] not in self.stratum_ports:
            return None
        wildcard_local = "::" if family == 6 else "0.0.0.0"
        candidates = {
            key,
            (family, protocol, wildcard_local, key[3], key[4], key[5]),
            (family, protocol, key[2], key[3], "*", 0),
            (family, protocol, wildcard_local, key[3], "*", 0),
        }
        if not candidates.intersection(flows):
            return None
        result = {
            "pid": pid,
            "mode": mode,
            "direction": "outbound",
            "flow": key,
            "logical_iface": self.LOGICAL_IFACE,
            "route": mode != "observe",
        }
        with self._lock:
            self._packets_tagged += 1
            first_seen = key not in self._seen_flow_logs
            if first_seen:
                self._seen_flow_logs.add(key)
        if first_seen:
            self._log(
                f"[ProcessInterface] PID {pid} flow attached: "
                f"{key[2]}:{key[3]} -> {key[4]}:{key[5]} ({protocol})."
            )
        return result

    def apply_packet_policy(self, packet, inbound_iface: str) -> str:
        decision = self.classify_packet(packet, inbound_iface)
        if not decision:
            return inbound_iface
        try:
            setattr(packet, "_process_interface_pid", decision["pid"])
            setattr(packet, "_process_interface_mode", decision["mode"])
            setattr(packet, "_process_interface_original_iface", inbound_iface)
        except Exception:
            pass
        if decision["route"]:
            return self.LOGICAL_IFACE
        return inbound_iface

    def status(self) -> dict:
        with self._lock:
            return {
                "enabled": bool(self.enabled),
                "mode": self.mode,
                "pid": self.selected_pid,
                "process_name": self.selected_process_name,
                "process_path": self.selected_process_path,
                "interface_ready": bool(self.interface_ready),
                "switch_name": self.switch_name,
                "interface_alias": self.interface_alias,
                "interface_ipv4": self.interface_ipv4,
                "prefix_length": self.prefix_length,
                "network": str(self.network),
                "interface_index": self.interface_index,
                "logical_only": bool(
                    self.interface_index is None
                    or self.interface_alias == self.LOGICAL_IFACE
                ),
                "flow_count": len(self._outbound_flows),
                "flows": list(self._flow_details[:64]),
                "packets_tagged": int(self._packets_tagged),
                "last_refresh_at": float(self._last_refresh_at),
                "last_error": self._last_refresh_error,
                "bundle_active": bool(self.bundle_active),
                "bundle_profile": self.bundle_profile,
                "bundle_router_pid": self.bundle_router_pid,
                "bundle_client_pid": self.bundle_client_pid,
                "bundle_applied": dict(self._bundle_applied),
            }

class PythonRouterManager:

    """
    Manages sniffing packets on multiple interfaces and routing them
    based on a simplified routing table. Self-contained for interface discovery and IP assignment.
    """

    # --- Configuration Defaults (used if dynamic assignment fails or as starting points) ---
    DEFAULT_IN_IFACE_FRIENDLY_NAME = "Ethernet"
    DEFAULT_OUT_IFACE_FRIENDLY_NAME = "Wi-Fi"
    DEFAULT_LOOPBACK_IFACE_FRIENDLY_NAME = "Loopback"
    NOTIFICATION_TARGET_IP = "127.0.0.1"  # IP of the machine to receive alerts
    NOTIFICATION_TARGET_PORT = 12345  # UDP Port to listen on

    # Default private IP ranges to try for the IN interface if auto-picking
    PRIVATE_SUBNETS_TO_TRY = [
        "192.168.100.0/24", "192.168.101.0/24", "192.168.102.0/24", "192.168.103.0/24",
        "10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24",
        "172.16.10.0/24", "172.16.11.0/24", "172.16.12.0/24"
    ]


    BPF_FILTER_BASE_DEFINITIONS = {
        "Ethernet": [],
        "Wi-Fi": [],
        "Loopback": [],
        "Ethernet 2": [],
    }
    def __init__(self, router_logger):




        self.router_logger = router_logger
        self.nat_instance_name = f"PythonRouterNAT_{socket.gethostname()}"
        self.code_output_manager = CodeOutputManager(self.router_logger)
        self.code_output_manager.bind_router(self)
        self.parallel_python = ParallelPythonTool(router_logger)
        self.outbound_load_balancer = OutboundLoadBalancer(router_logger)
        self.arp_manager = ARPManager(router_logger, self.outbound_load_balancer)
        self.ndp_manager = NDPManager(router_logger)
        self._interfaces_config = {}  # Stores config for all physical interfaces
        self.interface_in_full_name = None
        self.interface_in_friendly_name = None
        self.interface_out_full_name = None  # Primary OUT interface
        self.interface_out_friendly_name = None
        self.interface_loopback_full_name = None
        self.interface_ethernet_2_full_name = None
        self.interface_ethernet_2_friendly_name = None
        self.interface_lac_full_name = None
        self.interface_lac_friendly_name = None
        self.interface_lac_2_full_name = None
        self.interface_lac_2_friendly_name = None
        self.interface_wifi_full_name = None
        self.interface_wifi_friendly_name = None
        self.wifi_host_managed_ifaces: set[str] = set()
        self.wifi_host_state: dict = {}
        self.wifi_manager = WifiManager(
            router=self,
            router_logger=self.router_logger,
        )
        self.wifi_router_ip: Optional[str] = None
        self.wifi_router_network: Optional[ipaddress.IPv4Network] = None
        self._wifi_firewall_networks: set[str] = set()

        self.router_ip_in = None
        self.router_ip_out = None
        self.router_ipv6_out = None
        self.router_ipv6_link_local_out = None
        self.router_gateway_out_ip = None
        self.router_macs = None
        self.mac_in = None
        self.mac_out = None
        self.interface_macs = {}
        self._sniff_threads = {}
        self._worker_threads = {}
        self._stop_sniffing_event = threading.Event()

        # Runtime readiness and bounded ingress isolation. Capture callbacks,
        # WinDivert/WinTun pipe readers, and peer transports enqueue here and
        # return immediately; per-interface workers own process_packet().
        self._runtime_network_ready = threading.Event()
        self._ingress_lock = threading.RLock()
        self._ingress_states: Dict[str, Dict[str, Any]] = {}
        self._ingress_max_frames = 32768
        self._ingress_max_bytes = 192 * 1024 * 1024
        # Protected control traffic has a bounded reserve. Ordinary HTTPS or a
        # learned mining-port hint is not automatically protected.
        self._ingress_priority_reserve_frames = 4096
        self._ingress_priority_reserve_bytes = 64 * 1024 * 1024
        self._ingress_batch_size = 64
        self._ingress_summary_interval_sec = 30.0
        self._ingress_log_ts: Dict[str, float] = {}
        self._ingress_total_enqueued = 0
        self._ingress_total_processed = 0
        self._ingress_total_dropped = 0
        self._ingress_total_coalesced = 0
        self._ingress_total_evicted = 0
        self._sniff_threads_lock = threading.Lock() # Lock for _sniff_threads dictionary
        self._tshark_path = None
        self._discovered_tshark_interfaces = []
        # Only interfaces recorded here are restored during stop. The WAN is
        # not reset merely because the router observed its native DHCP lease.
        self._router_changed_ipv4_aliases: Dict[str, str] = {}
        self.scrapewebsite_manager = None
        self.function_call_tracker = FunctionCallTracker(router_logger)

        self.sniffer = None
        # Instantiate all specialized managers
        self._byte_parse_dedupe_lock = threading.Lock()
        self._byte_parse_dedupe_cache = {}  # fp -> timestamp
        self._byte_parse_dedupe_ttl = 0.50  # seconds; short on purpose
        self._byte_parse_dedupe_max = 8192

        self.lag_manager = LinkAggregationManager(router_logger)
        self.packet_signer = PacketSigningManager(router_logger)
        self.sendback_manager = SendBackManager(router_logger, self.packet_signer, self.outbound_load_balancer)
        self.packet_writer = PacketWriter(router_logger, self._interfaces_config, self.packet_signer, self.outbound_load_balancer, self.arp_manager, self.ndp_manager)
        self.dns_manager = None
        self.mdns_manager = mDNSManager(router_logger, self.packet_writer, self._interfaces_config)
        self.rip_manager = RIPManager(router_logger, self.function_call_tracker)
        self.nat_manager = None
        self.notification_manager = None
        self.packet_catcher = PacketCatcherManager(router_logger, self._interfaces_config)
        self.handshake_manager = None
        self.igmp_manager = IGMPManager(router_logger, self.packet_writer)
        self.icmp_manager = None
        self.dhcp_server_in = None
        self.dhcp_server_out = None
        self._dhcp_control_plane_signature = None
        self._dhcp_control_plane_signatures = {}
        self._enable_dhcp_server = True
        self._serve_dhcp_on_wan = False
        self._dhcp_server_settings = {}
        self._wan_dhcp_server_settings = {}
        # Optional per-interface DHCP scopes. Interfaces listed in
        # dhcp_server_settings["additional_ifaces"] share the LAN scope, while
        # dhcp_interface_profiles can own independent RFC1918 scopes.
        self._dhcp_interface_profiles = []
        self.dhcp_interface_servers = {}
        self._transport_settings = {}
        self._manager_settings = {
            "enable_firewall": True,
            "enable_packet_analyzer": True,
            "enable_packet_catcher": True,
            "enable_handshake": True,
            "enable_syn_scanner": True,
            "enable_igmp": True,
            "enable_mdns": True,
            "handshake_timeout_half_open": 60,
            "handshake_timeout_established": 300,
            "handshake_rate_limit_threshold": 20,
            "handshake_rate_limit_period": 60,
            "handshake_ban_duration": 300,
            "handshake_log_tcp_lifecycle": True,
            "handshake_log_non_tls_tcp": False,
            "handshake_log_tls_records": True,
            "handshake_log_application_data": False,
            "handshake_log_tls13_key_events": True,
            "syn_scan_interval": 300,
            "packet_catcher_tcp_rate": 0.60,
            "packet_catcher_udp_rate": 0.60,
            "packet_catcher_default_rate": 0.60,
            "require_ethernet_on_physical_capture": True,
            "tunnel_log_success_packets": False,
            "ingress_max_frames": 32768,
            "ingress_max_bytes": 192 * 1024 * 1024,
            "ingress_priority_reserve_frames": 4096,
            "ingress_priority_reserve_bytes": 64 * 1024 * 1024,
            "ingress_batch_size": 64,
            "ingress_summary_interval_sec": 30.0,
        }
        self.firewall_manager = FirewallManager(router_logger)
        self.syn_scanner = None
        self.ethernet_manager = EthernetBridgeManager(router_logger, self.packet_writer)
        self.forwarding_manager = ForwardingManager(self.function_call_tracker, router_logger=self.router_logger,)
        self.kerberos_manager = KerberosManager(router_logger, self.packet_writer)
        self.stratum_manager = None
        self.stratum_connection_manager = None
        self.daemon_manager = None
        self.ethernet_l2_manager = EthernetL2Manager(self.function_call_tracker, router_logger)
        self.transport_manager = TransportManager(router_logger, self.packet_signer,self.code_output_manager, self.parallel_python, self.packet_writer)
        self.isakmp_manager = None
        self.esp_manager = ESPManager(router_logger, self.packet_writer)
        self.hyperv_manager = HyperVManager(self.router_logger)
        self.hyperv_enabled = False
        self.broadcast_manager = BroadcastManager(self.router_logger)
        self.windivert_manager = WinDivertManager(
            self,self.code_output_manager,max_frames_per_batch=64,max_bytes_per_batch=(1 << 20),  # 1 MiB
        )
        self.process_interface_manager = ProcessInterfaceManager(
            self,
            self.router_logger,
        )
        self.codeoutput_interface_manager = CodeOutputInterfaceManager(
            self,
            self.router_logger,
        )
        self._codeoutput_flow_lock = threading.RLock()
        self._codeoutput_recent_flows = deque(maxlen=4096)
        self._codeoutput_flow_counters = collections.Counter()

        self.wintun_manager = WinTunManager(
            self,self.code_output_manager,pipe_name=r'\\.\pipe\wintun_to_python',max_frames_per_batch=256,max_bytes_per_batch = (4 << 20)
        )
        self.packet_catcher_heuristic_rates = {
            'TCP': 0.60,
            'UDP': 0.60,
            'DEFAULT': 0.60,
        }
        self.started = False

        self.packet_analyzer = PacketPipelineBlock()

        self.p2p_manager = None
        self.netroute_manager = None
        self.host_connectivity_boundary = None
        self.gateway_manager = None
        self.lan_manager = None
        self.uplink_manager = None
        self.upstream_manager = None
        self.hypervrouter_manager = None
        self.peerinterface_manager = None
        self.peerinterface_enabled = False
        self._peerinterface_settings = {}
        self._peerinterface_nat_ports = set()
        self.python_server_manager = None
        self.socket_interface = None
        # WAN/public-IP observation state
        self.public_ip_observed: Optional[str] = None
        self._public_ip_last_refresh: float = 0.0
        self._public_ip_refresh_ttl: float = 60.0
        self._public_ip_probe_timeout: float = 2.5
        self._public_ip_probe_urls: tuple[str, ...] = (
            "https://api.ipify.org",
            "https://ipv4.icanhazip.com",
            "https://ifconfig.me/ip",
        )
        self.ollama_assistant = None
        self.ollama_packet_memory = None
        self.ollama_router_bridge = None
        # Tracks the extra on-link WAN address we may publish to NAT in double-NAT cases
        self._nat_last_marked_public_on_lan: Optional[str] = None
        self.hyperv_enabled = False
        self.router_logger.log_message("[Router] Orchestrator Initialized.")

    def _current_lan_transit_ifaces(self) -> set[str]:
        """
        Return every interface that may originate downstream client traffic.

        The Wi-Fi Direct adapter is routed, not added to the outbound LAG.
        """
        result: set[str] = set()

        def add(value) -> None:
            value = str(value or "").strip()
            if value:
                result.add(value)

        add(getattr(self, "interface_in_full_name", None))
        add(getattr(self, "interface_ethernet_2_full_name", None))
        add(getattr(self, "interface_lac_full_name", None))
        add(getattr(self, "interface_lac_2_full_name", None))
        add(getattr(self, "interface_wifi_full_name", None))
        try:
            process_interface = getattr(self, "process_interface_manager", None)
            if process_interface is not None and process_interface.enabled:
                add(process_interface.LOGICAL_IFACE)
        except Exception:
            pass

        try:
            for iface in getattr(
                    self,
                    "wifi_host_managed_ifaces",
                    set(),
            ):
                add(iface)
        except Exception:
            pass

        try:
            members = self.ethernet_manager.get_bridge_members()
            if isinstance(members, (set, list, tuple)):
                for iface in members:
                    add(iface)
        except Exception:
            pass

        try:
            lan_ifaces = getattr(self.lan_manager, "lan_ifaces", None)
            if isinstance(lan_ifaces, (set, list, tuple)):
                for iface in lan_ifaces:
                    add(iface)
        except Exception:
            pass

        # WAN must never be classified as downstream LAN.
        wan_names = {
            str(value or "").strip().casefold()
            for value in (
                getattr(self, "interface_out_full_name", None),
                getattr(self, "interface_out_friendly_name", None),
            )
            if str(value or "").strip()
        }

        return {
            iface
            for iface in result
            if iface.casefold() not in wan_names
        }

    def _on_wifi_host_network_ready(
            self,
            *,
            iface_full_name: str,
            iface_friendly_name: str,
            router_ip: str,
            network,
            adapter: Optional[dict] = None,
    ) -> None:
        """
        Complete the routed LAN path after Windows gives the Wi-Fi Direct
        adapter its client-facing IPv4 subnet.
        """
        iface_full_name = str(iface_full_name or "").strip()
        iface_friendly_name = str(iface_friendly_name or "").strip()
        router_ip = str(router_ip or "").strip()

        if not iface_full_name or not router_ip:
            return

        try:
            wifi_network = (
                network
                if isinstance(network, ipaddress.IPv4Network)
                else ipaddress.ip_network(str(network), strict=False)
            )
        except Exception as exc:
            self.router_logger.log_message(
                f"[WiFiManager][Route] ❌ Invalid Wi-Fi network '{network}': {exc}"
            )
            return

        if not isinstance(wifi_network, ipaddress.IPv4Network):
            return

        previous_network = getattr(self, "wifi_router_network", None)

        self.interface_wifi_full_name = iface_full_name
        self.interface_wifi_friendly_name = iface_friendly_name
        self.wifi_router_ip = router_ip
        self.wifi_router_network = wifi_network

        config = dict(self._interfaces_config.get(iface_full_name, {}))
        config.update({
            "friendly_name": iface_friendly_name,
            "ip_addr": router_ip,
            "network": wifi_network,
            "broadcast": str(wifi_network.broadcast_address),
            "gateway": None,
            "is_default_gateway_iface": False,
            "wireless_host_managed": True,
            "dhcp_owner": "windows_wifi_direct",
            "routing_owner": "pythonrouter",
        })
        self._interfaces_config[iface_full_name] = config

        # Make the adapter a LAN/transit interface for LanManager.
        try:
            if self.lan_manager is not None:
                lan_ifaces = getattr(self.lan_manager, "lan_ifaces", None)
                if isinstance(lan_ifaces, set):
                    lan_ifaces.add(iface_full_name)
        except Exception:
            pass

        # Install a direct route so translated return traffic goes back to
        # the wireless client instead of following the WAN default route.
        try:
            if (
                    previous_network is not None
                    and previous_network != wifi_network
                    and self.rip_manager is not None
            ):
                self.rip_manager.remove_static_route(str(previous_network))
        except Exception:
            pass

        try:
            if self.rip_manager is not None:
                self.rip_manager.add_static_route(
                    network_str=str(wifi_network),
                    next_hop="0.0.0.0",
                    interface=iface_full_name,
                    cost=1,
                )
        except Exception as exc:
            self.router_logger.log_message(
                f"[WiFiManager][Route] ⚠️ Could not install direct Wi-Fi route: {exc}"
            )

        # Refresh manager copies of _interfaces_config.
        for manager in (
                getattr(self, "packet_writer", None),
                getattr(self, "igmp_manager", None),
                getattr(self, "netroute_manager", None),
        ):
            if manager is None:
                continue

            for method_name in (
                    "update_interfaces",
                    "set_interfaces_config",
                    "configure_interfaces",
            ):
                method = getattr(manager, method_name, None)
                if not callable(method):
                    continue
                try:
                    method(self._interfaces_config)
                    break
                except TypeError:
                    continue
                except Exception:
                    break

        # The existing dynamic firewall setup covers only router_network_in.
        # Add a bounded permit pair for the separate Wi-Fi Direct LAN.
        network_text = str(wifi_network)

        if network_text not in self._wifi_firewall_networks:
            try:
                self.firewall_manager.add_rule(
                    action="permit",
                    protocol="any",
                    src_ip=network_text,
                    dst_ip="any",
                    src_port="any",
                    dst_port="any",
                    position=0,
                )
            except TypeError:
                self.firewall_manager.add_rule(
                    action="permit",
                    protocol="any",
                    src_ip=network_text,
                    dst_ip="any",
                    src_port="any",
                    dst_port="any",
                )

            try:
                self.firewall_manager.add_rule(
                    action="permit",
                    protocol="any",
                    src_ip="any",
                    dst_ip=network_text,
                    src_port="any",
                    dst_port="any",
                    position=0,
                )
            except TypeError:
                self.firewall_manager.add_rule(
                    action="permit",
                    protocol="any",
                    src_ip="any",
                    dst_ip=network_text,
                    src_port="any",
                    dst_port="any",
                )

            self._wifi_firewall_networks.add(network_text)

        # Keep NAT's internal self-address useful for replies to services
        # addressed to the Wi-Fi gateway without changing the WAN identity.
        try:
            if self.nat_manager is not None:
                setter = getattr(
                    self.nat_manager,
                    "set_router_internal_ip",
                    None,
                )
                if callable(setter):
                    setter(router_ip)
        except Exception:
            pass

        self.wifi_host_state = {
            "state": "ready",
            "mode": "wifi_direct_legacy_ap",
            "dhcp_owner": "windows_wifi_direct",
            "routing_owner": "pythonrouter",
            "router_ip": router_ip,
            "network": network_text,
            "interface": iface_full_name,
            "friendly_name": iface_friendly_name,
            "adapter": dict(adapter or {}),
        }

        self.router_logger.log_message(
            "[WiFiManager][Route] ✅ Wireless internet path ready: "
            f"network={wifi_network} gateway={router_ip} "
            f"lan_iface={iface_full_name} wan_iface={self.interface_out_full_name}"
        )

    def _on_wifi_host_network_stopped(
            self,
            iface_full_name: Optional[str] = None,
    ) -> None:
        old_network = getattr(self, "wifi_router_network", None)

        try:
            if old_network is not None and self.rip_manager is not None:
                self.rip_manager.remove_static_route(str(old_network))
        except Exception:
            pass

        try:
            if self.lan_manager is not None:
                lan_ifaces = getattr(self.lan_manager, "lan_ifaces", None)
                if isinstance(lan_ifaces, set) and iface_full_name:
                    lan_ifaces.discard(iface_full_name)
        except Exception:
            pass

        self.wifi_router_ip = None
        self.wifi_router_network = None
    # --- add this helper inside PythonRouterManager ---
    def _boundary_transit_ifaces(self) -> set[str]:
        out = {SocketInterface.IFACE_NAME}

        for cand in (
                getattr(self, "interface_in_full_name", None),
                getattr(self, "interface_loopback_full_name", None),
                getattr(self, "interface_ethernet_2_full_name", None),
                getattr(self, "interface_lac_full_name", None),
                getattr(self, "interface_lac_2_full_name", None),
                getattr(self, "interface_wifi_full_name", None),
        ):
            if cand:
                out.add(cand)

        try:
            out.update(
                str(value).strip()
                for value in getattr(
                    self,
                    "wifi_host_managed_ifaces",
                    set(),
                )
                if str(value).strip()
            )
        except Exception:
            pass

        try:
            members = self.ethernet_manager.get_bridge_members()
            if isinstance(members, (list, tuple, set)):
                for member in members:
                    if member:
                        out.add(str(member))
        except Exception:
            pass

        return out

    def _is_wifi_host_interface(
            self,
            iface_full_name: str | None,
            iface_friendly_name: str | None,
    ) -> bool:
        manager = getattr(self, "wifi_manager", None)

        if manager is not None:
            try:
                if manager.is_managed_interface(
                        full_name=iface_full_name,
                        friendly_name=iface_friendly_name,
                ):
                    return True
            except Exception:
                pass

        candidates = {
            str(value or "").strip().casefold()
            for value in (
                iface_full_name,
                iface_friendly_name,
            )
            if str(value or "").strip()
        }

        managed = {
            str(value).strip().casefold()
            for value in getattr(
                self,
                "wifi_host_managed_ifaces",
                set(),
            )
            if str(value).strip()
        }

        return bool(candidates & managed)
    def _is_public_ipv4_text(self, ip: Optional[str]) -> bool:
        try:
            x = ipaddress.IPv4Address(str(ip or "").strip())
            return not (
                x.is_private
                or x.is_loopback
                or x.is_link_local
                or x.is_multicast
                or x.is_reserved
                or x.is_unspecified
            )
        except Exception:
            return False

    def _discover_router_public_ipv4(self, *, force: bool = False) -> Optional[str]:
        now = time.time()
        cached = str(self.public_ip_observed or "").strip()

        if (not force) and cached and ((now - self._public_ip_last_refresh) < self._public_ip_refresh_ttl):
            return cached

        headers = {
            "User-Agent": f"PythonRouter/{socket.gethostname()}",
            "Accept": "text/plain",
        }

        for url in self._public_ip_probe_urls:
            try:
                resp = requests.get(url, headers=headers, timeout=self._public_ip_probe_timeout)
                text = str(resp.text or "").strip()
                if "\n" in text:
                    text = text.splitlines()[0].strip()

                if resp.ok and self._is_public_ipv4_text(text):
                    self.public_ip_observed = text
                    self._public_ip_last_refresh = now
                    self.router_logger.log_message(
                        f"[Router][WAN] 🌐 Observed public IPv4 {text} via {url}"
                    )
                    return text
            except Exception:
                continue

        self._public_ip_last_refresh = now
        if self._is_public_ipv4_text(cached):
            return cached
        return None

    def _sync_nat_public_identity(self, *, reason: str = "manual", force: bool = False) -> Optional[str]:
        nm = getattr(self, "nat_manager", None)
        if nm is None:
            return None

        wan_full = str(self.interface_out_full_name or "").strip()
        wan_friendly = str(self.interface_out_friendly_name or "").strip()
        local_wan_ip = str(self.router_ip_out or "").strip()
        gateway_ip = str(self.router_gateway_out_ip or "").strip() or None

        dns_servers: list[str] = []
        try:
            if wan_friendly:
                dns_servers = self._get_windows_dns_servers(wan_friendly)
        except Exception:
            dns_servers = []

        observed_public = self._discover_router_public_ipv4(force=force)
        chosen_public = observed_public or (local_wan_ip if local_wan_ip else None)

        if not chosen_public:
            self.router_logger.log_message(
                f"[Router][WAN] ⚠️ NAT public identity sync skipped ({reason}): no WAN/public IP available"
            )
            return None

        try:
            nm.set_router_internal_ip(self.router_ip_in)
        except Exception as e:
            self.router_logger.log_message(f"[Router][WAN] ⚠️ NAT set_router_internal_ip failed: {e}")

        try:
            nm.set_public_ips(chosen_public, resync=False)
        except Exception as e:
            self.router_logger.log_message(f"[Router][WAN] ⚠️ NAT set_public_ips failed: {e}")

        try:
            if wan_full:
                nm.set_uplink_public_ip(wan_full, chosen_public, resync=False)
        except Exception as e:
            self.router_logger.log_message(f"[Router][WAN] ⚠️ NAT set_uplink_public_ip failed: {e}")

        try:
            old_marked = self._nat_last_marked_public_on_lan
            if local_wan_ip and local_wan_ip != chosen_public:
                if old_marked and old_marked != local_wan_ip:
                    nm.unmark_public_ip_on_lan(old_marked, resync=False)
                nm.mark_public_ip_on_lan(local_wan_ip, resync=False)
                self._nat_last_marked_public_on_lan = local_wan_ip
            else:
                if old_marked:
                    nm.unmark_public_ip_on_lan(old_marked, resync=False)
                self._nat_last_marked_public_on_lan = None
        except Exception as e:
            self.router_logger.log_message(f"[Router][WAN] ⚠️ NAT mark/unmark_public_ip_on_lan failed: {e}")

        try:
            nm.on_wan_recovered(
                iface_name=wan_full or None,
                public_ip=chosen_public,
                gateway_ip=gateway_ip,
                dns_servers=dns_servers,
                force_flush=bool(force),
                resync=False,
            )
        except Exception as e:
            self.router_logger.log_message(f"[Router][WAN] ⚠️ NAT on_wan_recovered failed: {e}")

        try:
            nm._resync_router_self_service_port_forwards()
        except Exception as e:
            self.router_logger.log_message(f"[Router][WAN] ⚠️ NAT final PFWD resync failed: {e}")

        self.router_logger.log_message(
            f"[Router][WAN] ✅ NAT public identity synced ({reason}): "
            f"public={chosen_public} onlink={local_wan_ip or '-'} "
            f"gw={gateway_ip or '-'} iface={wan_friendly or wan_full or '-'} dns={dns_servers}"
        )
        return chosen_public

    def _get_tshark_path(self) -> str | None:
        """Discover the path to tshark.exe (copied from your WiresharkManager)."""
        if getattr(sys, "frozen", False):
            tshark_exe = os.path.join(sys._MEIPASS, "tools", "Wireshark", "tshark.exe")
            if os.path.exists(tshark_exe):
                return tshark_exe

        server_dir = os.path.dirname(os.path.abspath(__file__))
        project_root = os.path.dirname(server_dir)
        tools_dir = os.path.join(project_root, "client", "tools", "Wireshark")
        candidate = os.path.join(tools_dir, "tshark.exe")
        if os.path.exists(candidate):
            return candidate

        system_tshark = shutil.which("tshark")
        if system_tshark:
            return system_tshark

        self.router_logger.log_message(
            "[Router] Error: tshark.exe not found. Cannot discover interfaces via tshark -D.")
        return None

    def _initialize_interface_discovery(self):
        """Discover current tshark interfaces without retaining stale runs.

        Start/stop can invoke discovery repeatedly on one manager instance. The
        previous implementation appended to the old snapshot, producing the
        observed 20 -> 40 -> 60 interface growth.
        """
        self._tshark_path = self._get_tshark_path()
        if not self._tshark_path:
            self._discovered_tshark_interfaces = []
            self.router_logger.log_message("[Router] Cannot perform interface discovery: tshark not found.")
            return

        self.router_logger.log_message("[Router] Discovering network interfaces via tshark -D...")
        try:
            proc = subprocess.run(
                [self._tshark_path, "-D"],
                capture_output=True,
                text=True,
                check=False,
                timeout=20,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode != 0:
                raise RuntimeError(
                    f"tshark -D exited {proc.returncode}: "
                    f"{(proc.stderr or proc.stdout or '').strip()}"
                )

            pattern = re.compile(r"(\d+)\.\s+([^(]+?)(?:\s*\((.*)\))?\s*$")
            snapshot = []
            seen_full_names = set()
            for raw_line in (proc.stdout or "").splitlines():
                line = raw_line.strip()
                if not line:
                    continue
                match = pattern.match(line)
                if not match:
                    continue
                full_name = str(match.group(2) or "").strip()
                friendly_name = str(match.group(3) or "").strip()
                if not full_name:
                    continue
                key = full_name.casefold()
                if key in seen_full_names:
                    continue
                seen_full_names.add(key)
                snapshot.append({
                    "id": str(match.group(1)),
                    "full_name": full_name,
                    "friendly_name": friendly_name,
                })

            self._discovered_tshark_interfaces = snapshot
            self.router_logger.log_message(
                f"[Router] Discovered {len(snapshot)} unique interfaces via tshark."
            )
        except Exception as exc:
            self._discovered_tshark_interfaces = []
            self.router_logger.log_message(
                f"[Router] Error during tshark interface discovery: {exc}"
            )

    def _configure_firewall_rules(self):
        """
        Adds firewall rules to allow traffic on the OUT interface.
        Note: Loopback doesn't typically need explicit firewall rules
        for routing traffic, as it's local to the host.
        """
        try:
            if not self.interface_out_friendly_name:
                self.router_logger.log_message("[Firewall] Skipping firewall rule configuration: OUT interface not found.")
                return

            for direction_str in ["Outbound", "Inbound"]:
                rule_name = f"PythonRouter-Allow-{direction_str}-{self.interface_out_friendly_name}"
                direction_flag = "Out" if direction_str == "Outbound" else "In"

                # Check if rule already exists to prevent duplicates on successive runs
                # Use a specific PowerShell command that returns null/empty if rule doesn't exist
                check_rule_cmd = ["powershell.exe", "-Command",
                                  f"Get-NetFirewallRule -DisplayName '{rule_name}' -ErrorAction SilentlyContinue | Select-Object -ExpandProperty DisplayName"]
                check_result = subprocess.run(check_rule_cmd, capture_output=True, text=True,
                                              creationflags=subprocess.CREATE_NO_WINDOW)

                if check_result.stdout.strip() == rule_name:
                    self.router_logger.log_message(f"[Firewall] Rule already exists: {rule_name}. Skipping.")
                    continue

                ps_command = [
                    "powershell.exe",
                    "-Command",
                    f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction {direction_flag} "
                    f"-InterfaceAlias '{self.interface_out_friendly_name}' -Action Allow -Profile Any -Protocol Any"
                ]

                result = subprocess.run(ps_command, capture_output=True, text=True,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    self.router_logger.log_message(f"[Firewall] ✅ Rule added: {rule_name}")
                else:
                    self.router_logger.log_message(
                        f"[Firewall] ⚠️ Failed to add rule: {rule_name}. STDERR: {result.stderr.strip()}")
        except Exception as e:
            self.router_logger.log_message(f"[Firewall] ❌ Unexpected error adding rules: {e}")

    def _remove_firewall_rules(self):
        """Removes any firewall rules added by this router."""
        try:
            # Using a wildcard pattern to ensure all rules created by this router are removed
            rule_name_pattern = "PythonRouter-Allow-*"
            ps_command = ["powershell.exe", "-Command",
                          f"Remove-NetFirewallRule -DisplayName '{rule_name_pattern}' -ErrorAction SilentlyContinue"]
            result = subprocess.run(ps_command, capture_output=True, text=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            if result.returncode == 0:
                # Check stdout for specific text indicating rules were found and removed
                if "No matching firewall rules found" not in result.stdout:
                    self.router_logger.log_message(f"[Firewall] 🧹 Removed rules matching: {rule_name_pattern}")
                else:
                    self.router_logger.log_message(f"[Firewall] No rules found to remove matching: {rule_name_pattern}")
            else:
                self.router_logger.log_message(
                    f"[Firewall] ⚠️ Failed to remove rules matching: {rule_name_pattern}. STDERR: {result.stderr.strip()}")
        except Exception as e:
            self.router_logger.log_message(f"[Firewall] ❌ Unexpected error removing rules: {e}")

    def _execute_netsh(self, full_netsh_command_args: list[str]) -> bool:
        """
        Helper to run netsh commands.
        Takes the full list of arguments *after* 'netsh interface ipv4'.
        """
        full_command = ["netsh", "interface", "ipv4"] + full_netsh_command_args
        try:
            self.router_logger.log_message(f"[Netsh] Executing: {' '.join(full_command)}")
            result = subprocess.run(
                full_command, capture_output=True, text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            stdout = result.stdout.strip()
            stderr = result.stderr.strip()

            if result.returncode == 0:
                if stdout:
                    self.router_logger.log_message(f"[Netsh] STDOUT: {stdout}")
                return True


            # Otherwise treat as real error
            self.router_logger.log_message(f"[Netsh] ERROR executing netsh (Return Code: {result.returncode}):")
            if stdout:
                self.router_logger.log_message(f"[Netsh] STDOUT: {stdout}")
            if stderr:
                self.router_logger.log_message(f"[Netsh] STDERR: {stderr}")
            return False

        except FileNotFoundError:
            self.router_logger.log_message("[Netsh] ERROR: 'netsh' command not found. Is Windows installed correctly?")
            return False
        except Exception as e:
            self.router_logger.log_message(f"[Netsh] UNEXPECTED ERROR during netsh execution: {e}")
            return False

    @staticmethod
    def _powershell_literal(value: Any) -> str:
        """Return a safe single-quoted PowerShell literal."""
        return "'" + str(value or "").replace("'", "''") + "'"

    @staticmethod
    def _windows_is_admin() -> bool:
        if os.name != "nt":
            return True
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False

    @staticmethod
    def _netmask_prefix_length(netmask: str) -> int:
        return ipaddress.IPv4Network(
            f"0.0.0.0/{str(netmask).strip()}", strict=False
        ).prefixlen

    @staticmethod
    def _is_usable_unicast_ipv4(value: Any) -> bool:
        try:
            address = ipaddress.IPv4Address(str(value or "").strip())
        except Exception:
            return False
        return not (
            address.is_link_local
            or address.is_loopback
            or address.is_unspecified
            or address.is_multicast
            or address == ipaddress.IPv4Address("255.255.255.255")
        )

    def _resolve_psutil_interface_name(self, iface_friendly_name: str) -> Optional[str]:
        wanted = str(iface_friendly_name or "").strip().casefold()
        if not wanted:
            return None
        for candidate in psutil.net_if_addrs().keys():
            if str(candidate).strip().casefold() == wanted:
                return str(candidate)
        return None

    def _current_interface_ipv4(self, iface_friendly_name: str, *, usable_only: bool = False):
        resolved = self._resolve_psutil_interface_name(iface_friendly_name)
        if not resolved:
            return None, None
        for addr in psutil.net_if_addrs().get(resolved, []):
            if addr.family != socket.AF_INET:
                continue
            if usable_only and not self._is_usable_unicast_ipv4(addr.address):
                continue
            return str(addr.address), str(addr.netmask or "255.255.255.0")
        return None, None

    def _verify_interface_ipv4(self, iface_friendly_name: str, ip_address: str,
                               netmask: str, timeout: float = 10.0) -> bool:
        deadline = time.monotonic() + max(1.0, float(timeout))
        while time.monotonic() < deadline:
            current_ip, current_mask = self._current_interface_ipv4(iface_friendly_name)
            if current_ip == str(ip_address) and current_mask == str(netmask):
                return True
            time.sleep(0.25)
        return False

    def _run_network_powershell(self, script: str, operation: str) -> bool:
        command = [
            "powershell.exe", "-NoProfile", "-NonInteractive",
            "-ExecutionPolicy", "Bypass", "-Command", script,
        ]
        try:
            result = subprocess.run(
                command,
                capture_output=True,
                text=True,
                timeout=30,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except Exception as exc:
            self.router_logger.log_message(
                f"[Router][IPv4] PowerShell {operation} could not run: {exc}"
            )
            return False

        stdout = (result.stdout or "").strip()
        stderr = (result.stderr or "").strip()
        if result.returncode == 0:
            if stdout:
                self.router_logger.log_message(
                    f"[Router][IPv4] PowerShell {operation}: {stdout}"
                )
            return True

        self.router_logger.log_message(
            f"[Router][IPv4] PowerShell {operation} failed rc={result.returncode}."
        )
        if stdout:
            self.router_logger.log_message(f"[Router][IPv4] STDOUT: {stdout}")
        if stderr:
            self.router_logger.log_message(f"[Router][IPv4] STDERR: {stderr}")
        return False

    def _set_interface_dhcp(self, iface_friendly_name: str, *, reset_dns: bool = True,
                            trigger_renew: bool = False, record_change: bool = True) -> bool:
        alias = str(iface_friendly_name or "").strip()
        if not alias:
            return False
        if not self._windows_is_admin():
            self.router_logger.log_message(
                f"[Router][IPv4] ⚠️ DHCP configuration for '{alias}' requires an elevated Administrator process."
            )
        ps_alias = self._powershell_literal(alias)
        dns_line = (
            "Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex "
            "-ResetServerAddresses -ErrorAction SilentlyContinue;"
            if reset_dns else ""
        )
        script = f"""
$ErrorActionPreference = 'Stop'
$alias = {ps_alias}
$adapter = Get-NetAdapter -Name $alias -IncludeHidden -ErrorAction Stop |
    Sort-Object ifIndex | Select-Object -First 1
if ($adapter.Status -eq 'Disabled') {{
    Enable-NetAdapter -InputObject $adapter -Confirm:$false -ErrorAction Stop
    Start-Sleep -Milliseconds 400
    $adapter = Get-NetAdapter -Name $alias -IncludeHidden -ErrorAction Stop |
        Sort-Object ifIndex | Select-Object -First 1
}}
Set-NetIPInterface -InterfaceIndex $adapter.ifIndex -AddressFamily IPv4 -Dhcp Enabled -ErrorAction Stop
{dns_line}
Write-Output ('DHCP enabled on ' + $alias + ' ifIndex=' + $adapter.ifIndex)
"""
        ok = self._run_network_powershell(script, f"enable DHCP on {alias}")
        if not ok:
            ok = self._execute_netsh([
                "set", "address", f"name={alias}", "source=dhcp"
            ])
            if reset_dns:
                self._execute_netsh([
                    "set", "dnsservers", f"name={alias}", "source=dhcp"
                ])
        if not ok:
            return False

        if record_change:
            self._router_changed_ipv4_aliases[alias.casefold()] = "dhcp"

        if trigger_renew:
            try:
                subprocess.run(
                    ["ipconfig", "/renew", alias],
                    capture_output=True,
                    text=True,
                    timeout=35,
                    check=False,
                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
                )
            except Exception as exc:
                self.router_logger.log_message(
                    f"[Router][DHCP] Renew for '{alias}' returned early: {exc}"
                )
        return True

    def _assign_ip_to_interface(self, iface_friendly_name: str, ip_address: str, netmask: str,
                                gateway: str = "") -> bool:
        """Assign and verify IPv4 using NetTCPIP cmdlets, then netsh fallback."""
        alias = str(iface_friendly_name or "").strip()
        try:
            address = str(ipaddress.IPv4Address(str(ip_address).strip()))
            prefix_length = self._netmask_prefix_length(netmask)
            mask = str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_length}").netmask)
            gateway_address = (
                str(ipaddress.IPv4Address(str(gateway).strip()))
                if str(gateway or "").strip() else ""
            )
        except Exception as exc:
            self.router_logger.log_message(
                f"[Router][IPv4] Invalid static configuration for '{alias}': {exc}"
            )
            return False

        if not alias:
            self.router_logger.log_message("[Router][IPv4] Empty interface alias; cannot assign address.")
            return False

        self.router_logger.log_message(
            f"[Router] Assigning IP {address}/{mask} to '{alias}'..."
        )
        current_ip, current_mask = self._current_interface_ipv4(alias)
        if current_ip == address and current_mask == mask:
            self.router_logger.log_message(
                f"[Router][IPv4] ✅ '{alias}' already owns {address}/{mask}."
            )
            return True

        if not self._windows_is_admin():
            self.router_logger.log_message(
                f"[Router][IPv4] ⚠️ Static IP assignment for '{alias}' requires Run as administrator."
            )
        ps_alias = self._powershell_literal(alias)
        ps_ip = self._powershell_literal(address)
        ps_gateway = self._powershell_literal(gateway_address)
        route_block = ""
        if gateway_address:
            route_block = f"""
Get-NetRoute -InterfaceIndex $ifIndex -AddressFamily IPv4 -DestinationPrefix '0.0.0.0/0' -ErrorAction SilentlyContinue |
    Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
New-NetRoute -InterfaceIndex $ifIndex -DestinationPrefix '0.0.0.0/0' -NextHop {ps_gateway} -RouteMetric 1 -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
"""

        script = f"""
$ErrorActionPreference = 'Stop'
$alias = {ps_alias}
$targetIp = {ps_ip}
$adapter = Get-NetAdapter -Name $alias -IncludeHidden -ErrorAction Stop |
    Sort-Object ifIndex | Select-Object -First 1
if ($adapter.Status -eq 'Disabled') {{
    Enable-NetAdapter -InputObject $adapter -Confirm:$false -ErrorAction Stop
    Start-Sleep -Milliseconds 500
    $adapter = Get-NetAdapter -Name $alias -IncludeHidden -ErrorAction Stop |
        Sort-Object ifIndex | Select-Object -First 1
}}
$ifIndex = $adapter.ifIndex
Set-NetIPInterface -InterfaceIndex $ifIndex -AddressFamily IPv4 -Dhcp Disabled -ErrorAction Stop
Start-Sleep -Milliseconds 250
Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -ErrorAction SilentlyContinue |
    Where-Object {{ $_.IPAddress -ne $targetIp }} |
    Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
$existing = Get-NetIPAddress -InterfaceIndex $ifIndex -AddressFamily IPv4 -IPAddress $targetIp -ErrorAction SilentlyContinue
if (-not $existing) {{
    New-NetIPAddress -InterfaceIndex $ifIndex -IPAddress $targetIp -PrefixLength {prefix_length} -Type Unicast -PolicyStore ActiveStore -ErrorAction Stop | Out-Null
}}
{route_block}
Write-Output ('Static IPv4 ' + $targetIp + '/{prefix_length} installed on ' + $alias + ' ifIndex=' + $ifIndex)
"""
        command_ok = self._run_network_powershell(script, f"assign {address} to {alias}")
        if not command_ok:
            netsh_args = [
                "set", "address", f"name={alias}", "source=static",
                f"address={address}", f"mask={mask}",
                f"gateway={gateway_address}" if gateway_address else "gateway=none",
            ]
            if gateway_address:
                netsh_args.append("gwmetric=1")
            command_ok = self._execute_netsh(netsh_args)

        verified = self._verify_interface_ipv4(alias, address, mask, timeout=10.0)
        if not verified:
            admin_hint = ""
            if not self._windows_is_admin():
                admin_hint = " The application is not elevated; restart it with Run as administrator."
            self.router_logger.log_message(
                f"[Router][IPv4] ❌ '{alias}' did not acquire {address}/{mask} after "
                f"PowerShell/netsh assignment.{admin_hint}"
            )
            return False

        self._router_changed_ipv4_aliases[alias.casefold()] = "static"
        self.router_logger.log_message(
            f"[Router][IPv4] ✅ Verified {address}/{mask} on '{alias}'."
        )
        return True

    def _get_system_networks(self, router_ip_in: str = None, router_netmask_in: str = "255.255.255.0") -> list[
        ipaddress.IPv4Network]:
        """Gets all currently active IPv4 networks on the system using psutil,
           and adds a user-provided network for conflict checking."""
        active_networks = []
        try:
            for iface_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address and addr.netmask:
                        try:
                            network_obj = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                            active_networks.append(network_obj)
                        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                            self.router_logger.log_message(
                                f"[Router] Warning: Could not parse network {addr.address}/{addr.netmask}: {e}")

            # --- NEW: Check for the provided IN interface IP and add it to the list
            if router_ip_in:
                try:
                    router_in_network = ipaddress.ip_network(f"{router_ip_in}/{router_netmask_in}", strict=False)
                    active_networks.append(router_in_network)
                    self.router_logger.log_message(
                        f"[Router] ✅ User-provided IN network {router_in_network} added to conflict list."
                    )
                except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                    self.router_logger.log_message(
                        f"[Router] Warning: Could not parse user-provided IN network {router_ip_in}/{router_netmask_in}: {e}"
                    )

        except Exception as e:
            self.router_logger.log_message(f"[Router] Error getting system networks via psutil: {e}")
        return active_networks

    def _find_unused_private_subnet(self, existing_networks: list[ipaddress.IPv4Network],
                                    subnet_size: int = 24) -> str | None:
        """
        Finds the first available /24 private subnet from a predefined list that
        does not conflict with existing_networks.
        Returns IP address (e.g., '192.168.X.1') from the first available subnet.
        """
        self.router_logger.log_message("[Router] Searching for an unused private subnet for IN interface...")
        for potential_network_str in self.PRIVATE_SUBNETS_TO_TRY:
            try:
                potential_network = ipaddress.ip_network(potential_network_str, strict=False)

                conflicts = False
                for existing_net in existing_networks:
                    if potential_network.overlaps(existing_net):
                        self.router_logger.log_message(
                            f"[Router] Subnet {potential_network} conflicts with {existing_net}. Skipping.")
                        conflicts = True
                        break

                if not conflicts:
                    router_ip = str(potential_network.network_address + 1)
                    self.router_logger.log_message(
                        f"[Router] Found unused subnet: {potential_network}. Router IN IP: {router_ip}")
                    return router_ip
            except ValueError as e:
                self.router_logger.log_message(
                    f"[Router] Invalid potential subnet '{potential_network_str}': {e}")

        self.router_logger.log_message("[Router] ERROR: No unused private subnet found from predefined list.")
        return None

    def _inject_dependencies(self):
        """
        Injects shared dependencies (like the sniffer/sender) into all manager classes
        that are designed to accept it.
        """
        self.router_logger.log_message("[Router] Injecting dependencies into managers...")

        # Create a list of all manager attributes on this class instance
        managers = [
            getattr(self, attr)
            for attr in dir(self)
            if not callable(getattr(self, attr)) and not attr.startswith('__')
        ]
        for manager in managers:
            if manager is not None:
                # Check if the manager has a placeholder for the sniffer instance
                if hasattr(manager, 'sniffer'):
                    # Use setattr to assign the sniffer instance
                    setattr(manager, 'sniffer', self.sniffer)
                    self.router_logger.log_message(f"[Sniffer] -> Injected sniffer into {manager.__class__.__name__}")

    def _ps_quote(self, value: str | None) -> str:
        return str(value or "").replace("'", "''")

    def _run_powershell_hidden(self, script: str, label: str = "PowerShell") -> bool:
        try:
            result = subprocess.run(
                [
                    "powershell.exe",
                    "-NoProfile",
                    "-ExecutionPolicy", "Bypass",
                    "-Command", script
                ],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0)
            )
            stdout = (result.stdout or "").strip()
            stderr = (result.stderr or "").strip()

            if result.returncode == 0:
                if stdout:
                    self.router_logger.log_message(f"[{label}] {stdout}")
                return True

            self.router_logger.log_message(f"[{label}] ❌ Failed with code {result.returncode}")
            if stdout:
                self.router_logger.log_message(f"[{label}] STDOUT: {stdout}")
            if stderr:
                self.router_logger.log_message(f"[{label}] STDERR: {stderr}")
            return False
        except Exception as e:
            self.router_logger.log_message(f"[{label}] ❌ Exception: {e}")
            return False

    def _configure_host_preserving_upstream_mode(
            self,
            preferred_metric: int = 5,
            internal_metric: int = 500,
            aux_metric: int = 550,
            loopback_metric: int = 900,
    ) -> bool:
        """
        Configure Windows so the HOST keeps using the real upstream router for its own internet,
        while this Python router can still forward/NAT transit traffic.

        What this does:
          - pins the host's preferred default path to the active OUT interface
          - de-prioritizes internal/router-side adapters
          - removes default routes from internal/router-side adapters
          - enables forwarding on LAN/WAN router interfaces
          - prevents loopback/internal adapters from influencing host default routing
        """
        wan_alias = (self.interface_out_friendly_name or "").strip()
        wan_gateway = (self.router_gateway_out_ip or "").strip()

        if not wan_alias:
            self.router_logger.log_message(
                "[HostRoute] ⚠️ No active OUT interface alias is set. Skipping host-preserving upstream mode."
            )
            return False

        lan_router_aliases: list[str] = []
        for alias in (
                self.interface_in_friendly_name,
                self.interface_ethernet_2_friendly_name,
                self.interface_lac_friendly_name,
                self.interface_lac_2_friendly_name,
                self.interface_wifi_friendly_name,
        ):
            alias = (alias or "").strip()
            if alias and alias.lower() != wan_alias.lower() and alias not in lan_router_aliases:
                lan_router_aliases.append(alias)

        loopback_alias = ""
        if self.interface_loopback_full_name:
            loopback_alias = self._get_friendly_name_from_full(self.interface_loopback_full_name) or ""
            loopback_alias = loopback_alias.strip()

        wan_alias_ps = self._ps_quote(wan_alias)
        wan_gateway_ps = self._ps_quote(wan_gateway)
        loopback_alias_ps = self._ps_quote(loopback_alias)

        lan_aliases_ps = ", ".join(f"'{self._ps_quote(x)}'" for x in lan_router_aliases)
        if not lan_aliases_ps:
            lan_aliases_ps = ""

        script = f"""
$ErrorActionPreference = "Stop"

$wanAlias = '{wan_alias_ps}'
$wanGateway = '{wan_gateway_ps}'
$loopbackAlias = '{loopback_alias_ps}'
$lanAliases = @({lan_aliases_ps})

function Apply-IfPolicy([string]$Alias, [int]$Metric, [string]$Forwarding, [string]$IgnoreDefaultRoutes) {{
    if ([string]::IsNullOrWhiteSpace($Alias)) {{ return }}

    $if4 = Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -ErrorAction SilentlyContinue
    if ($if4) {{
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -AutomaticMetric Disabled -ErrorAction SilentlyContinue | Out-Null
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -InterfaceMetric $Metric -ErrorAction SilentlyContinue | Out-Null
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -Forwarding $Forwarding -ErrorAction SilentlyContinue | Out-Null
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv4 -IgnoreDefaultRoutes $IgnoreDefaultRoutes -ErrorAction SilentlyContinue | Out-Null
    }}

    $if6 = Get-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv6 -ErrorAction SilentlyContinue
    if ($if6) {{
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv6 -AutomaticMetric Disabled -ErrorAction SilentlyContinue | Out-Null
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv6 -InterfaceMetric ($Metric + 10) -ErrorAction SilentlyContinue | Out-Null
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv6 -Forwarding $Forwarding -ErrorAction SilentlyContinue | Out-Null
        Set-NetIPInterface -InterfaceAlias $Alias -AddressFamily IPv6 -IgnoreDefaultRoutes $IgnoreDefaultRoutes -ErrorAction SilentlyContinue | Out-Null
    }}
}}

function Remove-DefaultRoutesOnAlias([string]$Alias) {{
    if ([string]::IsNullOrWhiteSpace($Alias)) {{ return }}

    Get-NetRoute -InterfaceAlias $Alias -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null

    Get-NetRoute -InterfaceAlias $Alias -DestinationPrefix "::/0" -ErrorAction SilentlyContinue |
        Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue | Out-Null
}}

# 1) Prefer the real WAN/upstream for HOST traffic
Apply-IfPolicy -Alias $wanAlias -Metric {preferred_metric} -Forwarding "Enabled" -IgnoreDefaultRoutes "Disabled"

# 2) De-prioritize all router-side LAN/aux interfaces and strip any default routes from them
foreach ($alias in $lanAliases) {{
    if (-not [string]::IsNullOrWhiteSpace($alias) -and $alias -ne $wanAlias) {{
        Apply-IfPolicy -Alias $alias -Metric {internal_metric} -Forwarding "Enabled" -IgnoreDefaultRoutes "Enabled"
        Remove-DefaultRoutesOnAlias -Alias $alias
    }}
}}

# 3) Loopback should never influence host default routing
if (-not [string]::IsNullOrWhiteSpace($loopbackAlias) -and $loopbackAlias -ne $wanAlias) {{
    Apply-IfPolicy -Alias $loopbackAlias -Metric {loopback_metric} -Forwarding "Disabled" -IgnoreDefaultRoutes "Enabled"
    Remove-DefaultRoutesOnAlias -Alias $loopbackAlias
}}

# 4) Make sure the WAN has a default route if the OS somehow lost it
if (-not [string]::IsNullOrWhiteSpace($wanAlias) -and -not [string]::IsNullOrWhiteSpace($wanGateway)) {{
    $existingWanDefault = @(
        Get-NetRoute -InterfaceAlias $wanAlias -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue
    )

    if (-not $existingWanDefault -or $existingWanDefault.Count -eq 0) {{
        New-NetRoute -InterfaceAlias $wanAlias `
                     -DestinationPrefix "0.0.0.0/0" `
                     -NextHop $wanGateway `
                     -RouteMetric {preferred_metric} `
                     -PolicyStore ActiveStore `
                     -ErrorAction SilentlyContinue | Out-Null
    }}
}}

Write-Output ("Configured host-preserving upstream mode. WAN='{0}' GW='{1}' LANs={2}" -f $wanAlias, $wanGateway, ($lanAliases -join ", "))
"""
        ok = self._run_powershell_hidden(script, label="HostRoute")
        if ok:
            self.router_logger.log_message(
                f"[HostRoute] ✅ Host-preserving upstream mode active. "
                f"Host default path stays on '{wan_alias}' via {wan_gateway or 'existing OS route'}."
            )
        else:
            self.router_logger.log_message(
                "[HostRoute] ⚠️ Could not fully apply host-preserving upstream mode."
            )
        return ok
    def _find_active_default_route_interface(self) -> Tuple[Optional[str], Optional[str]]:
        """Return the Windows interface alias and IPv4 next hop for the best default route."""
        if os.name != "nt":
            return None, None
        script = r'''
$ErrorActionPreference = "SilentlyContinue"
$route = Get-NetRoute -AddressFamily IPv4 -DestinationPrefix "0.0.0.0/0" |
    Where-Object { $_.State -ne "Invalid" -and $_.NextHop -ne "0.0.0.0" } |
    Sort-Object @{Expression={$_.RouteMetric + $_.InterfaceMetric}}, RouteMetric, InterfaceMetric |
    Select-Object -First 1 InterfaceAlias,NextHop
if ($route) { Write-Output ($route.InterfaceAlias + "|" + $route.NextHop) }
'''
        try:
            kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": 5,
                "check": False,
            }
            kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            result = subprocess.run(
                ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                **kwargs,
            )
            line = next((x.strip() for x in (result.stdout or "").splitlines() if "|" in x), "")
            if line:
                alias, gateway = line.split("|", 1)
                return alias.strip() or None, gateway.strip() or None
        except Exception:
            pass
        return None, None

    @staticmethod
    def _usable_interface_ipv4(friendly_name: str) -> Tuple[Optional[str], Optional[str]]:
        for addr in psutil.net_if_addrs().get(str(friendly_name or ""), []):
            if addr.family != socket.AF_INET:
                continue
            try:
                parsed = ipaddress.IPv4Address(addr.address)
            except Exception:
                continue
            if parsed.is_loopback or parsed.is_link_local or parsed.is_unspecified or parsed.is_multicast:
                continue
            return str(parsed), str(addr.netmask or "255.255.255.0")
        return None, None

    def _auto_configure_interfaces(self, use_dhcp_out, use_dhcp_in, router_ip_in: str = None,
                                   router_netmask_in: str = "255.255.255.0", router_ip_out: str = None,
                                   router_netmask_out: str = "255.255.255.0"):
        """
        Automatically finds and configures IN, OUT, and Loopback interfaces.
        Sets their IP addresses dynamically (for IN/OUT) and determines the default gateway.
        Adds a new parameter `use_os_gateway` to control the default gateway.
        """
        in_iface_info = None
        out_iface_info = None
        loopback_iface_info = None
        ethernet_2_info = None
        lac_2_info = None
        lac_2_info_2 = None
        self.router_logger.log_message("[Router] Attempting to auto-configure IN, OUT, and Loopback interfaces...")

        for iface in self._discovered_tshark_interfaces:
            if self._is_wifi_host_interface(
                    iface.get("full_name"),
                    iface.get("friendly_name"),
            ):
                self.router_logger.log_message(
                    "[Router][WiFi] Keeping the Wi-Fi Direct host adapter "
                    f"out of LAC/static-IP auto-configuration: "
                    f"{iface.get('friendly_name') or iface.get('full_name')}"
                )
                continue
            name = iface['friendly_name'].lower()
            match = re.search(r'\*[\s]?(\d+)$', name)
            if match and int(match.group(1)) == 1:
                lac_2_info = iface
                self.router_logger.log_message(
                    f"[Router] Found exact match for LAC 1: {iface['friendly_name']}")
            if (match and int(match.group(1)) == 12) or (match and int(match.group(1)) == 2):
                lac_2_info_2 = iface
                self.router_logger.log_message(
                    f"[Router] Found exact match for LAC 2: {iface['friendly_name']}")

        if lac_2_info:
            self.router_logger.log_message(
                f"[Router] Found lowest-numbered LAC: {lac_2_info['friendly_name']}")
        if lac_2_info_2:
            self.router_logger.log_message(
                f"[Router] Found second-lowest-numbered LAC: {lac_2_info_2['friendly_name']}")
        for iface_info in self._discovered_tshark_interfaces:
            if self._is_wifi_host_interface(
                    iface_info.get("full_name"),
                    iface_info.get("friendly_name"),
            ):
                continue
            # Check for IN interface
            if self.DEFAULT_IN_IFACE_FRIENDLY_NAME.lower() == iface_info[
                'friendly_name'].lower() and in_iface_info is None:
                in_iface_info = iface_info
                self.router_logger.log_message(
                    f"[Router] Found IN interface: {self.DEFAULT_IN_IFACE_FRIENDLY_NAME} as {in_iface_info['full_name']}")

            # Check for OUT interface
            if self.DEFAULT_OUT_IFACE_FRIENDLY_NAME.lower() in iface_info[
                'friendly_name'].lower() and out_iface_info is None:
                out_iface_info = iface_info
                self.router_logger.log_message(
                    f"[Router] Found OUT interface: {self.DEFAULT_OUT_IFACE_FRIENDLY_NAME} as {out_iface_info['full_name']}")

            # NEW: Check for Loopback interface
            # Common names for loopback include 'Loopback', 'lo', or an empty friendly name with 'loopback' in full name
            if ("loopback" in iface_info['full_name'].lower() or \
                self.DEFAULT_LOOPBACK_IFACE_FRIENDLY_NAME.lower() in iface_info['friendly_name'].lower() or \
                iface_info['friendly_name'].lower() == "lo") and loopback_iface_info is None:
                loopback_iface_info = iface_info
                self.router_logger.log_message(
                    f"[Router] Found Loopback interface: {loopback_iface_info['full_name']} (Friendly: {loopback_iface_info['friendly_name']})")
            if ("ethernet 2" in iface_info['friendly_name'].lower()):
                ethernet_2_info = iface_info
                self.router_logger.log_message(
                    f"[Router] Found Ethernet 2 interface")
            if in_iface_info is not None and out_iface_info is not None and loopback_iface_info is not None and ethernet_2_info is not None:
                break  # All found, exit loop
        # AT&T Internet Air IP Passthrough can put the host's public default
        # route on an adapter named "Ethernet". Prefer the route Windows is
        # actually using when the old name-based Wi-Fi OUT choice has no route.
        default_alias, default_gateway = self._find_active_default_route_interface()
        if default_alias:
            route_iface = next(
                (item for item in self._discovered_tshark_interfaces
                 if str(item.get("friendly_name") or "").casefold() == default_alias.casefold()),
                None,
            )
            named_out_has_gateway = False
            if out_iface_info is not None:
                try:
                    named_out_has_gateway = bool(
                        self._get_default_gateway_for_interface(out_iface_info.get("friendly_name", ""))
                    )
                except Exception:
                    named_out_has_gateway = False

            if route_iface is not None and (out_iface_info is None or not named_out_has_gateway):
                previous_out = out_iface_info
                out_iface_info = route_iface
                self.router_logger.log_message(
                    f"[Router][Uplink] 🧭 Using Windows default-route adapter "
                    f"'{default_alias}' via {default_gateway or 'existing route'} as OUT."
                )

                if in_iface_info is route_iface or (
                        in_iface_info and in_iface_info.get("full_name") == route_iface.get("full_name")
                ):
                    alternatives = [
                        item for item in self._discovered_tshark_interfaces
                        if item.get("full_name") != route_iface.get("full_name")
                        and not self._is_wifi_host_interface(item.get("full_name"), item.get("friendly_name"))
                        and "loopback" not in str(item.get("friendly_name") or "").casefold()
                    ]
                    preferred = []
                    if previous_out is not None and previous_out in alternatives:
                        preferred.append(previous_out)
                    preferred.extend(sorted(
                        alternatives,
                        key=lambda x: (
                            0 if any(token in str(x.get("friendly_name") or "").casefold()
                                     for token in ("ethernet 2", "local area connection", "vethernet")) else 1,
                            str(x.get("friendly_name") or "").casefold(),
                        ),
                    ))
                    if preferred:
                        in_iface_info = preferred[0]
                        self.router_logger.log_message(
                            f"[Router][Uplink] 🏠 Reassigned IN to "
                            f"'{in_iface_info.get('friendly_name')}' to keep WAN and LAN distinct."
                        )

        # Handle cases where IN or OUT are not found

        if in_iface_info is None or out_iface_info is None:
            self.router_logger.log_message(
                f"[Router] ERROR: Could not auto-configure required interfaces ('{self.DEFAULT_IN_IFACE_FRIENDLY_NAME}' and '{self.DEFAULT_OUT_IFACE_FRIENDLY_NAME}').")
            self.router_logger.log_message(
                f"[Router] Please check interface names and ensure they are active. Available: {[i['friendly_name'] for i in self._discovered_tshark_interfaces]}")

            self.interface_in_full_name = None
            self.interface_out_full_name = None
            self.interface_in_friendly_name = None
            self.interface_out_friendly_name = None
            self.mac_in = None
            self.mac_out = None
            self.interface_loopback_full_name = None  # Ensure loopback is also cleared on critical failure
            return False

        # Assign full and friendly names to instance attributes
        if (lac_2_info_2):
            self.interface_lac_2_full_name = lac_2_info_2["full_name"]
            self.interface_lac_2_friendly_name = lac_2_info_2["friendly_name"]
        if (lac_2_info):
            self.interface_lac_full_name = lac_2_info['full_name']
            self.interface_lac_friendly_name = lac_2_info['friendly_name']
        if (ethernet_2_info):
            self.interface_ethernet_2_full_name = ethernet_2_info['full_name']
            self.interface_ethernet_2_friendly_name = ethernet_2_info['friendly_name']
        self.interface_in_full_name = in_iface_info['full_name']
        self.interface_in_friendly_name = in_iface_info['friendly_name']
        self.interface_out_full_name = out_iface_info['full_name']
        self.interface_out_friendly_name = out_iface_info['friendly_name']
        if loopback_iface_info:  # Assign if found
            self.interface_loopback_full_name = loopback_iface_info['full_name']

        # Step 2: Determine IP configurations for OUT and IN interfaces
        # Call _get_system_networks initially with router_ip_in to include it in conflict checks
        system_active_networks = self._get_system_networks(router_ip_in, router_netmask_in)

        # --- Start of Logic for OUT (WAN) Interface ---
        current_out_ip = None
        current_out_netmask = None
        current_out_gateway = None

        if use_dhcp_out:
            self.router_logger.log_message(
                f"[Router][WanDHCP] 🌍 Enabling native DHCP on OUT interface '{self.interface_out_friendly_name}'.")

            self._set_interface_dhcp(
                self.interface_out_friendly_name,
                reset_dns=True,
                trigger_renew=False,
                record_change=False,
            )

            renew_kwargs = {
                "capture_output": True,
                "text": True,
                "timeout": 35,
                "check": False,
            }
            if os.name == "nt":
                renew_kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
            try:
                subprocess.run(
                    ["ipconfig", "/renew", self.interface_out_friendly_name],
                    **renew_kwargs,
                )
            except Exception as exc:
                self.router_logger.log_message(
                    f"[Router][WanDHCP] ⚠️ Native renew command returned early: {exc}"
                )

            # A DHCP OFFER/ACK can take longer than five seconds on Wi-Fi.
            # Poll until Windows has installed both a non-APIPA address and
            # the upstream default gateway used by the host itself.
            deadline = time.monotonic() + 35.0
            while time.monotonic() < deadline:
                current_out_ip = None
                current_out_netmask = None
                for addr in psutil.net_if_addrs().get(self.interface_out_friendly_name, []):
                    if addr.family != socket.AF_INET:
                        continue
                    try:
                        parsed = ipaddress.IPv4Address(addr.address)
                    except Exception:
                        continue
                    if parsed.is_link_local or parsed.is_loopback or parsed.is_unspecified:
                        continue
                    current_out_ip = addr.address
                    current_out_netmask = addr.netmask or "255.255.255.0"
                    break

                current_out_gateway = self._get_default_gateway_for_interface(
                    self.interface_out_friendly_name
                )
                if current_out_ip and current_out_netmask and current_out_gateway:
                    break
                time.sleep(1.0)

            if current_out_ip and current_out_netmask and current_out_gateway:
                self.router_logger.log_message(
                    "[Router][WanDHCP] ✅ Lease active: "
                    f"{current_out_ip}/{current_out_netmask} via {current_out_gateway}."
                )
            elif router_ip_out:
                current_out_ip = router_ip_out
                current_out_netmask = router_netmask_out
                current_out_gateway = self._get_default_gateway_for_interface(
                    self.interface_out_friendly_name
                )
                self.router_logger.log_message(
                    "[Router][WanDHCP] ⚠️ No complete DHCP lease was installed; "
                    f"using the explicitly supplied static WAN address {current_out_ip}/{current_out_netmask}."
                )
            else:
                self.router_logger.log_message(
                    "[Router][WanDHCP] ❌ No DHCP ACK/default gateway became active. "
                    "Refusing to invent a private WAN address because that would disconnect the host."
                )
                return False
        else:  # use_dhcp_out is False, so configure statically
            if router_ip_out:  # User explicitly provided static IP for OUT
                current_out_ip = router_ip_out
                current_out_netmask = router_netmask_out
                current_out_gateway = self._get_default_gateway_for_interface(self.interface_out_friendly_name)
                self.router_logger.log_message(
                    f"[Router] Using user-provided static IP for OUT interface: {current_out_ip}/{current_out_netmask}")
            else:  # No user-provided static IP for OUT, try to get current OS static config
                current_out_ip, current_out_netmask = self._usable_interface_ipv4(
                    self.interface_out_friendly_name
                )
                current_out_gateway = self._get_default_gateway_for_interface(
                    self.interface_out_friendly_name
                )
                if current_out_ip and current_out_netmask:
                    self.router_logger.log_message(
                        f"[Router] Using current static IP for OUT interface '{self.interface_out_friendly_name}': {current_out_ip}/{current_out_netmask}, Gateway: {current_out_gateway}")
                    if not current_out_gateway:
                        self.router_logger.log_message(
                            "[Router][Uplink] ⚠️ No IPv4 default gateway is active. "
                            "Starting in local-only/degraded mode; external socket opens are deferred."
                        )
                else:
                    self.router_logger.log_message(
                        "[Router] CRITICAL ERROR: Could not determine static IP for OUT interface. Please configure it manually or use DHCP.")
                    return False

        self.router_gateway_out_ip = current_out_gateway

        # Assign determined OUT interface details to router attributes
        self.router_ip_out = current_out_ip
        self.router_netmask_out = current_out_netmask
        self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}", strict=False)
        # The router_gateway_out_ip is already set based on the new logic.
        # --- End of Logic for OUT (WAN) Interface ---

        # --- Start of Logic for IN (LAN) Interface ---
        # Re-get system active networks after OUT interface IP is determined,
        # ensuring router_network_out is included for IN interface conflict checks.
        # This is crucial to prevent IN and OUT interfaces from being on the same subnet.
        system_active_networks_updated = self._get_system_networks(router_ip_in, router_netmask_in)
        existing_networks_for_in = system_active_networks_updated + [self.router_network_out]

        current_in_ip, current_in_netmask = None, None
        in_address_source = "static"

        if use_dhcp_in:
            self.router_logger.log_message(
                f"[Router] 🏠 Setting IN interface '{self.interface_in_friendly_name}' to DHCP.")
            dhcp_enabled = self._set_interface_dhcp(
                self.interface_in_friendly_name,
                reset_dns=True,
                trigger_renew=True,
                record_change=True,
            )
            if not dhcp_enabled:
                self.router_logger.log_message(
                    "[Router] ⚠️ Windows could not enable DHCP on IN; checking for an existing proper lease."
                )

            deadline = time.monotonic() + 20.0
            while time.monotonic() < deadline:
                current_in_ip, current_in_netmask = self._current_interface_ipv4(
                    self.interface_in_friendly_name, usable_only=True
                )
                if current_in_ip and current_in_netmask:
                    break
                time.sleep(0.5)

            if current_in_ip and current_in_netmask:
                in_address_source = "dhcp"
                self.router_logger.log_message(
                    f"[Router] ✅ IN interface obtained a proper DHCP lease: {current_in_ip}/{current_in_netmask}")
            else:
                observed_ip, observed_mask = self._current_interface_ipv4(
                    self.interface_in_friendly_name, usable_only=False
                )
                if observed_ip and not self._is_usable_unicast_ipv4(observed_ip):
                    self.router_logger.log_message(
                        f"[Router] ⚠️ Ignoring APIPA/non-routable IN address {observed_ip}/{observed_mask or '-'}; "
                        "it is not a DHCP lease."
                    )
                self.router_logger.log_message(
                    "[Router] DHCP IN did not receive a proper lease; selecting a private static fallback."
                )
                unused_in_ip = self._find_unused_private_subnet(existing_networks_for_in)
                if not unused_in_ip:
                    self.router_logger.log_message("[Router] CRITICAL ERROR: Failed to select an IN fallback address.")
                    return False
                current_in_ip = unused_in_ip
                current_in_netmask = "255.255.255.0"
                in_address_source = "static_fallback"
                self.router_logger.log_message(
                    f"[Router] Static fallback selected for IN '{self.interface_in_friendly_name}': "
                    f"{current_in_ip}/{current_in_netmask}")
        else:
            if router_ip_in:
                current_in_ip = router_ip_in
                current_in_netmask = router_netmask_in
                self.router_logger.log_message(
                    f"[Router] Using user-provided static IP for IN interface: {current_in_ip}/{current_in_netmask}")
            else:
                self.router_logger.log_message(
                    "[Router] No static IP provided for IN interface. Dynamically assigning a private one...")
                unused_in_ip = self._find_unused_private_subnet(existing_networks_for_in)
                if unused_in_ip:
                    current_in_ip = unused_in_ip
                    current_in_netmask = "255.255.255.0"
                    self.router_logger.log_message(
                        f"[Router] Dynamically assigned private IP for IN interface '{self.interface_in_friendly_name}': {current_in_ip}/{current_in_netmask}")
                else:
                    self.router_logger.log_message("[Router] CRITICAL ERROR: Failed to assign any IP to IN interface.")
                    return False

        # Assign determined IN interface details to router attributes
        self.router_ip_in = current_in_ip
        self.router_netmask_in = current_in_netmask
        self.router_network_in = ipaddress.ip_network(f"{self.router_ip_in}/{self.router_netmask_in}", strict=False)
        # --- End of Logic for IN (LAN) Interface ---

        # Step 3: Assign IPs to interfaces using OS commands (netsh for Windows)
        self.router_logger.log_message(
            "[Router] Assigning IPs to interfaces via OS commands (Requires Admin). This may cause temporary network disruption.")

        if in_address_source != "dhcp":
            if not self._assign_ip_to_interface(self.interface_in_friendly_name, self.router_ip_in,
                                                self.router_netmask_in):
                self.router_logger.log_message(
                    f"[Router] CRITICAL ERROR: Failed to assign IP to IN interface. Routing may not work.")
                return False

        # The key change is here: only assign a static gateway if we are NOT using the OS gateway
        if not use_dhcp_out:
            if not self._assign_ip_to_interface(self.interface_out_friendly_name, self.router_ip_out,
                                                self.router_netmask_out,
                                                self.router_gateway_out_ip):
                self.router_logger.log_message(
                    f"[Router] CRITICAL ERROR: Failed to assign IP to OUT interface. Routing may not work.")
                return False

        # Assign IPs to the additional interfaces (Ethernet 2, LAC 1, LAC 2)
        # We will give them static IPs from the same subnet as the IN interface.
        # Note: These IPs must be unique and not conflict with other devices.
        if ethernet_2_info:
            # Reuse an address only when it is a usable member of the selected
            # LAN. Never propagate Windows APIPA (169.254/16) into bridge/LAN
            # configuration.
            eth2_ip = None
            observed_eth2_ip, _ = self._current_interface_ipv4(
                ethernet_2_info["friendly_name"], usable_only=False
            )
            if observed_eth2_ip and self._is_usable_unicast_ipv4(observed_eth2_ip):
                try:
                    observed_obj = ipaddress.IPv4Address(observed_eth2_ip)
                    if observed_obj in self.router_network_in and str(observed_obj) != self.router_ip_in:
                        eth2_ip = str(observed_obj)
                except Exception:
                    eth2_ip = None

            if not eth2_ip:
                eth2_ip = str(self.router_network_in.network_address + 2)

            self.router_logger.log_message(f"[Router] Attempting to assign LAN IP {eth2_ip} to Ethernet 2.")
            if not self._assign_ip_to_interface(ethernet_2_info['friendly_name'], eth2_ip, self.router_netmask_in):
                self.router_logger.log_message(
                    "[Router] ⚠️ Ethernet 2 could not be configured; excluding it from this run instead of aborting the router."
                )
                ethernet_2_info = None
                self.interface_ethernet_2_full_name = None
                self.interface_ethernet_2_friendly_name = None

        if lac_2_info:
            lac_1_ip = None
            observed_lac_ip, _ = self._current_interface_ipv4(
                lac_2_info["friendly_name"], usable_only=False
            )
            if observed_lac_ip and self._is_usable_unicast_ipv4(observed_lac_ip):
                try:
                    observed_obj = ipaddress.IPv4Address(observed_lac_ip)
                    if observed_obj in self.router_network_in and str(observed_obj) not in {
                        self.router_ip_in,
                        str(self.router_network_in.network_address + 2),
                    }:
                        lac_1_ip = str(observed_obj)
                except Exception:
                    lac_1_ip = None

            if not lac_1_ip:
                lac_1_ip = str(self.router_network_in.network_address + 3)

            self.router_logger.log_message(f"[Router] Attempting to assign LAN IP {lac_1_ip} to LAC 1.")
            if not self._assign_ip_to_interface(lac_2_info['friendly_name'], lac_1_ip, self.router_netmask_in):
                self.router_logger.log_message(
                    "[Router] ⚠️ LAC 1 could not be configured; excluding it from this run."
                )
                lac_2_info = None
                self.interface_lac_full_name = None
                self.interface_lac_friendly_name = None

        if lac_2_info_2:
            lac_2_ip = None
            observed_lac2_ip, _ = self._current_interface_ipv4(
                lac_2_info_2["friendly_name"], usable_only=False
            )
            if observed_lac2_ip and self._is_usable_unicast_ipv4(observed_lac2_ip):
                try:
                    observed_obj = ipaddress.IPv4Address(observed_lac2_ip)
                    reserved = {
                        self.router_ip_in,
                        str(self.router_network_in.network_address + 2),
                        str(self.router_network_in.network_address + 3),
                    }
                    if observed_obj in self.router_network_in and str(observed_obj) not in reserved:
                        lac_2_ip = str(observed_obj)
                except Exception:
                    lac_2_ip = None

            if not lac_2_ip:
                lac_2_ip = str(self.router_network_in.network_address + 4)

            self.router_logger.log_message(f"[Router] Attempting to assign LAN IP {lac_2_ip} to LAC 2.")
            if not self._assign_ip_to_interface(lac_2_info_2['friendly_name'], lac_2_ip, self.router_netmask_in):
                self.router_logger.log_message(
                    "[Router] ⚠️ LAC 2 could not be configured; excluding it from this run."
                )
                lac_2_info_2 = None
                self.interface_lac_2_full_name = None
                self.interface_lac_2_friendly_name = None

        # Step 4: Update internal _interfaces_config with assigned IPs and MACs
        # Store configurations by full Scapy name
        self._interfaces_config[self.interface_in_full_name] = {
            "friendly_name": self.interface_in_friendly_name,
            'ip_addr': self.router_ip_in,
            'network': self.router_network_in,
            'mac': get_if_hwaddr(self.interface_in_full_name),
            'broadcast': str(self.router_network_in.broadcast_address)
        }
        self._interfaces_config[self.interface_out_full_name] = {
            "friendly_name": self.interface_out_friendly_name,
            'ip_addr': self.router_ip_out,
            'network': self.router_network_out,
            'mac': get_if_hwaddr(self.interface_out_full_name),
            'broadcast': str(self.router_network_out.broadcast_address),
            'is_default_gateway_iface': True,
        }
        self.default_gateway_ip = self.router_gateway_out_ip

        bridge_members = [self.interface_in_full_name]

        if ethernet_2_info:
            try:
                eth2_mac = get_if_hwaddr(ethernet_2_info["full_name"])
                eth2_ip = None
                eth2_netmask = None
                for addr in psutil.net_if_addrs().get(ethernet_2_info["friendly_name"], []):
                    if addr.family == socket.AF_INET:
                        eth2_ip = addr.address
                        eth2_netmask = addr.netmask
                        break
                if eth2_ip and eth2_netmask:
                    eth2_network = ipaddress.ip_network(f"{eth2_ip}/{eth2_netmask}", strict=False)
                    self._interfaces_config[ethernet_2_info["full_name"]] = {
                        "friendly_name": self.interface_ethernet_2_friendly_name,
                        "ip_addr": eth2_ip,
                        "network": eth2_network,
                        "mac": eth2_mac,
                        "broadcast": str(eth2_network.broadcast_address)
                    }
                else:
                    self._interfaces_config[ethernet_2_info["full_name"]] = {
                        "friendly_name": self.interface_ethernet_2_friendly_name,
                        "ip_addr": "0.0.0.0",
                        "network": None,
                        "mac": eth2_mac,
                        "broadcast": "255.255.255.255"
                    }

                self.router_logger.log_message(
                    f"[Router] Added Ethernet 2 to config: {ethernet_2_info['full_name']}, MAC: {eth2_mac}")
                bridge_members.append(ethernet_2_info["full_name"])
            except Exception as e:
                self.router_logger.log_message(f"[Router] ⚠️ Failed to add Ethernet 2 to bridge: {e}")
        if lac_2_info:
            try:
                lac_mac = get_if_hwaddr(self.interface_lac_full_name)
                lac_ip = None
                lac_netmask = None
                for addr in psutil.net_if_addrs().get(self.interface_lac_friendly_name, []):
                    if addr.family == socket.AF_INET:
                        lac_ip = addr.address
                        lac_netmask = addr.netmask
                        break

                if lac_ip and lac_netmask:
                    lac_network = ipaddress.ip_network(f"{lac_ip}/{lac_netmask}", strict=False)
                    self._interfaces_config[self.interface_lac_full_name] = {
                        "friendly_name": self.interface_lac_friendly_name,
                        "ip_addr": lac_ip,
                        "network": lac_network,
                        "mac": lac_mac,
                        "broadcast": str(lac_network.broadcast_address)
                    }
                    self.router_logger.log_message(
                        f"[Router] Added LAC interface to config: {self.interface_lac_full_name}, IP: {lac_ip}, MAC: {lac_mac}")
                else:
                    self._interfaces_config[self.interface_lac_full_name] = {
                        "friendly_name": self.interface_lac_friendly_name,
                        "ip_addr": "0.0.0.0",
                        "network": None,
                        "mac": lac_mac,
                        "broadcast": "255.255.255.255"
                    }
                    self.router_logger.log_message(
                        f"[Router] Added LAC interface to config: {self.interface_lac_full_name} (No IP found), MAC: {lac_mac}")
                bridge_members.append(lac_2_info["full_name"])
            except Exception as e:
                self.router_logger.log_message(
                    f"[Router] ⚠️ Failed to configure LAC interface {self.interface_lac_full_name}: {e}")
        if lac_2_info_2:
            try:
                lac_2_mac = get_if_hwaddr(self.interface_lac_2_full_name)
                lac_2_ip = None
                lac_2_netmask = None

                for addr in psutil.net_if_addrs().get(self.interface_lac_2_friendly_name, []):
                    if addr.family == socket.AF_INET:
                        lac_2_ip = addr.address
                        lac_2_netmask = addr.netmask
                        break

                if lac_2_ip and lac_2_netmask:
                    lac_2_network = ipaddress.ip_network(f"{lac_2_ip}/{lac_2_netmask}", strict=False)

                    self._interfaces_config[self.interface_lac_2_full_name] = {
                        "friendly_name": self.interface_lac_2_friendly_name,
                        "ip_addr": lac_2_ip,
                        "network": lac_2_network,
                        "mac": lac_2_mac,
                        "broadcast": str(lac_2_network.broadcast_address)
                    }
                    self.router_logger.log_message(
                        f"[Router] Added LAC 2 interface to config: {self.interface_lac_2_full_name}, IP: {lac_2_ip}, MAC: {lac_2_mac}")
                else:
                    self._interfaces_config[self.interface_lac_2_full_name] = {
                        "friendly_name": self.interface_lac_2_friendly_name,
                        "ip_addr": "0.0.0.0",
                        "network": None,
                        "mac": lac_2_mac,
                        "broadcast": "255.255.255.255"
                    }
                    self.router_logger.log_message(
                        f"[Router] Added LAC 2 interface to config: {self.interface_lac_2_full_name} (No IP found), MAC: {lac_2_mac}")
                bridge_members.append(lac_2_info_2["full_name"])
            except Exception as e:
                self.router_logger.log_message(
                    f"[Router] ⚠️ Failed to configure LAC 2 interface {self.interface_lac_2_full_name}: {e}")
        # ✅ Create LAN bridge with discovered members
        self.router_logger.log_message(
            "[Router][ARP] 🔒 Configuring trusted ARP interfaces and static entries...")

        # Trust the IN interface
        self.add_trusted_arp_port(self.interface_in_full_name)
        self.add_trusted_arp_port(self.interface_out_full_name)
        # Optionally trust Ethernet 2 (if used in bridging)
        if ethernet_2_info:
            self.add_static_arp_entry(
                self._interfaces_config[self.interface_ethernet_2_full_name]["ip_addr"],
                self._interfaces_config[self.interface_ethernet_2_full_name]["mac"]
            )
            self.add_trusted_arp_port(self.interface_ethernet_2_full_name)
        if lac_2_info:
            self.add_static_arp_entry(
                self._interfaces_config[self.interface_lac_full_name]["ip_addr"],
                self._interfaces_config[self.interface_lac_full_name]["mac"]
            )
            self.add_trusted_arp_port(self.interface_lac_full_name)
        if self.interface_lac_2_full_name:
            self.add_static_arp_entry(
                self._interfaces_config[self.interface_lac_2_full_name]["ip_addr"],
                self._interfaces_config[self.interface_lac_2_full_name]["mac"]
            )
            self.add_trusted_arp_port(self.interface_lac_2_full_name)
        # Example: Add static ARP entry for gateway (if known)
        if self.router_gateway_out_ip:
            try:
                gateway_mac = self.arp_manager.resolve(self.router_gateway_out_ip, self.interface_out_full_name)
                if gateway_mac:
                    self.add_static_arp_entry(self.router_gateway_out_ip, gateway_mac)
            except Exception as e:
                self.router_logger.log_message(f"[Router][ARP] ⚠️ Failed to resolve gateway MAC: {e}")
        if self.router_ip_in:
            self.add_static_arp_entry(self.router_ip_in, self._interfaces_config[self.interface_in_full_name]['mac'])

        # NEW: Add Loopback interface to config if found
        if self.interface_loopback_full_name:
            loopback_ip = "127.0.0.1"
            loopback_netmask = "255.0.0.0"
            loopback_network = ipaddress.ip_network(f"{loopback_ip}/{loopback_netmask}", strict=False)
            try:
                loopback_mac = get_if_hwaddr(self.interface_loopback_full_name)
            except Exception:
                loopback_mac = "00:00:00:00:00:00"

            self._interfaces_config[self.interface_loopback_full_name] = {
                'friendly_name': "Loopback",
                'ip_addr': loopback_ip,
                'network': loopback_network,
                'mac': loopback_mac,
                "broadcast": str(loopback_network.broadcast_address)
            }
            if self.interface_loopback_full_name:
                self.add_static_arp_entry(loopback_ip, loopback_mac)
                self.add_trusted_arp_port(self.interface_loopback_full_name)
            self.rip_manager.interface_loopback_full_name = self.interface_loopback_full_name
            self.router_logger.log_message(
                f"  Loopback Interface: '{self.interface_loopback_full_name}' (IP: {loopback_ip}/{loopback_netmask}, MAC: {loopback_mac})")

        self.create_l2_bridge("MyLANBridge", bridge_members)
        self.add_outbound_load_balancing_interface(self.interface_out_full_name)
        link_group = [self.interface_out_full_name]

        self.create_link_aggregation_group(
            "MyLANAggregation",
            link_group,
        )

        self.broadcast_manager.ensure_broadcast_for_pcap(self.interface_out_full_name)

        self.mac_in = get_if_hwaddr(self.interface_in_full_name)
        self.mac_out = get_if_hwaddr(self.interface_out_full_name)
        self.create_link_aggregation_group("MyLANAggregation", link_group)
        self._set_ipv6_link_local()
        self.router_macs = {cfg.get('mac') for cfg in self._interfaces_config.values() if 'mac' in cfg}
        self.router_logger.log_message(f"\n--- Python Router Configuration Summary ---")
        self.router_logger.log_message(
            f"  IN Interface: '{self.interface_in_friendly_name}' (Full: {self.interface_in_full_name}, MAC: {self.mac_in}, IP: {self.router_ip_in}/{self.router_netmask_in})")
        self.router_logger.log_message(
            f"  OUT Interface: '{self.interface_out_friendly_name}' (Full: {self.interface_out_full_name}, MAC: {self.mac_out}, IP: {self.router_ip_out}/{self.router_netmask_out})")
        self.router_logger.log_message(
            f"  IN Network: {self.router_network_in}, OUT Network: {self.router_network_out}")
        self.router_logger.log_message(
            f"  External Gateway: {self.router_gateway_out_ip} via '{self.interface_out_friendly_name}'")
        self.router_logger.log_message(f"----------------------------------------------------------------")
        return True

    def _synthesize_link_local_ipv6(self, mac_address: str) -> Optional[str]:
        """
        Creates an IPv6 link-local address from a MAC address using the EUI-64 standard.
        """
        try:
            # 1. Remove delimiters and split the MAC into two halves
            mac_parts = mac_address.replace(":", "").replace("-", "")
            if len(mac_parts) != 12: return None

            part1 = mac_parts[:6]
            part2 = mac_parts[6:]

            # 2. Insert 'fffe' in the middle
            eui64 = f"{part1}fffe{part2}"

            # 3. Invert the 7th bit (the "U/L" bit) of the first byte
            first_byte = int(eui64[:2], 16)
            inverted_byte = first_byte ^ 2

            # 4. Reconstruct the host part
            host_part = f"{inverted_byte:02x}{eui64[2:]}"

            # 5. Format into a standard IPv6 address with the link-local prefix
            addr_parts = [host_part[i:i + 4] for i in range(0, len(host_part), 4)]
            final_addr = f"fe80::{':'.join(addr_parts)}"

            return str(ipaddress.IPv6Address(final_addr))  # Return a compressed, valid address
        except Exception as e:
            self.router_logger.log_message(f"[Router] ❌ Failed to synthesize EUI-64 address: {e}")
            return None

    def _set_ipv6_link_local(self):
        # 1. Run ipconfig and capture the output
        self.router_logger.log_message(
            f"[Router] 🔎 Discovering link-local IPv6 address for {self.interface_out_friendly_name}..."
        )

        found_address = None
        result = subprocess.check_output("ipconfig", text=True, stderr=subprocess.DEVNULL)

        in_correct_adapter_section = False
        for line in result.splitlines():
            # [FIX] This is a more robust way to track which adapter section we are in.
            # A new section starts with a line containing "adapter" and ending with a colon.
            if "adapter" in line.lower() and line.strip().endswith(':'):
                # Check if this new section is the one we are looking for.
                if self.interface_out_friendly_name.lower() in line.lower():
                    in_correct_adapter_section = True
                else:
                    # It's a different adapter, so we are no longer in the correct section.
                    in_correct_adapter_section = False

            # If we are in the correct section, look for the address line.
            if in_correct_adapter_section:
                clean_line = line.strip()
                if clean_line.startswith("Link-local IPv6 Address"):
                    address_part = clean_line.split(":", 1)[1].strip()
                    # Clean up the '(Preferred)' suffix and any other trailing text
                    cleaned_address = address_part.split("(")[0].strip()
                    found_address = cleaned_address
                    break  # We found the address, no need to parse further.
                if clean_line.startswith("Link-local IPv6 Address"):
                    address_part = clean_line.split(":", 1)[1].strip()
                    # Clean up the '(Preferred)' suffix and any other trailing text
                    cleaned_address = address_part.split("(")[0].strip()
                    found_address = cleaned_address
                    break  # We found the address, no need to parse further.

        if found_address:
            self.router_ipv6_link_local_out = found_address
            conf.route6.add(
                dst="::/0",  # For any destination
                gw=self.router_ipv6_link_local_out,
                dev=self.interface_out_full_name
            )
            self.router_logger.log_message(
                f"[Router] ✅ Discovered OS link-local address: {self.router_ipv6_link_local_out}"
            )
            logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
        else:
            self.router_logger.log_message(
                f"[Router] ⚠️ No link-local IPv6 address found on {self.interface_out_friendly_name}. Synthesizing one..."
            )
            # Get the MAC address of the outbound interface
            out_mac = self.get_interface_mac(self.interface_out_full_name)
            if out_mac:
                synthesized_ll = self._synthesize_link_local_ipv6(out_mac)
                if synthesized_ll:
                    self.router_ipv6_link_local_out = synthesized_ll
                    self.router_logger.log_message(
                        f"[Router] ✅ Synthesized EUI-64 link-local address: {self.router_ipv6_link_local_out}")
            self.ndp_manager.router_ipv6_link_local_out = self.router_ipv6_link_local_out

    def _coerce_ingress_packet(self, pkt):
        """
        Accept either:
          - real Ether frames
          - L3-only Scapy packets (IP/IPv6/ARP), common on Npcap loopback
          - raw bytes that can be parsed safely

        Returns a Scapy packet or None.
        """
        try:
            if pkt is None:
                return None

            # 1) Already a good Ether frame
            if hasattr(pkt, "haslayer") and pkt.haslayer(Ether):
                try:
                    plen = len(pkt)
                    if plen < 14 or plen > 65535:
                        return None
                except Exception:
                    pass
                return pkt

            # 2) Already a good L3 packet
            if hasattr(pkt, "haslayer") and (pkt.haslayer(IP) or pkt.haslayer(IPv6) or pkt.haslayer(ARP)):
                try:
                    plen = len(pkt)
                    if plen <= 0 or plen > 65535:
                        return None
                except Exception:
                    pass
                return pkt

            # 3) Convert to raw bytes and parse
            try:
                raw_buf = bytes(pkt)
            except Exception:
                return None

            if not raw_buf or len(raw_buf) > 65535:
                return None

            # Prefer L3 parse first for loopback/raw captures
            b0 = raw_buf[0]
            ver = (b0 >> 4) & 0xF

            if ver == 4:
                if len(raw_buf) < 20:
                    return None
                try:
                    return IP(raw_buf)
                except Exception:
                    return None

            if ver == 6:
                if len(raw_buf) < 40:
                    return None
                try:
                    return IPv6(raw_buf)
                except Exception:
                    return None

            # Final fallback: only try Ether if frame is big enough
            if len(raw_buf) >= 14:
                try:
                    eth = Ether(raw_buf)
                    return eth
                except Exception:
                    return None

            return None

        except Exception:
            return None
    def _ingress_log_sparse(self, key: str, message: str, every: float = 2.0) -> None:
        now = time.monotonic()
        with self._ingress_lock:
            last = float(self._ingress_log_ts.get(key, 0.0) or 0.0)
            if now - last < max(0.1, float(every)):
                return
            self._ingress_log_ts[key] = now
        try:
            self.router_logger.log_message(message)
        except Exception:
            pass

    @staticmethod
    def _estimate_ingress_size(packet) -> int:
        if isinstance(packet, (bytes, bytearray, memoryview)):
            return len(packet)
        try:
            return max(1, len(packet))
        except Exception:
            try:
                return max(1, len(bytes(packet)))
            except Exception:
                return 1

    @staticmethod
    def _ingress_parsed_packet(packet):
        if not isinstance(packet, (bytes, bytearray, memoryview)):
            return packet
        raw_packet = bytes(packet)
        if not raw_packet:
            return packet
        try:
            version = (raw_packet[0] >> 4) & 0x0F
            if version == 4:
                return IP(raw_packet)
            if version == 6:
                return IPv6(raw_packet)
            if len(raw_packet) >= 14:
                return Ether(raw_packet)
        except Exception:
            pass
        return packet

    @staticmethod
    def _ingress_payload_bytes(packet, cap: int = 65536) -> bytes:
        try:
            layer = packet.getlayer(TCP) or packet.getlayer(UDP)
            payload = getattr(layer, "payload", None) if layer is not None else None
            if payload is None or payload.__class__.__name__ == "NoPayload":
                return b""
            return bytes(payload)[:max(0, int(cap))]
        except Exception:
            return b""

    @staticmethod
    def _ingress_flow_key(packet):
        try:
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip_layer is None:
                return ("frame", hashlib.sha1(bytes(packet)[:96]).hexdigest()[:16])
            proto = "ip"
            sport = dport = 0
            if packet.haslayer(TCP):
                proto = "tcp"
                sport = int(packet[TCP].sport)
                dport = int(packet[TCP].dport)
            elif packet.haslayer(UDP):
                proto = "udp"
                sport = int(packet[UDP].sport)
                dport = int(packet[UDP].dport)
            a = (str(ip_layer.src), sport)
            b = (str(ip_layer.dst), dport)
            if b < a:
                a, b = b, a
            return (proto, a[0], a[1], b[0], b[1])
        except Exception:
            return ("unknown",)

    @staticmethod
    def _ingress_confirmed_stratum(packet, payload: bytes) -> bool:
        for attr in (
            "_capture_stratum_evidence", "_stratum_confirmed",
            "_stratum_payload_confirmed", "_router_stratum_confirmed",
        ):
            try:
                if bool(getattr(packet, attr, False)):
                    return True
            except Exception:
                pass
        try:
            context = dict(getattr(packet, "_handshake_transport_context", None) or {})
            evidence = dict(context.get("stratum") or {})
            if evidence.get("detected") or evidence.get("confirmed"):
                return True
            transport = str(evidence.get("transport") or "").casefold()
            if transport in {"plaintext-jsonrpc", "stratum", "stratum-over-tls"}:
                return True
        except Exception:
            pass
        if not payload:
            return False
        lowered = payload[:32768].lower()
        markers = (
            b'"mining.subscribe"', b'"mining.authorize"', b'"mining.submit"',
            b'"mining.notify"', b'"job"', b'"submit"', b'"login"',
        )
        return bool(payload[:1] in b"[{" and any(marker in lowered for marker in markers))

    def _ingress_priority_value(self, packet) -> int:
        """Return 0=bulk/noise, 1=normal, 2=protected, 3=critical.

        Classification is evidence based. A common HTTPS port or a learned
        mining-port hint alone never promotes a packet.
        """
        try:
            label = str(getattr(packet, "_capture_priority", "") or "").casefold()
            if label == "critical":
                return 3
            if label == "high" or bool(getattr(packet, "_capture_high_value", False)):
                return 2
            if label == "elevated":
                return 1
        except Exception:
            pass

        parsed = self._ingress_parsed_packet(packet)
        try:
            if parsed.haslayer(DHCP) or parsed.haslayer(DHCP6):
                return 3
            if parsed.haslayer(ARP):
                return 3
            if parsed.haslayer(ICMPv6ND_NS) or parsed.haslayer(ICMPv6ND_NA):
                return 3
            if parsed.haslayer(DNS):
                return 2
            if parsed.haslayer(ISAKMP) or parsed.haslayer(IKEv2):
                return 3
        except Exception:
            pass

        payload = self._ingress_payload_bytes(parsed)
        try:
            tcp = parsed.getlayer(TCP)
            if tcp is not None:
                flags = int(getattr(tcp, "flags", 0) or 0)
                if flags & 0x04:  # RST
                    return 3
                if flags & 0x02:  # SYN
                    return 2
                if flags & 0x01:  # FIN
                    return 2
                if len(payload) >= 5:
                    content_type = int(payload[0])
                    version = int.from_bytes(payload[1:3], "big")
                    record_len = int.from_bytes(payload[3:5], "big")
                    if content_type in {20, 21, 22} and 0x0300 <= version <= 0x0304 and record_len <= 18432:
                        return 3
                if self._ingress_confirmed_stratum(parsed, payload):
                    return 3
            udp = parsed.getlayer(UDP)
            if udp is not None:
                ports = {int(udp.sport), int(udp.dport)}
                if ports & {67, 68, 546, 547}:
                    return 3
                if ports & {500, 4500}:
                    return 3
                if self._ingress_confirmed_stratum(parsed, payload):
                    return 3
        except Exception:
            pass
        return 1

    @staticmethod
    def _ingress_coalesce_key(packet, priority: int):
        if int(priority) > 1:
            return None
        try:
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip_layer is None:
                return None
            dst = ipaddress.ip_address(str(ip_layer.dst).split("%", 1)[0])
            is_noise_dst = bool(dst.is_multicast or str(dst) == "255.255.255.255")
            if not is_noise_dst:
                return None
            if packet.haslayer(UDP):
                udp = packet[UDP]
                ports = (int(udp.sport), int(udp.dport))
                if set(ports) & {137, 138, 1900, 3702, 5353, 5355}:
                    return ("udp-noise", str(ip_layer.src), str(ip_layer.dst), ports)
            if packet.haslayer(ARP):
                return ("arp-noise", str(getattr(packet[ARP], "psrc", "")), str(getattr(packet[ARP], "pdst", "")))
        except Exception:
            pass
        return None

    @staticmethod
    def _drop_ingress_for_pressure(state: dict, incoming_priority: int):
        q = state.get("queue")
        if not q:
            return None
        lowest = min(int(item["priority"]) for item in q)
        if int(incoming_priority) < lowest:
            return None
        counts = collections.Counter(
            item.get("flow") for item in q if int(item["priority"]) == lowest
        )
        noisy_flow = counts.most_common(1)[0][0] if counts else None
        drop_index = 0
        for index, item in enumerate(q):
            if int(item["priority"]) == lowest and (noisy_flow is None or item.get("flow") == noisy_flow):
                drop_index = index
                break
        dropped = q[drop_index]
        del q[drop_index]
        return dropped

    def _ensure_ingress_state(self, inbound_iface: str) -> Dict[str, Any]:
        key = str(inbound_iface or "Unknown")
        with self._ingress_lock:
            state = self._ingress_states.get(key)
            if state is not None and state.get("thread") and state["thread"].is_alive():
                return state
            stop_event = threading.Event()
            state = {
                "iface": key,
                "queue": deque(),
                "bytes": 0,
                "cv": threading.Condition(threading.RLock()),
                "stop": stop_event,
                "thread": None,
                "enqueued": 0,
                "processed": 0,
                "dropped": 0,
                "evicted": 0,
                "coalesced": 0,
                "dropped_by_priority": {0: 0, 1: 0, 2: 0, 3: 0},
                "queued_by_priority": {0: 0, 1: 0, 2: 0, 3: 0},
                "errors": 0,
                "latency_total": 0.0,
                "latency_max": 0.0,
                "last_progress": time.monotonic(),
                "last_summary": time.monotonic(),
            }
            thread = threading.Thread(
                target=self._ingress_worker_loop,
                args=(state,),
                name=f"RouterIngress-{key.split('_')[-1]}",
                daemon=True,
            )
            state["thread"] = thread
            self._ingress_states[key] = state
            thread.start()
            return state

    def _log_ingress_summary(self, state: dict, *, force: bool = False) -> None:
        now = time.monotonic()
        interval = max(5.0, float(self._ingress_summary_interval_sec))
        if not force and now - float(state.get("last_summary", 0.0)) < interval:
            return
        state["last_summary"] = now
        processed = max(1, int(state.get("processed", 0)))
        avg_ms = 1000.0 * float(state.get("latency_total", 0.0)) / processed
        self._ingress_log_sparse(
            f"summary:{state['iface']}",
            (
                f"[RouterIngress] iface={state['iface']} queued={len(state['queue'])} "
                f"bytes={int(state['bytes'])} processed={int(state['processed'])} "
                f"rejected={int(state['dropped'])} evicted={int(state['evicted'])} "
                f"coalesced={int(state['coalesced'])} avg_latency_ms={avg_ms:.2f} "
                f"max_latency_ms={1000.0 * float(state.get('latency_max', 0.0)):.2f}"
            ),
            every=interval,
        )

    def enqueue_ingress_packet(self, packet, inbound_iface: str = "Unknown") -> bool:
        """Non-blocking, process-friendly ingress API for all capture backends."""
        if packet is None or self._stop_sniffing_event.is_set():
            return False
        state = self._ensure_ingress_state(inbound_iface)
        parsed = self._ingress_parsed_packet(packet)
        size = self._estimate_ingress_size(packet)
        priority = self._ingress_priority_value(parsed)
        flow = self._ingress_flow_key(parsed)
        coalesce_key = self._ingress_coalesce_key(parsed, priority)
        single_packet_limit = self._ingress_max_bytes + (
            self._ingress_priority_reserve_bytes if priority >= 2 else 0
        )
        if size > single_packet_limit:
            state["dropped"] += 1
            self._ingress_total_dropped += 1
            self._log_ingress_summary(state, force=True)
            return False
        if isinstance(packet, (bytearray, memoryview)):
            packet = bytes(packet)

        cv = state["cv"]
        frame_limit = self._ingress_max_frames + (
            self._ingress_priority_reserve_frames if priority >= 2 else 0
        )
        byte_limit = self._ingress_max_bytes + (
            self._ingress_priority_reserve_bytes if priority >= 2 else 0
        )
        with cv:
            q = state["queue"]
            if coalesce_key is not None:
                for index in range(len(q) - 1, -1, -1):
                    old = q[index]
                    if old.get("coalesce_key") != coalesce_key:
                        continue
                    state["bytes"] = max(0, int(state["bytes"]) - int(old["size"]))
                    old_priority = int(old["priority"])
                    state["queued_by_priority"][old_priority] = max(
                        0, int(state["queued_by_priority"][old_priority]) - 1
                    )
                    del q[index]
                    state["coalesced"] += 1
                    self._ingress_total_coalesced += 1
                    break

            while q and (len(q) >= frame_limit or int(state["bytes"]) + size > byte_limit):
                dropped = self._drop_ingress_for_pressure(state, priority)
                if dropped is None:
                    break
                state["bytes"] = max(0, int(state["bytes"]) - int(dropped["size"]))
                old_priority = int(dropped["priority"])
                state["dropped"] += 1
                state["evicted"] += 1
                state["dropped_by_priority"][old_priority] += 1
                state["queued_by_priority"][old_priority] = max(
                    0, int(state["queued_by_priority"][old_priority]) - 1
                )
                self._ingress_total_dropped += 1
                self._ingress_total_evicted += 1

            if len(q) >= frame_limit or int(state["bytes"]) + size > byte_limit:
                state["dropped"] += 1
                state["dropped_by_priority"][int(priority)] += 1
                self._ingress_total_dropped += 1
                self._log_ingress_summary(state, force=True)
                return False

            q.append({
                "packet": packet,
                "size": size,
                "queued_ts": time.monotonic(),
                "priority": int(priority),
                "flow": flow,
                "coalesce_key": coalesce_key,
            })
            state["bytes"] = int(state["bytes"]) + size
            state["enqueued"] += 1
            state["queued_by_priority"][int(priority)] += 1
            self._ingress_total_enqueued += 1
            cv.notify()
        self._log_ingress_summary(state)
        return True

    ingest_packet = enqueue_ingress_packet

    def _ingress_worker_loop(self, state: Dict[str, Any]) -> None:
        cv = state["cv"]
        stop_event = state["stop"]
        iface = state["iface"]
        while not stop_event.is_set():
            batch = []
            with cv:
                while not state["queue"] and not stop_event.is_set():
                    cv.wait(timeout=0.25)
                if stop_event.is_set() and not state["queue"]:
                    break
                for _ in range(max(1, int(self._ingress_batch_size))):
                    if not state["queue"]:
                        break
                    item = state["queue"].popleft()
                    state["bytes"] = max(0, int(state["bytes"]) - int(item["size"]))
                    priority = int(item["priority"])
                    state["queued_by_priority"][priority] = max(
                        0, int(state["queued_by_priority"][priority]) - 1
                    )
                    batch.append(item)
            for item in batch:
                try:
                    latency = max(0.0, time.monotonic() - float(item["queued_ts"]))
                    state["latency_total"] += latency
                    state["latency_max"] = max(float(state["latency_max"]), latency)
                    self.process_packet(item["packet"], iface)
                    state["processed"] += 1
                    self._ingress_total_processed += 1
                    state["last_progress"] = time.monotonic()
                except Exception as exc:
                    state["errors"] += 1
                    self._ingress_log_sparse(
                        f"worker-error:{iface}",
                        f"[Router][Ingress] ❗ worker error on {iface}: {type(exc).__name__}: {exc}",
                        every=5.0,
                    )
            self._log_ingress_summary(state)

    def _stop_ingress_workers(self, *, discard: bool = True) -> None:
        with self._ingress_lock:
            states = list(self._ingress_states.values())

        for state in states:
            state["stop"].set()
            with state["cv"]:
                if discard:
                    dropped = len(state["queue"])
                    state["dropped"] += dropped
                    self._ingress_total_dropped += dropped
                    state["queue"].clear()
                    state["bytes"] = 0
                    state["queued_by_priority"] = {0: 0, 1: 0, 2: 0, 3: 0}
                state["cv"].notify_all()

        for state in states:
            thread = state.get("thread")
            if thread and thread.is_alive() and thread is not threading.current_thread():
                try:
                    thread.join(timeout=2.0)
                except Exception:
                    pass

        with self._ingress_lock:
            self._ingress_states.clear()

    def get_runtime_health(self) -> Dict[str, Any]:
        with self._ingress_lock:
            ingress = {
                name: {
                    "queued_frames": len(state["queue"]),
                    "queued_bytes": int(state["bytes"]),
                    "enqueued": int(state["enqueued"]),
                    "processed": int(state["processed"]),
                    "dropped": int(state["dropped"]),
                    "dropped_by_priority": dict(state.get("dropped_by_priority", {})),
                    "queued_by_priority": dict(state.get("queued_by_priority", {})),
                    "errors": int(state["errors"]),
                    "evicted": int(state.get("evicted", 0)),
                    "coalesced": int(state.get("coalesced", 0)),
                    "avg_latency_ms": (
                        1000.0 * float(state.get("latency_total", 0.0)) / max(1, int(state.get("processed", 0)))
                    ),
                    "max_latency_ms": 1000.0 * float(state.get("latency_max", 0.0)),
                    "worker_alive": bool(state.get("thread") and state["thread"].is_alive()),
                    "last_progress_age_sec": max(0.0, time.monotonic() - float(state["last_progress"])),
                }
                for name, state in self._ingress_states.items()
            }
        out = {
            "started": bool(self.started),
            "network_ready": self._runtime_network_ready.is_set(),
            "ingress_total_enqueued": self._ingress_total_enqueued,
            "ingress_total_processed": self._ingress_total_processed,
            "ingress_total_dropped": self._ingress_total_dropped,
            "ingress_total_evicted": self._ingress_total_evicted,
            "ingress_total_coalesced": self._ingress_total_coalesced,
            "ingress": ingress,
        }
        try:
            out["hyperv_pipe"] = self.hyperv_manager.get_pipe_stats()
        except Exception:
            pass
        return out

    def _safe_stop_component(self, label: str, component, method: str = "stop") -> bool:
        if component is None:
            return True
        fn = getattr(component, method, None)
        if not callable(fn):
            return True
        try:
            fn()
            return True
        except Exception as exc:
            self._ingress_log_sparse(
                f"safe-stop:{label}",
                f"[Router][Cleanup] ⚠️ {label}.{method} failed: {type(exc).__name__}: {exc}",
                every=1.0,
            )
            return False

    def _best_effort_runtime_core_stop(
            self,
            *,
            use_hyperv: bool = False,
            use_peerinterface: bool = False,
            use_stratum_comm: bool = False,
    ) -> None:
        """Idempotent fallback cleanup used after partial startup/stop failures."""
        self._runtime_network_ready.clear()
        self._stop_sniffing_event.set()
        self._stop_ingress_workers(discard=True)

        self._safe_stop_component("SocketInterface", self.socket_interface)
        try:
            self.codeoutput_interface_manager.shutdown()
        except Exception:
            pass
        self._safe_stop_component("TransportManager", self.transport_manager)
        self._safe_stop_component("HyperVRouterManager", self.hypervrouter_manager)
        self._safe_stop_component("PeerInterfaceManager", self.peerinterface_manager)
        self.peerinterface_manager = None
        self.peerinterface_enabled = False

        if use_hyperv or self.hyperv_enabled:
            self._safe_stop_component("WinDivertManager", self.windivert_manager)
            self._safe_stop_component("WinTunManager", self.wintun_manager)
            self._safe_stop_component("HyperVManager", self.hyperv_manager, "teardown")
            self.hyperv_enabled = False

        if use_stratum_comm:
            self._safe_stop_component("MoneroDaemonManager", self.daemon_manager)
            self._safe_stop_component("StratumConnectionManager", self.stratum_connection_manager)

        seen = set()
        for role, server in (
                ("DHCP-IN", self.dhcp_server_in),
                ("DHCP-OUT", self.dhcp_server_out),
                *[(f"DHCP-{name}", obj) for name, obj in (getattr(self, "dhcp_interface_servers", {}) or {}).items()],
        ):
            if server is None or id(server) in seen:
                continue
            seen.add(id(server))
            self._safe_stop_component(role, server)

        # These components are expected to tolerate repeated stop calls and own
        # background workers or open handles that should not survive rollback.
        for label, component in (
                ("CodeOutputManager", self.code_output_manager),
                ("RIPManager", self.rip_manager),
                ("EthernetBridgeManager", self.ethernet_manager),
                ("PacketWriter", self.packet_writer),
                ("NATManager", self.nat_manager),
                ("DNSManager", self.dns_manager),
                ("P2PPeerManager", self.p2p_manager),
                ("NetRouteManager", self.netroute_manager),
                ("HostConnectivityBoundaryManager", self.host_connectivity_boundary),
                ("LanManager", self.lan_manager),
                ("GatewayManager", self.gateway_manager),
                ("UplinkManager", self.upstream_manager or self.uplink_manager),
        ):
            self._safe_stop_component(label, component)

        self.started = False

    def _start_single_sniffer(self, iface_name: str, promisc = False):
        """Starts a sniffer thread for a given interface (no rate limiting, no queue)."""

        friendly_name_for_filter = next(
            (item['friendly_name'] for item in self._discovered_tshark_interfaces if item['full_name'] == iface_name),
            'DEFAULT'
        )
        filter_clauses = self.BPF_FILTER_BASE_DEFINITIONS.get(friendly_name_for_filter,
                                                              self.BPF_FILTER_BASE_DEFINITIONS.get("DEFAULT", []))
        filter_str = " or ".join(f"({clause})" for clause in filter_clauses) if filter_clauses else ""

        def sniffer_loop(name=iface_name):
            self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[-1]} starting...")

            def direct_process(pkt):
                try:
                    pkt2 = self._coerce_ingress_packet(pkt)
                    if pkt2 is None:
                        return
                    if not self.enqueue_ingress_packet(pkt2, iface_name):
                        self._ingress_log_sparse(
                            f"capture-drop:{iface_name}",
                            f"[Sniffer] ⚠️ ingress queue rejected packet on {iface_name}",
                        )
                except Exception as e:
                    import traceback
                    tb = traceback.format_exc()
                    self.router_logger.log_message(f"[Sniffer] ❗ Error in direct packet processing: {e}\n{tb}")

            try:
                self.sniffer.sniff(
                    iface=name,
                    prn=direct_process,
                    promisc=promisc,
                    stop_filter=lambda p: self._stop_sniffing_event.is_set(),
                    filter=filter_str,
                    mac_filter_only=bool(
                        self._manager_settings.get("require_ethernet_on_physical_capture", True)
                    ),
                    allow_l3_on_loopback=True,
                    allow_l3_on_virtual=True,
                    session=TCPSession,
                )
            except Exception as e:
                self.router_logger.log_message(f"‼️ CRITICAL ERROR in sniffer thread for {name.split('_')[-1]}: {e}")
            finally:
                self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[-1]} has exited.")

        sniffer_thread = threading.Thread(target=sniffer_loop, name=f"Sniffer-{iface_name.split('_')[-1]}", daemon=True)

        with self._sniff_threads_lock:
            self._sniff_threads[iface_name] = sniffer_thread
        sniffer_thread.start()

        self.router_logger.log_message(f"[Router] Sniffing started on {iface_name.split('_')[-1]}.")

    @staticmethod
    def _looks_like_virtual_downstream_iface(value: str) -> bool:
        name = str(value or "").casefold()
        hints = (
            "windivertbridge", "windivert bridge", "nate's tunnel", "nates tunnel",
            "wintun", "wireshark", "wire shark", "vethernet", "virtual ethernet",
            "hyper-v", "hyperv", "lan bridge", "virtual switch",
        )
        return any(h in name for h in hints)


    @staticmethod
    def _coerce_network_object(
            value,
            *,
            ip_hint=None,
            netmask_hint=None,
            version: Optional[int] = None,
    ):
        """
        Convert mixed interface-network metadata into an ipaddress network.

        Accepted inputs include IPv4Network/IPv6Network, interface objects,
        CIDR strings, address/netmask pairs, and dictionaries produced by
        external adapter managers. A version mismatch never wins over a valid
        hinted candidate.
        """
        network_types = (ipaddress.IPv4Network, ipaddress.IPv6Network)
        interface_types = (ipaddress.IPv4Interface, ipaddress.IPv6Interface)

        def acceptable(network) -> bool:
            return (
                isinstance(network, network_types)
                and (version not in (4, 6) or network.version == version)
            )

        if isinstance(value, network_types):
            if acceptable(value):
                return value
        elif isinstance(value, interface_types):
            if acceptable(value.network):
                return value.network

        raw_candidates = []
        if isinstance(value, dict):
            for key in ("network", "cidr", "subnet", "prefix"):
                candidate = value.get(key)
                if candidate is not None:
                    raw_candidates.append(candidate)
        elif value is not None:
            raw_candidates.append(value)

        ip_text = str(ip_hint or "").strip().split("%", 1)[0]
        mask_text = str(netmask_hint or "").strip()

        # Prefer a complete address/mask pair because a bare dotted netmask can
        # otherwise be misread as a /32 host network.
        if ip_text and mask_text:
            raw_candidates.insert(0, f"{ip_text}/{mask_text}")

        if ip_text and value is not None:
            value_text = str(value).strip()
            if value_text and "/" not in value_text:
                raw_candidates.insert(0, f"{ip_text}/{value_text}")

        if ip_text and "/" in ip_text:
            raw_candidates.append(ip_text)

        seen = set()
        for candidate in raw_candidates:
            text = str(candidate or "").strip()
            if not text or text.casefold() in {"none", "null"} or text in seen:
                continue
            seen.add(text)
            try:
                network = ipaddress.ip_network(text, strict=False)
            except (TypeError, ValueError):
                continue
            if acceptable(network):
                return network

        return None

    def _get_interface_network(
            self,
            iface_name: Optional[str],
            config: Optional[dict] = None,
            *,
            version: Optional[int] = None,
            persist: bool = True,
    ):
        """
        Return a normalized network object for an interface.

        When possible this also repairs the shared interface configuration so
        every downstream manager receives a real IPv4Network/IPv6Network object
        instead of a serialized string.
        """
        iface = str(iface_name or "").strip()
        cfg = config if isinstance(config, dict) else None
        if cfg is None and iface:
            candidate = self._interfaces_config.get(iface)
            cfg = candidate if isinstance(candidate, dict) else None
        if cfg is None:
            return None

        network = self._coerce_network_object(
            cfg.get("network"),
            ip_hint=cfg.get("ip_addr"),
            netmask_hint=cfg.get("netmask"),
            version=version,
        )
        if network is None:
            return None

        if persist:
            cfg["network"] = network
            cfg["network_text"] = str(network)
            cfg["netmask"] = str(network.netmask)
            if isinstance(network, ipaddress.IPv4Network):
                cfg["broadcast"] = str(network.broadcast_address)
            ip_text = str(cfg.get("ip_addr") or "").strip()
            if ip_text:
                try:
                    ip_obj = ipaddress.ip_address(ip_text.split("%", 1)[0])
                    if ip_obj.version == network.version:
                        cfg["cidr"] = f"{ip_obj}/{network.prefixlen}"
                except ValueError:
                    pass
        return network

    def _normalize_all_interface_networks(self) -> None:
        """Repair all currently registered interface network metadata in place."""
        for iface_name, cfg in list(self._interfaces_config.items()):
            if isinstance(cfg, dict):
                self._get_interface_network(iface_name, cfg, persist=True)

    @staticmethod
    def _is_loopback_iface_name(iface_name: Optional[str]) -> bool:
        name = str(iface_name or "").strip().casefold()
        return (
            name in {"lo", "loopback"}
            or "loopback" in name
            or name.endswith("npf_loopback")
        )

    def _ipv4_broadcast_owner_ifaces(self, address) -> list[str]:
        """Return configured interfaces whose directed broadcast equals address."""
        try:
            dst = address if isinstance(address, ipaddress.IPv4Address) else ipaddress.IPv4Address(str(address))
        except (TypeError, ValueError):
            return []

        matches = []
        for iface_name, cfg in list(self._interfaces_config.items()):
            if not isinstance(cfg, dict):
                continue
            network = self._get_interface_network(iface_name, cfg, version=4)
            if isinstance(network, ipaddress.IPv4Network) and dst == network.broadcast_address:
                matches.append(str(iface_name))
                continue
            configured_broadcast = str(cfg.get("broadcast") or "").strip()
            if configured_broadcast and configured_broadcast == str(dst):
                matches.append(str(iface_name))
        return matches

    def _is_ipv4_broadcast(self, address, network=None, config: Optional[dict] = None) -> bool:
        """Safely recognize limited or directed IPv4 broadcast destinations."""
        try:
            dst = address if isinstance(address, ipaddress.IPv4Address) else ipaddress.IPv4Address(str(address))
        except (TypeError, ValueError):
            return False

        if dst == ipaddress.IPv4Address("255.255.255.255"):
            return True

        normalized = self._coerce_network_object(network, version=4)
        if isinstance(normalized, ipaddress.IPv4Network) and dst == normalized.broadcast_address:
            return True

        configured_broadcast = str((config or {}).get("broadcast") or "").strip()
        return bool(configured_broadcast and configured_broadcast == str(dst))

    def _track_local_broadcast_drop(self, identifier: str, message: str) -> None:
        try:
            self.function_call_tracker.track(
                identifier=identifier,
                threshold=25,
                final_message=message + " Count: {}.",
                count_message=None,
            )
        except Exception:
            pass

    def _ensure_virtual_interface_ipv4_metadata(
            self,
            iface_name: str,
            *,
            router_ip: str,
            network: ipaddress.IPv4Network,
            router_mac: Optional[str] = None,
            source: str = "dhcp-interface-assignment",
    ) -> dict:
        """Persist a stable logical-interface IPv4 record for SnifferSoftware and DHCP."""
        iface = str(iface_name or "").strip()
        if not iface:
            return {}
        cfg = self._interfaces_config.setdefault(iface, {})
        if not isinstance(cfg, dict):
            cfg = {}
            self._interfaces_config[iface] = cfg
        cfg.setdefault("friendly_name", iface)
        cfg["ip_addr"] = str(router_ip)
        cfg["netmask"] = str(network.netmask)
        cfg["cidr"] = f"{router_ip}/{network.prefixlen}"
        cfg["network"] = network
        cfg["network_text"] = str(network)
        cfg["synthetic_ipv4"] = True
        cfg["ipv4_resolution_source"] = str(source)
        if router_mac:
            cfg.setdefault("mac", str(router_mac))
        return cfg

    def _normalized_dhcp_interface_profiles(self, profiles) -> list[dict]:
        """Validate independent per-interface DHCP scope descriptions."""
        out = []
        for index, raw_profile in enumerate(profiles or []):
            if not isinstance(raw_profile, dict):
                self.router_logger.log_message(
                    f"[DHCP][InterfaceScope] ⚠️ Ignoring profile #{index + 1}: expected an object."
                )
                continue
            profile = dict(raw_profile)
            iface = str(profile.get("iface") or profile.get("interface") or "").strip()
            cidr = str(profile.get("cidr") or profile.get("router_cidr") or "").strip()
            if not iface:
                self.router_logger.log_message(
                    f"[DHCP][InterfaceScope] ⚠️ Ignoring profile #{index + 1}: missing iface."
                )
                continue
            if not cidr:
                shared = self._dhcp_server_settings.setdefault("additional_ifaces", [])
                if iface not in shared:
                    shared.append(iface)
                continue
            try:
                iv = ipaddress.IPv4Interface(cidr)
            except Exception as exc:
                raise ValueError(f"Invalid DHCP interface CIDR for {iface}: {cidr}") from exc
            if not iv.ip.is_private:
                raise ValueError(
                    f"Independent DHCP interface scope for {iface} must use RFC1918/private IPv4; got {iv.ip}."
                )
            profile["iface"] = iface
            profile["cidr"] = f"{iv.ip}/{iv.network.prefixlen}"
            out.append(profile)
        return out

    def _dhcp_profile_policy_factory(self, owned_ifaces: set[str]):
        def _policy():
            allowed = set(str(x).strip() for x in owned_ifaces if str(x).strip())
            denied = {
                str(x).strip()
                for x in (
                    self.interface_out_full_name,
                    self.interface_out_friendly_name,
                    self.interface_loopback_full_name,
                    SocketInterface.IFACE_NAME,
                )
                if str(x or "").strip()
            }
            denied -= allowed
            return allowed, denied
        return _policy

    def _dhcp_control_plane_iface_sets(self) -> tuple[set[str], set[str]]:
        """
        Build the explicit LAN-DHCP service and deny sets.

        The LAN server owns only known downstream interfaces. The current WAN,
        loopback, and socket interfaces remain denied even when a separate WAN
        DHCP server is enabled.
        """
        allowed: set[str] = set()
        denied: set[str] = set()

        def add_iface(target: set[str], value) -> None:
            value = str(value or "").strip()
            if value:
                target.add(value)

        # DHCP must never respond on these interfaces.
        add_iface(denied, self.interface_out_full_name)
        add_iface(denied, self.interface_out_friendly_name)
        add_iface(denied, self.interface_loopback_full_name)
        add_iface(denied, SocketInterface.IFACE_NAME)

        selected_ifaces = {
            str(value).strip()
            for value in self._dhcp_server_settings.get("selected_ifaces", []) or []
            if str(value).strip()
        }
        # The primary router IN interface remains a LAN candidate; GUI-selected
        # adapters add exact ownership across physical and virtual interfaces.
        add_iface(allowed, self.interface_in_full_name)
        add_iface(allowed, self.interface_in_friendly_name)
        for iface in selected_ifaces:
            add_iface(allowed, iface)

        try:
            configured_outbound = (
                self.outbound_load_balancer.get_configured_interfaces()
            )

            if isinstance(configured_outbound, (set, list, tuple)):
                for iface in configured_outbound:
                    add_iface(denied, iface)
        except Exception:
            pass

        # Wi-Fi Direct adapters created by WifiManager are downstream LAN
        # interfaces, not uplinks.
        for iface in getattr(
                self,
                "wifi_host_managed_ifaces",
                set(),
        ):
            add_iface(allowed, iface)

        # Include interfaces currently owned by LanManager.
        try:
            lan_ifaces = getattr(self.lan_manager, "lan_ifaces", None)

            if isinstance(lan_ifaces, (set, list, tuple)):
                for iface in lan_ifaces:
                    add_iface(allowed, iface)
        except Exception:
            pass

        # Include current software-bridge members.
        try:
            bridge_members = self.ethernet_manager.get_bridge_members()

            if isinstance(bridge_members, (set, list, tuple)):
                for iface in bridge_members:
                    add_iface(allowed, iface)
        except Exception:
            pass

        # Explicitly assigned aliases share the LAN DHCP scope.
        for iface in self._dhcp_server_settings.get("additional_ifaces", []) or []:
            add_iface(allowed, iface)
            try:
                if getattr(self, "router_network_in", None) and self.router_ip_in:
                    self._ensure_virtual_interface_ipv4_metadata(
                        iface, router_ip=self.router_ip_in, network=self.router_network_in,
                        router_mac=self.mac_in, source="shared-lan-dhcp",
                    )
            except Exception:
                pass

        # Existing virtual downstream adapters also join the LAN scope unless an
        # independent profile explicitly owns them.
        dedicated = {
            str(p.get("iface") or "").casefold()
            for p in getattr(self, "_dhcp_interface_profiles", []) or []
        }
        for full_name, cfg in list((self._interfaces_config or {}).items()):
            friendly = str((cfg or {}).get("friendly_name") or full_name)
            if (
                self._looks_like_virtual_downstream_iface(full_name)
                or self._looks_like_virtual_downstream_iface(friendly)
            ) and str(full_name).casefold() not in dedicated and str(friendly).casefold() not in dedicated:
                add_iface(allowed, full_name)
                add_iface(allowed, friendly)

        # A deny rule always overrides an allow rule.
        selected_normalized = {str(iface).casefold() for iface in selected_ifaces}
        denied = {
            iface for iface in denied
            if str(iface).casefold() not in selected_normalized
        }
        denied_normalized = {
            str(iface).casefold()
            for iface in denied
        }

        allowed = {
            iface
            for iface in allowed
            if str(iface).casefold() not in denied_normalized
        }

        return allowed, denied

    def _dhcp_wan_control_plane_iface_sets(
            self,
    ) -> tuple[set[str], set[str]]:
        """
        Build a narrow policy for the optional WAN DHCP server.

        Only the selected active OUT interface is allowed. LAN, loopback, and
        socket interfaces are denied so enabling WAN DHCP cannot broaden the
        existing LAN server's ownership.
        """
        allowed: set[str] = set()
        denied: set[str] = set()

        def add_iface(target: set[str], value) -> None:
            value = str(value or "").strip()
            if value:
                target.add(value)

        selected_ifaces = {
            str(value).strip()
            for value in self._wan_dhcp_server_settings.get("selected_ifaces", []) or []
            if str(value).strip()
        }
        add_iface(allowed, self.interface_out_full_name)
        add_iface(allowed, self.interface_out_friendly_name)
        for iface in selected_ifaces:
            add_iface(allowed, iface)

        add_iface(denied, self.interface_in_full_name)
        add_iface(denied, self.interface_in_friendly_name)
        add_iface(denied, self.interface_loopback_full_name)
        add_iface(denied, SocketInterface.IFACE_NAME)

        for iface in getattr(
                self,
                "wifi_host_managed_ifaces",
                set(),
        ):
            add_iface(denied, iface)

        try:
            lan_ifaces = getattr(self.lan_manager, "lan_ifaces", None)
            if isinstance(lan_ifaces, (set, list, tuple)):
                for iface in lan_ifaces:
                    add_iface(denied, iface)
        except Exception:
            pass

        selected_normalized = {str(iface).casefold() for iface in selected_ifaces}
        denied = {
            iface for iface in denied
            if str(iface).casefold() not in selected_normalized
        }
        allowed_normalized = {
            str(iface).casefold()
            for iface in allowed
        }
        denied = {
            iface
            for iface in denied
            if str(iface).casefold() not in allowed_normalized
        }

        return allowed, denied

    def _configure_dhcp_control_plane(
            self,
            *,
            reason: str = "runtime",
    ) -> dict:
        """
        Atomically update DHCP interface ownership without restarting the server,
        clearing leases, resetting NAT, or changing Windows interface state.
        """
        server_specs = [
            (
                "lan",
                getattr(self, "dhcp_server_in", None),
                self._dhcp_control_plane_iface_sets,
            ),
            (
                "wan",
                getattr(self, "dhcp_server_out", None),
                self._dhcp_wan_control_plane_iface_sets,
            ),
        ]

        results = {}

        for role_name, server, policy_factory in server_specs:
            if server is None:
                continue

            allowed, denied = policy_factory()
            interface_roles = {
                iface: f"{role_name}-dhcp-server"
                for iface in allowed
            }
            interface_roles.update({
                iface: "deny"
                for iface in denied
            })

            signature = (
                id(server),
                tuple(sorted(
                    str(iface).casefold()
                    for iface in allowed
                )),
                tuple(sorted(
                    str(iface).casefold()
                    for iface in denied
                )),
            )
            previous_signature = (
                self._dhcp_control_plane_signatures.get(role_name)
            )
            changed = signature != previous_signature

            configure_policy = getattr(
                server,
                "configure_interface_policy",
                None,
            )
            if callable(configure_policy):
                policy_snapshot = configure_policy(
                    allowed_ifaces=allowed,
                    denied_ifaces=denied,
                    observe_only_ifaces=set(),
                    interface_roles=interface_roles,
                    replace=True,
                    reason=f"{reason}:{role_name}",
                )
            else:
                server.serve_on_all_ifaces = False
                server.allowed_ifaces = set(allowed)
                server.denied_ifaces = set(denied)
                policy_snapshot = {
                    "legacy": True,
                    "allowed": sorted(allowed),
                    "denied": sorted(denied),
                }

            self._dhcp_control_plane_signatures[role_name] = signature

            if changed:
                self.router_logger.log_message(
                    f"[DHCP][ControlPlane][{role_name.upper()}] "
                    f"✅ Configured reason={reason} "
                    f"allowed={sorted(allowed)} "
                    f"denied={sorted(denied)}"
                )

            results[role_name] = {
                "configured": True,
                "changed": changed,
                "policy": policy_snapshot,
            }

        self._dhcp_control_plane_signature = tuple(
            sorted(self._dhcp_control_plane_signatures.items())
        )

        return {
            "configured": bool(results),
            "reason": reason if results else "no-server",
            "servers": results,
        }

    @staticmethod
    def _default_dhcp_pool(
            network: ipaddress.IPv4Network,
            router_ip: str,
    ) -> tuple[str, str]:
        router_address = ipaddress.IPv4Address(router_ip)
        first_host = int(network.network_address) + 1
        last_host = int(network.broadcast_address) - 1
        router_value = int(router_address)

        if last_host < first_host:
            raise RuntimeError(
                f"No usable DHCP addresses exist in {network}."
            )

        below = (first_host, router_value - 1)
        above = (router_value + 1, last_host)
        candidates = [
            pair
            for pair in (below, above)
            if pair[0] <= pair[1]
        ]
        if not candidates:
            raise RuntimeError(
                f"No DHCP range remains after reserving {router_address}."
            )

        start_value, end_value = max(
            candidates,
            key=lambda pair: pair[1] - pair[0],
        )
        return (
            str(ipaddress.IPv4Address(start_value)),
            str(ipaddress.IPv4Address(end_value)),
        )

    def _create_configured_dhcp_server(
            self,
            *,
            role_name: str,
            iface_name: str,
            network: ipaddress.IPv4Network,
            router_ip: str,
            router_mac: str,
            settings: dict,
            policy_factory,
    ):
        settings = dict(settings or {})
        pool_start = settings.get("pool_start")
        pool_end = settings.get("pool_end")

        if not pool_start or not pool_end:
            pool_start, pool_end = self._default_dhcp_pool(
                network,
                router_ip,
            )

        pool_start_ip = ipaddress.IPv4Address(pool_start)
        pool_end_ip = ipaddress.IPv4Address(pool_end)
        router_address = ipaddress.IPv4Address(router_ip)

        if pool_start_ip > pool_end_ip:
            raise ValueError(
                f"{role_name.upper()} DHCP pool start is after pool end."
            )
        if settings.get("enforce_same_subnet", True):
            if pool_start_ip not in network or pool_end_ip not in network:
                raise ValueError(
                    f"{role_name.upper()} DHCP pool must be inside "
                    f"{network}."
                )
        if pool_start_ip <= router_address <= pool_end_ip:
            raise ValueError(
                f"{role_name.upper()} DHCP pool includes router address "
                f"{router_address}."
            )

        allowed_ifaces, denied_ifaces = policy_factory()
        interface_roles = {
            iface: f"{role_name}-dhcp-server"
            for iface in allowed_ifaces
        }
        interface_roles.update({
            iface: "deny"
            for iface in denied_ifaces
        })

        server = DHCPServer(
            self.router_logger,
            self.packet_writer,
            iface_name,
            str(pool_start_ip),
            str(pool_end_ip),
            self._interfaces_config,
            dhcp_relay_target_ip=settings.get(
                "dhcp_relay_target_ip"
            ),
            dhcp6_prefix=settings.get("dhcp6_prefix"),
            dhcp6_relay_target_ip=settings.get(
                "dhcp6_relay_target_ip"
            ),
            in_mac=router_mac,
            allow_out_of_pool=bool(
                settings.get("allow_out_of_pool", False)
            ),
            enforce_same_subnet=bool(
                settings.get("enforce_same_subnet", True)
            ),
            serve_on_all_ifaces=False,
            authoritative=bool(
                settings.get("authoritative", True)
            ),
            rogue_policy=str(
                settings.get("rogue_policy", "log")
            ),
            dns_v6=list(settings.get("dns_v6") or []),
            search_domains=list(
                settings.get("search_domains") or []
            ),
            allowed_ifaces=allowed_ifaces,
            denied_ifaces=denied_ifaces,
            observe_only_ifaces=set(),
            interface_roles=interface_roles,
            control_plane_name=f"router-{role_name}-dhcp",
            preserve_leases_on_policy_update=True,
            lease_duration_seconds=int(
                settings.get("lease_duration_seconds", 600)
            ),
            dns_v4=list(settings.get("dns_v4") or []),
            domain_name=settings.get("domain_name"),
            max_leases=settings.get("max_leases"),
        )
        server.sniffer = self.sniffer
        server.router_ipv6_link_local_out = (
            self.router_ipv6_link_local_out
        )
        server.start()

        self.router_logger.log_message(
            f"[DHCP][{role_name.upper()}] 🚀 Serving {pool_start_ip}-"
            f"{pool_end_ip} on {iface_name}."
        )
        return server

    def _start_dhcp_interface_profile_servers(self) -> None:
        """Start isolated DHCP scopes bound to explicitly named logical/virtual interfaces."""
        old_servers = dict(getattr(self, "dhcp_interface_servers", {}) or {})
        self.dhcp_interface_servers = {}
        for server in old_servers.values():
            try:
                server.stop()
            except Exception:
                pass

        for profile in getattr(self, "_dhcp_interface_profiles", []) or []:
            iface = str(profile.get("iface") or "").strip()
            if not iface:
                continue
            iv = ipaddress.IPv4Interface(str(profile["cidr"]))
            network = iv.network
            router_ip = str(iv.ip)
            profile_settings = dict(self._dhcp_server_settings)
            profile_settings.update({
                key: value for key, value in profile.items()
                if key not in {"iface", "interface", "cidr", "router_cidr", "aliases"}
            })
            aliases = {iface}
            aliases.update(str(x).strip() for x in (profile.get("aliases") or []) if str(x).strip())
            for alias in aliases:
                self._ensure_virtual_interface_ipv4_metadata(
                    alias, router_ip=router_ip, network=network, router_mac=self.mac_in,
                    source=f"dedicated-dhcp:{iface}",
                )
            try:
                server = self._create_configured_dhcp_server(
                    role_name=f"iface:{iface}", iface_name=iface, network=network,
                    router_ip=router_ip, router_mac=self.mac_in, settings=profile_settings,
                    policy_factory=self._dhcp_profile_policy_factory(aliases),
                )
                self.dhcp_interface_servers[iface] = server
                self.router_logger.log_message(
                    f"[DHCP][InterfaceScope] ✅ {iface} owns {network} router={router_ip} aliases={sorted(aliases)}"
                )
            except Exception as exc:
                self.router_logger.log_message(
                    f"[DHCP][InterfaceScope] ❌ Could not start {iface}: {exc}"
                )

    def _start_dhcp_servers(self):
        """
        Start the configured LAN server and, only when explicitly requested,
        an isolated WAN server with its own pool and interface policy.
        """
        if self._enable_dhcp_server:
            if not getattr(self, "router_network_in", None):
                self.router_logger.log_message(
                    "[DHCP][LAN] ❌ Router LAN network is unavailable."
                )
            else:
                existing_server = getattr(
                    self,
                    "dhcp_server_in",
                    None,
                )
                if existing_server is not None:
                    existing_server.sniffer = self.sniffer
                    existing_server.router_ipv6_link_local_out = (
                        self.router_ipv6_link_local_out
                    )
                    existing_server.start()
                    self.router_logger.log_message(
                        "[DHCP][LAN] ♻️ Adopted the DHCP server "
                        "created by LanManager."
                    )
                else:
                    interface_config = self._interfaces_config.get(
                        self.interface_in_full_name,
                        {},
                    )
                    router_lan_ip = (
                        interface_config.get("ip_addr")
                        or self.router_ip_in
                    )
                    router_lan_mac = (
                        interface_config.get("mac")
                        or self.mac_in
                    )
                    try:
                        self.dhcp_server_in = (
                            self._create_configured_dhcp_server(
                                role_name="lan",
                                iface_name=self.interface_in_full_name,
                                network=self.router_network_in,
                                router_ip=router_lan_ip,
                                router_mac=router_lan_mac,
                                settings=self._dhcp_server_settings,
                                policy_factory=(
                                    self._dhcp_control_plane_iface_sets
                                ),
                            )
                        )
                    except Exception as exc:
                        self.dhcp_server_in = None
                        self.router_logger.log_message(
                            f"[DHCP][LAN] ❌ Startup failed: {exc}"
                        )
        else:
            if self.dhcp_server_in is not None:
                try:
                    self.dhcp_server_in.stop()
                except Exception:
                    pass
            self.dhcp_server_in = None
            self.router_logger.log_message(
                "[DHCP][LAN] ⏭️ LAN DHCP server disabled by settings."
            )

        if self._serve_dhcp_on_wan:
            if (
                not getattr(self, "router_network_out", None)
                or not self.interface_out_full_name
                or not self.router_ip_out
            ):
                self.dhcp_server_out = None
                self.router_logger.log_message(
                    "[DHCP][WAN] ❌ WAN DHCP requested, but the active "
                    "WAN interface/network is unavailable."
                )
            else:
                interface_config = self._interfaces_config.get(
                    self.interface_out_full_name,
                    {},
                )
                router_wan_ip = (
                    interface_config.get("ip_addr")
                    or self.router_ip_out
                )
                router_wan_mac = (
                    interface_config.get("mac")
                    or self.mac_out
                )
                try:
                    self.dhcp_server_out = (
                        self._create_configured_dhcp_server(
                            role_name="wan",
                            iface_name=self.interface_out_full_name,
                            network=self.router_network_out,
                            router_ip=router_wan_ip,
                            router_mac=router_wan_mac,
                            settings=self._wan_dhcp_server_settings,
                            policy_factory=(
                                self._dhcp_wan_control_plane_iface_sets
                            ),
                        )
                    )
                    self.router_logger.log_message(
                        "[DHCP][WAN] ⚠️ WAN DHCP is active on the "
                        "selected uplink."
                    )
                except Exception as exc:
                    self.dhcp_server_out = None
                    self.router_logger.log_message(
                        f"[DHCP][WAN] ❌ Startup failed: {exc}"
                    )
        else:
            if self.dhcp_server_out is not None:
                try:
                    self.dhcp_server_out.stop()
                except Exception:
                    pass
            self.dhcp_server_out = None

        # Dedicated logical/virtual scopes are separate from LAN/WAN ownership.
        self._start_dhcp_interface_profile_servers()

        try:
            self.arp_manager.set_dhcp_server_reference(
                self.dhcp_server_in,
                self.dhcp_server_out,
            )
        except Exception as exc:
            self.router_logger.log_message(
                f"[DHCP] ⚠️ Could not update ARP DHCP references: {exc}"
            )

        self._configure_dhcp_control_plane(
            reason="server-start"
        )

    def _dispatch_dhcp_packet(
            self,
            packet,
            inbound_iface: str,
    ) -> str:
        """
        Results:
            served   - Python DHCP owns the interface and handled the packet.
            bypass   - Windows, ICS, or an upstream DHCP server owns it.
            not-dhcp - No DHCP action was taken.
        """
        servers = list((getattr(self, "dhcp_interface_servers", {}) or {}).values()) + [
            getattr(self, "dhcp_server_out", None),
            getattr(self, "dhcp_server_in", None),
        ]
        servers = [server for server in servers if server is not None]

        if not servers:
            return "not-dhcp"

        self._configure_dhcp_control_plane(
            reason="dhcp-dispatch-refresh"
        )

        for server in servers:
            decision = server.interface_policy_decision(
                inbound_iface
            )

            if decision == "serve":
                handled = server.handle_packet(
                    packet,
                    inbound_iface,
                    self.rip_manager.find_route,
                )
                return "served" if handled else "not-dhcp"

            if decision == "observe":
                server.handle_packet(
                    packet,
                    inbound_iface,
                    self.rip_manager.find_route,
                )
                return "bypass"

        # No configured DHCP instance owns this interface.
        logger_server = servers[0]
        logger_server._policy_log_limited(
            f"bypass:{logger_server._normalize_iface_name(inbound_iface)}",
            (
                f"[DHCP][ControlPlane] 🚪 BYPASS DHCP on "
                f"{inbound_iface}; no configured server owns it"
            ),
            cooldown=15.0,
        )

        return "bypass"

    # DNS dispatcher results.
    DNS_DISPOSITION_NOT_DNS = "not-dns"
    DNS_DISPOSITION_HANDLED = "handled"
    DNS_DISPOSITION_HOST_PASSTHROUGH = "host-passthrough"
    DNS_DISPOSITION_TRANSIT_PASSTHROUGH = "transit-passthrough"
    DNS_DISPOSITION_SPECIAL_NAME_SERVICE = "special-name-service"
    DNS_DISPOSITION_DROP = "drop"

    # Common DNS registry values used only for readable packet metadata/logging.
    # Unknown values are retained numerically, so newer RR types still survive.
    DNS_TYPE_NAMES = {
        1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR",
        15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 35: "NAPTR",
        39: "DNAME", 41: "OPT", 43: "DS", 44: "SSHFP", 46: "RRSIG",
        47: "NSEC", 48: "DNSKEY", 50: "NSEC3", 51: "NSEC3PARAM",
        52: "TLSA", 64: "SVCB", 65: "HTTPS", 99: "SPF", 108: "EUI48",
        109: "EUI64", 249: "TKEY", 250: "TSIG", 251: "IXFR",
        252: "AXFR", 255: "ANY", 256: "URI", 257: "CAA",
    }
    DNS_CLASS_NAMES = {1: "IN", 3: "CH", 4: "HS", 254: "NONE", 255: "ANY"}
    DNS_RCODE_NAMES = {
        0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
        4: "NOTIMP", 5: "REFUSED", 6: "YXDOMAIN", 7: "YXRRSET",
        8: "NXRRSET", 9: "NOTAUTH", 10: "NOTZONE", 16: "BADVERS",
    }

    def _dns_normalize_ip(self, value) -> str:
        try:
            return str(value or "").strip().split("%", 1)[0].lower()
        except Exception:
            return ""

    def _dns_safe_int(self, value, default: int = 0) -> int:
        try:
            value = getattr(value, "value", value)
            return int(value)
        except (TypeError, ValueError, OverflowError):
            return int(default)

    def _dns_router_ip_set(self) -> set[str]:
        result: set[str] = set()

        try:
            addresses = self._get_all_local_ips() or []
        except Exception:
            addresses = []

        for address in addresses:
            normalized = self._dns_normalize_ip(address)
            if normalized:
                result.add(normalized)

        for attribute_name in (
                "router_ip_out",
                "router_ipv4_out",
                "router_ipv6_out",
                "router_ipv6_link_local_out",
        ):
            normalized = self._dns_normalize_ip(
                getattr(self, attribute_name, None)
            )
            if normalized:
                result.add(normalized)

        return result

    def _dns_is_fragmented_packet(self, packet) -> bool:
        """Return True when DNS must wait for IP reassembly."""
        try:
            if packet.haslayer(IP):
                ip = packet[IP]
                fragment_offset = self._dns_safe_int(getattr(ip, "frag", 0), 0)
                try:
                    more_fragments = bool(int(getattr(ip, "flags", 0)) & 0x01)
                except Exception:
                    more_fragments = "MF" in str(getattr(ip, "flags", ""))

                if fragment_offset != 0 or more_fragments:
                    return True

            ipv6_fragment_class = globals().get("IPv6ExtHdrFragment")
            if (
                    ipv6_fragment_class is not None
                    and packet.haslayer(ipv6_fragment_class)
            ):
                return True
        except Exception:
            return False

        return False

    def _dns_type_name(self, value: int) -> str:
        value = self._dns_safe_int(value, 0)
        return self.DNS_TYPE_NAMES.get(value, f"TYPE{value}")

    def _dns_class_name(self, value: int) -> str:
        value = self._dns_safe_int(value, 0)
        return self.DNS_CLASS_NAMES.get(value, f"CLASS{value}")

    def _dns_rcode_name(self, value: int) -> str:
        value = self._dns_safe_int(value, 0)
        return self.DNS_RCODE_NAMES.get(value, f"RCODE{value}")

    def _dns_wire_label_text(self, label: bytes) -> str:
        if not label:
            return ""

        try:
            return label.decode("idna")
        except Exception:
            try:
                return label.decode("utf-8", errors="replace")
            except Exception:
                return "\\x" + label.hex()

    def _dns_read_wire_name(
            self,
            wire: bytes,
            offset: int,
            *,
            max_jumps: int = 32,
            max_labels: int = 128,
    ) -> tuple[str, int]:
        """
        Decode one RFC 1035 domain name, including compression pointers.

        The returned offset always points after the bytes consumed at the original
        location, not after the pointer target. This is required for RR traversal.
        """
        wire_length = len(wire)
        cursor = int(offset)
        consumed_offset = None
        labels: list[str] = []
        visited: set[int] = set()
        jumps = 0

        while True:
            if cursor < 0 or cursor >= wire_length:
                raise ValueError("DNS name offset is outside the message")

            if cursor in visited:
                raise ValueError("DNS compression pointer loop")
            visited.add(cursor)

            length = wire[cursor]

            if length == 0:
                if consumed_offset is None:
                    consumed_offset = cursor + 1
                break

            marker = length & 0xC0

            if marker == 0xC0:
                if cursor + 1 >= wire_length:
                    raise ValueError("truncated DNS compression pointer")

                pointer = ((length & 0x3F) << 8) | wire[cursor + 1]
                if pointer >= wire_length:
                    raise ValueError("DNS compression pointer is outside message")

                if consumed_offset is None:
                    consumed_offset = cursor + 2

                cursor = pointer
                jumps += 1
                if jumps > max_jumps:
                    raise ValueError("too many DNS compression pointer jumps")
                continue

            # 01xxxxxx and 10xxxxxx are reserved extended-label forms. They are
            # not ordinary RFC 1035 labels and must not be accepted as a hostname.
            if marker != 0:
                raise ValueError("unsupported DNS extended label")

            if length > 63:
                raise ValueError("DNS label exceeds 63 bytes")

            start = cursor + 1
            end = start + length
            if end > wire_length:
                raise ValueError("truncated DNS label")

            labels.append(self._dns_wire_label_text(wire[start:end]))
            if len(labels) > max_labels:
                raise ValueError("too many DNS labels")

            cursor = end

        name = ".".join(labels).rstrip(".").lower()
        if len(name.encode("utf-8", errors="ignore")) > 1024:
            raise ValueError("decoded DNS name is unreasonably long")

        return name or ".", int(consumed_offset)

    def _dns_format_svc_params(self, data: bytes) -> str:
        params: list[str] = []
        cursor = 0
        key_names = {
            0: "mandatory", 1: "alpn", 2: "no-default-alpn", 3: "port",
            4: "ipv4hint", 5: "ech", 6: "ipv6hint", 7: "dohpath",
            8: "ohttp",
        }

        while cursor + 4 <= len(data) and len(params) < 16:
            key, length = struct.unpack("!HH", data[cursor:cursor + 4])
            cursor += 4
            if cursor + length > len(data):
                params.append(f"key{key}=<truncated>")
                break

            value = data[cursor:cursor + length]
            cursor += length
            name = key_names.get(key, f"key{key}")

            try:
                if key == 1:  # ALPN: one-byte length-prefixed strings
                    items = []
                    p = 0
                    while p < len(value):
                        item_len = value[p]
                        p += 1
                        if p + item_len > len(value):
                            break
                        items.append(value[p:p + item_len].decode("ascii", errors="replace"))
                        p += item_len
                    rendered = ",".join(items)
                elif key == 3 and len(value) == 2:
                    rendered = str(struct.unpack("!H", value)[0])
                elif key == 4 and len(value) % 4 == 0:
                    rendered = ",".join(
                        socket.inet_ntop(socket.AF_INET, value[i:i + 4])
                        for i in range(0, len(value), 4)
                    )
                elif key == 6 and len(value) % 16 == 0:
                    rendered = ",".join(
                        socket.inet_ntop(socket.AF_INET6, value[i:i + 16])
                        for i in range(0, len(value), 16)
                    )
                elif key == 7:
                    rendered = value.decode("utf-8", errors="replace")
                elif key in (0,) and len(value) % 2 == 0:
                    rendered = ",".join(
                        str(struct.unpack("!H", value[i:i + 2])[0])
                        for i in range(0, len(value), 2)
                    )
                elif key in (2, 8) and not value:
                    rendered = ""
                else:
                    rendered = value.hex()[:128]
            except Exception:
                rendered = value.hex()[:128]

            params.append(f"{name}={rendered}" if rendered else name)

        if cursor < len(data):
            params.append(f"trailing={data[cursor:].hex()[:64]}")

        return " ".join(params)

    def _dns_format_rr_rdata(
            self,
            wire: bytes,
            rdata_offset: int,
            rdlength: int,
            rr_type: int,
            rr_class: int,
            rr_ttl: int,
    ) -> str:
        """Render common RR payloads without trusting Scapy's field binding."""
        end = rdata_offset + rdlength
        if rdata_offset < 0 or rdlength < 0 or end > len(wire):
            raise ValueError("truncated DNS RDATA")

        data = wire[rdata_offset:end]

        try:
            if rr_type == 1 and len(data) == 4:
                return socket.inet_ntop(socket.AF_INET, data)

            if rr_type == 28 and len(data) == 16:
                return socket.inet_ntop(socket.AF_INET6, data)

            if rr_type in (2, 5, 12, 39):
                name, _ = self._dns_read_wire_name(wire, rdata_offset)
                return name

            if rr_type == 15 and len(data) >= 3:
                preference = struct.unpack("!H", data[:2])[0]
                exchange, _ = self._dns_read_wire_name(wire, rdata_offset + 2)
                return f"{preference} {exchange}"

            if rr_type == 33 and len(data) >= 7:
                priority, weight, port = struct.unpack("!HHH", data[:6])
                target, _ = self._dns_read_wire_name(wire, rdata_offset + 6)
                return f"{priority} {weight} {port} {target}"

            if rr_type in (16, 99):
                texts: list[str] = []
                cursor = 0
                while cursor < len(data) and len(texts) < 32:
                    text_length = data[cursor]
                    cursor += 1
                    if cursor + text_length > len(data):
                        texts.append("<truncated>")
                        break
                    texts.append(
                        data[cursor:cursor + text_length]
                        .decode("utf-8", errors="replace")
                    )
                    cursor += text_length
                return " | ".join(texts)

            if rr_type == 6:
                mname, cursor = self._dns_read_wire_name(wire, rdata_offset)
                rname, cursor = self._dns_read_wire_name(wire, cursor)
                if cursor + 20 > end:
                    raise ValueError("truncated SOA integers")
                serial, refresh, retry, expire, minimum = struct.unpack(
                    "!IIIII", wire[cursor:cursor + 20]
                )
                return (
                    f"{mname} {rname} serial={serial} refresh={refresh} "
                    f"retry={retry} expire={expire} minimum={minimum}"
                )

            if rr_type == 35 and len(data) >= 5:
                order, preference = struct.unpack("!HH", data[:4])
                cursor = 4
                fields = []
                for _ in range(3):
                    if cursor >= len(data):
                        raise ValueError("truncated NAPTR character-string")
                    size = data[cursor]
                    cursor += 1
                    if cursor + size > len(data):
                        raise ValueError("truncated NAPTR character-string")
                    fields.append(data[cursor:cursor + size].decode("utf-8", errors="replace"))
                    cursor += size
                replacement, _ = self._dns_read_wire_name(wire, rdata_offset + cursor)
                return f"{order} {preference} {' '.join(fields)} {replacement}"

            if rr_type == 43 and len(data) >= 4:
                key_tag, algorithm, digest_type = struct.unpack("!HBB", data[:4])
                return (
                    f"keytag={key_tag} alg={algorithm} digest={digest_type} "
                    f"{data[4:].hex()}"
                )

            if rr_type == 48 and len(data) >= 4:
                flags, protocol, algorithm = struct.unpack("!HBB", data[:4])
                return (
                    f"flags={flags} protocol={protocol} alg={algorithm} "
                    f"key={data[4:].hex()[:192]}"
                )

            if rr_type == 46 and len(data) >= 18:
                covered, algorithm, labels, original_ttl, expiration, inception, key_tag = struct.unpack(
                    "!HBBIIIH", data[:18]
                )
                signer, signer_end = self._dns_read_wire_name(wire, rdata_offset + 18)
                signature_start = signer_end
                signature = wire[signature_start:end].hex()[:192]
                return (
                    f"covered={self._dns_type_name(covered)} alg={algorithm} labels={labels} "
                    f"original_ttl={original_ttl} expiration={expiration} "
                    f"inception={inception} keytag={key_tag} signer={signer} sig={signature}"
                )

            if rr_type == 52 and len(data) >= 3:
                usage, selector, matching = struct.unpack("!BBB", data[:3])
                return (
                    f"usage={usage} selector={selector} matching={matching} "
                    f"data={data[3:].hex()}"
                )

            if rr_type in (64, 65) and len(data) >= 3:
                priority = struct.unpack("!H", data[:2])[0]
                target, target_end = self._dns_read_wire_name(wire, rdata_offset + 2)
                params = self._dns_format_svc_params(wire[target_end:end])
                return f"priority={priority} target={target}" + (f" {params}" if params else "")

            if rr_type == 257 and len(data) >= 2:
                flags = data[0]
                tag_length = data[1]
                if 2 + tag_length > len(data):
                    raise ValueError("truncated CAA tag")
                tag = data[2:2 + tag_length].decode("ascii", errors="replace")
                value = data[2 + tag_length:].decode("utf-8", errors="replace")
                return f"{flags} {tag} {value}"

            if rr_type == 256 and len(data) >= 4:
                priority, weight = struct.unpack("!HH", data[:4])
                target = data[4:].decode("utf-8", errors="replace")
                return f"{priority} {weight} {target}"

            if rr_type == 41:
                # OPT uses CLASS as advertised UDP payload size and TTL bits for
                # extended RCODE/version/flags. Decode its option list.
                options: list[str] = []
                cursor = 0
                while cursor + 4 <= len(data) and len(options) < 16:
                    option_code, option_length = struct.unpack("!HH", data[cursor:cursor + 4])
                    cursor += 4
                    if cursor + option_length > len(data):
                        options.append(f"opt{option_code}=<truncated>")
                        break
                    option_data = data[cursor:cursor + option_length]
                    cursor += option_length
                    options.append(f"opt{option_code}={option_data.hex()[:96]}")

                ext_rcode = (rr_ttl >> 24) & 0xFF
                version = (rr_ttl >> 16) & 0xFF
                do_flag = bool(rr_ttl & 0x8000)
                rendered = (
                    f"udp={rr_class} ext_rcode={ext_rcode} version={version} "
                    f"do={int(do_flag)}"
                )
                if options:
                    rendered += " " + " ".join(options)
                return rendered

        except Exception as exc:
            return f"<decode-error:{exc}> raw={data.hex()[:256]}"

        return data.hex()[:512]

    def _dns_parse_wire_message(self, wire: bytes) -> dict:
        """
        Parse a DNS datagram directly from captured bytes.

        This parser is intentionally bounded and independent of Scapy. It gives the
        dispatcher real question/answer names even when Scapy leaves UDP payload as
        Raw, wraps qd/an in a packet-list field, or partially decodes compression.
        """
        if not isinstance(wire, (bytes, bytearray, memoryview)):
            raise TypeError("DNS wire message must be bytes-like")

        wire = bytes(wire)
        if len(wire) < 12:
            raise ValueError("DNS message is shorter than the 12-byte header")
        if len(wire) > 65535:
            raise ValueError("DNS UDP message exceeds 65535 bytes")

        (
            transaction_id,
            flags,
            question_count,
            answer_count,
            authority_count,
            additional_count,
        ) = struct.unpack("!HHHHHH", wire[:12])

        qr = (flags >> 15) & 0x01
        opcode = (flags >> 11) & 0x0F
        rcode = flags & 0x0F

        if question_count > 64:
            raise ValueError("DNS question count is unreasonably large")
        if any(count > 4096 for count in (answer_count, authority_count, additional_count)):
            raise ValueError("DNS RR count is unreasonably large")
        if question_count + answer_count + authority_count + additional_count > 8192:
            raise ValueError("DNS section counts are unreasonably large")

        cursor = 12
        questions: list[dict] = []

        for index in range(question_count):
            name, cursor = self._dns_read_wire_name(wire, cursor)
            if cursor + 4 > len(wire):
                raise ValueError(f"truncated DNS question {index}")
            qtype, qclass = struct.unpack("!HH", wire[cursor:cursor + 4])
            cursor += 4
            questions.append({
                "name": name,
                "type": qtype,
                "type_name": self._dns_type_name(qtype),
                "class": qclass,
                "class_name": self._dns_class_name(qclass),
            })

        def parse_rr_section(section_name: str, count: int) -> list[dict]:
            nonlocal cursor
            records: list[dict] = []

            for index in range(count):
                name, cursor = self._dns_read_wire_name(wire, cursor)
                if cursor + 10 > len(wire):
                    raise ValueError(f"truncated {section_name} RR header {index}")

                rr_type, rr_class, ttl, rdlength = struct.unpack(
                    "!HHIH", wire[cursor:cursor + 10]
                )
                cursor += 10
                rdata_offset = cursor
                rdata_end = cursor + rdlength
                if rdata_end > len(wire):
                    raise ValueError(f"truncated {section_name} RR data {index}")

                rdata_text = self._dns_format_rr_rdata(
                    wire,
                    rdata_offset,
                    rdlength,
                    rr_type,
                    rr_class,
                    ttl,
                )

                records.append({
                    "name": name,
                    "type": rr_type,
                    "type_name": self._dns_type_name(rr_type),
                    "class": rr_class,
                    "class_name": self._dns_class_name(rr_class),
                    "ttl": ttl,
                    "rdlength": rdlength,
                    "rdata": bytes(wire[rdata_offset:rdata_end]),
                    "rdata_text": rdata_text,
                })
                cursor = rdata_end

            return records

        answers = parse_rr_section("answer", answer_count)
        authorities = parse_rr_section("authority", authority_count)
        additionals = parse_rr_section("additional", additional_count)

        # A query with no question and no update/notify opcode is almost certainly
        # random bytes that happened to travel on port 53. Empty responses are legal.
        if qr == 0 and opcode == 0 and question_count == 0:
            raise ValueError("standard DNS query has no question")

        return {
            "wire": wire,
            "wire_length": len(wire),
            "transaction_id": transaction_id,
            "flags": flags,
            "qr": qr,
            "opcode": opcode,
            "aa": (flags >> 10) & 0x01,
            "tc": (flags >> 9) & 0x01,
            "rd": (flags >> 8) & 0x01,
            "ra": (flags >> 7) & 0x01,
            "z": (flags >> 6) & 0x01,
            "ad": (flags >> 5) & 0x01,
            "cd": (flags >> 4) & 0x01,
            "rcode": rcode,
            "rcode_name": self._dns_rcode_name(rcode),
            "question_count": question_count,
            "answer_count": answer_count,
            "authority_count": authority_count,
            "additional_count": additional_count,
            "questions": questions,
            "answers": answers,
            "authorities": authorities,
            "additionals": additionals,
            "parsed_length": cursor,
            "trailing_bytes": wire[cursor:],
        }

    def _dns_udp_payload_bytes(self, packet) -> bytes:
        """
        Extract exactly the UDP application payload.

        UDP.len includes the eight-byte UDP header. Trimming prevents Ethernet or
        capture padding from being mistaken for DNS records. `bytes(udp.payload)`
        works for both Raw payloads from Wireshark and Scapy-bound DNS payloads.
        """
        udp = packet.getlayer(UDP)
        if udp is None:
            return b""

        payload_object = udp.payload
        try:
            original = getattr(payload_object, "original", None)
            payload = bytes(original) if original else bytes(payload_object)
        except Exception:
            try:
                payload = bytes(payload_object)
            except Exception:
                return b""

        if not payload:
            return b""

        udp_length = self._dns_safe_int(getattr(udp, "len", 0), 0)
        if udp_length >= 8:
            expected_payload_length = udp_length - 8
            if expected_payload_length <= len(payload):
                payload = payload[:expected_payload_length]

        return payload

    def _dns_decode_udp_wire(self, packet) -> dict | None:
        """Decode and validate DNS from the exact UDP payload."""
        udp = packet.getlayer(UDP)
        if udp is None:
            return None

        sport = self._dns_safe_int(getattr(udp, "sport", 0), 0)
        dport = self._dns_safe_int(getattr(udp, "dport", 0), 0)
        if sport != 53 and dport != 53:
            return None

        wire = self._dns_udp_payload_bytes(packet)
        if len(wire) < 12:
            return None

        try:
            result = self._dns_parse_wire_message(wire)
        except Exception:
            return None

        # Build a Scapy DNS object for existing DNSManager implementations, but do
        # not use it as the source of truth for names or RR data.
        decoded_dns = None
        try:
            decoded_dns = DNS(wire)
            if self._dns_safe_int(getattr(decoded_dns, "id", -1), -1) != result["transaction_id"]:
                decoded_dns = None
        except Exception:
            decoded_dns = None

        result["dns"] = decoded_dns
        return result

    def _dns_make_decoded_packet(self, packet, wire_result: dict | None):
        """Create a DNS-bound copy while preserving the original packet for forwarding."""
        if not wire_result or packet.getlayer(UDP) is None:
            return packet

        decoded_dns = wire_result.get("dns")
        wire = bytes(wire_result.get("wire") or b"")
        if decoded_dns is None and wire:
            try:
                decoded_dns = DNS(wire)
            except Exception:
                return packet

        if decoded_dns is None:
            return packet

        try:
            normalized = packet.copy()
            udp = normalized.getlayer(UDP)
            if udp is None:
                return packet

            udp.remove_payload()
            try:
                udp.add_payload(decoded_dns.copy())
            except Exception:
                udp.add_payload(DNS(wire))

            # Checksums/lengths belong to the original captured packet. The
            # normalized copy is for manager inspection, not direct reinjection.
            return normalized
        except Exception as exc:
            self._dns_dispatch_log_limited(
                key="dns-normalized-packet-failure",
                message=f"[DNS] ⚠️ Could not create normalized DNS packet: {exc}",
                interval_sec=10.0,
            )
            return packet

    def _dns_scapy_section_items(self, section, expected_count: int = 0) -> list:
        """Normalize Scapy's single-packet, packet-list, and chained RR layouts."""
        if section is None:
            return []

        items: list = []

        if isinstance(section, (list, tuple)):
            items.extend(section)
        else:
            try:
                # Scapy's _DNSPacketListField behaves list-like in newer releases.
                if hasattr(section, "__iter__") and not hasattr(section, "qname") and not hasattr(section, "rrname"):
                    items.extend(list(section))
                else:
                    items.append(section)
            except Exception:
                items.append(section)

        # Older Scapy versions may chain records through payload.
        flattened: list = []
        seen: set[int] = set()
        limit = max(1, min(int(expected_count or 1), 4096))

        for item in items:
            current = item
            while current is not None and len(flattened) < limit:
                identity = id(current)
                if identity in seen:
                    break
                seen.add(identity)
                flattened.append(current)

                payload = getattr(current, "payload", None)
                if payload is None or payload.__class__.__name__ in ("NoPayload", "Raw"):
                    break
                if not (hasattr(payload, "qname") or hasattr(payload, "rrname")):
                    break
                current = payload

        return flattened

    def _dns_questions_from_scapy(self, dns) -> list[dict]:
        if dns is None:
            return []

        expected = self._dns_safe_int(getattr(dns, "qdcount", 0), 0)
        result: list[dict] = []

        for question in self._dns_scapy_section_items(getattr(dns, "qd", None), expected):
            try:
                qname = getattr(question, "qname", b"")
                if isinstance(qname, bytes):
                    raw_name = qname.rstrip(b".")
                    try:
                        name = raw_name.decode("idna").rstrip(".").lower()
                    except Exception:
                        name = raw_name.decode("utf-8", errors="replace").rstrip(".").lower()
                else:
                    name = str(qname or "").rstrip(".").lower()
                if not name:
                    continue

                qtype = self._dns_safe_int(getattr(question, "qtype", 0), 0)
                qclass = self._dns_safe_int(getattr(question, "qclass", 0), 0)
                result.append({
                    "name": name,
                    "type": qtype,
                    "type_name": self._dns_type_name(qtype),
                    "class": qclass,
                    "class_name": self._dns_class_name(qclass),
                })
            except Exception:
                continue

        return result

    def _dns_question_summary(self, questions: list[dict] | None) -> str:
        questions = list(questions or [])
        if not questions:
            return "<no-question>"

        rendered = []
        for question in questions[:4]:
            rendered.append(
                f"{question.get('name') or '.'} "
                f"{question.get('type_name') or self._dns_type_name(question.get('type', 0))}/"
                f"{question.get('class_name') or self._dns_class_name(question.get('class', 0))}"
            )
        if len(questions) > 4:
            rendered.append(f"+{len(questions) - 4} more")
        return ", ".join(rendered)

    def _dns_answer_summary(self, answers: list[dict] | None) -> str:
        answers = list(answers or [])
        if not answers:
            return "<no-answer>"

        rendered = []
        for answer in answers[:4]:
            rendered.append(
                f"{answer.get('name') or '.'} "
                f"{answer.get('type_name') or self._dns_type_name(answer.get('type', 0))}="
                f"{answer.get('rdata_text', '')} ttl={answer.get('ttl', 0)}"
            )
        if len(answers) > 4:
            rendered.append(f"+{len(answers) - 4} more")
        return "; ".join(rendered)

    def _dns_safe_question_name(self, dns) -> str:
        questions = self._dns_questions_from_scapy(dns)
        if not questions:
            return "<no-question>"
        return str(questions[0].get("name") or "<no-question>")

    def _dns_pending_key(
            self,
            *,
            transport: str,
            src_ip: str,
            sport: int,
            dst_ip: str,
            dport: int,
            transaction_id: int,
    ) -> tuple:
        return (
            str(transport or "udp").lower(),
            self._dns_normalize_ip(src_ip),
            self._dns_safe_int(sport, 0),
            self._dns_normalize_ip(dst_ip),
            self._dns_safe_int(dport, 0),
            self._dns_safe_int(transaction_id, 0),
        )

    def _dns_correlate_wire_message(
            self,
            metadata: dict,
            *,
            src_ip: str,
            dst_ip: str,
    ) -> None:
        """Remember queries and recover omitted response questions safely."""
        wire_result = metadata.get("wire_result")
        if not wire_result:
            return

        lock = getattr(self, "_dns_pending_wire_lock", None)
        if lock is None:
            lock = threading.Lock()
            self._dns_pending_wire_lock = lock

        table = getattr(self, "_dns_pending_wire_queries", None)
        if table is None:
            table = {}
            self._dns_pending_wire_queries = table

        now = time.monotonic()
        ttl = 45.0
        transaction_id = self._dns_safe_int(wire_result.get("transaction_id"), 0)
        transport = str(metadata.get("transport") or "udp")
        sport = self._dns_safe_int(metadata.get("sport"), 0)
        dport = self._dns_safe_int(metadata.get("dport"), 0)
        qr = self._dns_safe_int(metadata.get("qr"), 0)

        with lock:
            if len(table) > 4096:
                for key, value in list(table.items()):
                    if now - float(value.get("seen", 0.0)) > ttl:
                        table.pop(key, None)
                if len(table) > 4096:
                    oldest = sorted(table.items(), key=lambda item: float(item[1].get("seen", 0.0)))[:1024]
                    for key, _ in oldest:
                        table.pop(key, None)

            if qr == 0:
                key = self._dns_pending_key(
                    transport=transport,
                    src_ip=src_ip,
                    sport=sport,
                    dst_ip=dst_ip,
                    dport=dport,
                    transaction_id=transaction_id,
                )
                table[key] = {
                    "seen": now,
                    "questions": list(wire_result.get("questions") or []),
                    "server_ip": self._dns_normalize_ip(dst_ip),
                    "transaction_id": transaction_id,
                    "transport": transport,
                }
                return

            response_key = self._dns_pending_key(
                transport=transport,
                src_ip=dst_ip,
                sport=dport,
                dst_ip=src_ip,
                dport=sport,
                transaction_id=transaction_id,
            )
            candidate = table.get(response_key)

            if candidate is None:
                # NAT can change the client-side address/port before the reply is
                # captured. Use a conservative unique match by server+ID+transport.
                matches = [
                    value
                    for value in table.values()
                    if (
                        value.get("transaction_id") == transaction_id
                        and value.get("transport") == transport
                        and value.get("server_ip") == self._dns_normalize_ip(src_ip)
                        and now - float(value.get("seen", 0.0)) <= ttl
                    )
                ]
                if len(matches) == 1:
                    candidate = matches[0]

            if candidate and not wire_result.get("questions"):
                recovered = list(candidate.get("questions") or [])
                wire_result["questions"] = recovered
                metadata["questions"] = recovered
                metadata["question_recovered_from_query"] = bool(recovered)

    def _dns_extract_packet_metadata(self, packet) -> dict:
        """Identify DNS and extract real questions/answers from UDP wire bytes."""
        udp = packet.getlayer(UDP)
        tcp = packet.getlayer(TCP)

        if udp is not None:
            transport = "udp"
            transport_layer = udp
        elif tcp is not None:
            transport = "tcp"
            transport_layer = tcp
        else:
            return {
                "is_dns_related": False,
                "is_standard_dns": False,
                "transport": None,
                "sport": 0,
                "dport": 0,
                "dns": None,
                "dispatch_packet": packet,
                "qr": None,
                "rcode": None,
                "special": None,
                "fragmented": False,
                "decoded_from_wire": False,
                "direction_mismatch": False,
                "wire_result": None,
                "questions": [],
                "answers": [],
                "authorities": [],
                "additionals": [],
            }

        sport = self._dns_safe_int(getattr(transport_layer, "sport", 0), 0)
        dport = self._dns_safe_int(getattr(transport_layer, "dport", 0), 0)

        special = None
        if sport == 5353 or dport == 5353:
            special = "mdns"
        elif sport == 5355 or dport == 5355:
            special = "llmnr"
        elif sport in (137, 138) or dport in (137, 138):
            special = "nbns"

        is_standard_dns = sport == 53 or dport == 53
        is_dns_related = bool(is_standard_dns or special)
        existing_dns = packet.getlayer(DNS)
        wire_result = None

        if transport == "udp" and is_standard_dns and special is None:
            wire_result = self._dns_decode_udp_wire(packet)

        if wire_result is not None:
            dns = wire_result.get("dns") or existing_dns
            qr = self._dns_safe_int(wire_result.get("qr"), 0)
            rcode = self._dns_safe_int(wire_result.get("rcode"), 0)
            dispatch_packet = self._dns_make_decoded_packet(packet, wire_result)
            questions = list(wire_result.get("questions") or [])
            answers = list(wire_result.get("answers") or [])
            authorities = list(wire_result.get("authorities") or [])
            additionals = list(wire_result.get("additionals") or [])
            decoded_from_wire = True
        else:
            dns = existing_dns
            dispatch_packet = packet
            qr = self._dns_safe_int(getattr(dns, "qr", 0), 0) if dns is not None else None
            rcode = self._dns_safe_int(getattr(dns, "rcode", 0), 0) if dns is not None else None
            questions = self._dns_questions_from_scapy(dns)
            answers = []
            authorities = []
            additionals = []
            decoded_from_wire = False

        port_direction = None
        if dport == 53 and sport != 53:
            port_direction = 0
        elif sport == 53 and dport != 53:
            port_direction = 1

        direction_mismatch = bool(
            qr is not None
            and port_direction is not None
            and int(qr) != int(port_direction)
        )

        return {
            "is_dns_related": is_dns_related,
            "is_standard_dns": is_standard_dns,
            "transport": transport,
            "sport": sport,
            "dport": dport,
            "dns": dns,
            "dispatch_packet": dispatch_packet,
            "qr": qr,
            "rcode": rcode,
            "rcode_name": self._dns_rcode_name(rcode or 0),
            "special": special,
            "fragmented": self._dns_is_fragmented_packet(packet),
            "decoded_from_wire": decoded_from_wire,
            "direction_mismatch": direction_mismatch,
            "wire_result": wire_result,
            "questions": questions,
            "answers": answers,
            "authorities": authorities,
            "additionals": additionals,
            "question_summary": self._dns_question_summary(questions),
            "answer_summary": self._dns_answer_summary(answers),
        }

    def _dns_dispatch_log_limited(
            self,
            key: str,
            message: str,
            interval_sec: float = 5.0,
    ):
        """Rate-limit duplicate capture-path logs without hiding different DNS messages."""
        now = time.monotonic()
        table = getattr(self, "_dns_dispatch_log_times", None)
        if table is None:
            table = {}
            self._dns_dispatch_log_times = table

        last = float(table.get(key, 0.0))
        if now - last < float(interval_sec):
            return
        table[key] = now

        if len(table) > 2048:
            cutoff = now - max(float(interval_sec) * 4.0, 30.0)
            for existing_key, timestamp in list(table.items()):
                if float(timestamp) < cutoff:
                    table.pop(existing_key, None)

        self.router_logger.log_message(message)

    def _dns_deliver_to_manager(
            self,
            dns_packet,
            inbound_iface: str,
            *,
            qr,
            context: dict,
    ) -> dict:
        """
        Deliver one captured DNS packet to DNSManager exactly once.

        ``handled=False`` means DNSManager received the packet but intentionally
        left it on the host/transit path. It must not be interpreted as a failed
        delivery. TCP/53 packets are observation-only until a complete framed DNS
        message has been reassembled by the manager's TCP listener/stream logic.
        """
        result = {
            "available": False,
            "called": False,
            "handled": False,
            "method": None,
            "error": None,
        }

        manager = getattr(self, "dns_manager", None)
        if manager is None:
            return result

        result["available"] = True
        manager_context = dict(context or {})
        manager_context["dns_manager_delivery"] = True
        manager_context["observation_only"] = bool(
            manager_context.get("transport") == "tcp"
        )
        manager_context["complete_dns_message"] = bool(
            manager_context.get("transport") == "udp"
            and manager_context.get("dns_wire")
        )

        try:
            process_packet = getattr(manager, "process_packet", None)
            if callable(process_packet):
                result["method"] = "process_packet"
                try:
                    result["handled"] = bool(
                        process_packet(
                            dns_packet,
                            inbound_iface,
                            context=manager_context,
                        )
                    )
                except TypeError as exc:
                    message = str(exc)
                    context_unsupported = (
                        "unexpected keyword argument 'context'" in message
                        or 'unexpected keyword argument "context"' in message
                    )
                    if not context_unsupported:
                        raise
                    result["handled"] = bool(
                        process_packet(dns_packet, inbound_iface)
                    )
                result["called"] = True
                return result

            # Compatibility with older DNSManager implementations. Never feed an
            # arbitrary TCP segment into UDP-only handle_query/handle_response.
            if manager_context.get("transport") == "udp":
                if self._dns_safe_int(qr, -1) == 0:
                    handler = getattr(manager, "handle_query", None)
                    if callable(handler):
                        result["method"] = "handle_query"
                        result["handled"] = bool(
                            handler(dns_packet, inbound_iface)
                        )
                        result["called"] = True
                        return result
                elif self._dns_safe_int(qr, -1) == 1:
                    handler = getattr(manager, "handle_response", None)
                    if callable(handler):
                        result["method"] = "handle_response"
                        result["handled"] = bool(handler(dns_packet))
                        result["called"] = True
                        return result

            # Optional passive hook for managers that separate observation from
            # resolver ownership, especially for TCP stream segments.
            for method_name in (
                    "observe_dns_packet",
                    "observe_packet",
                    "ingest_dns_packet",
            ):
                observer = getattr(manager, method_name, None)
                if not callable(observer):
                    continue
                result["method"] = method_name
                try:
                    observer(
                        dns_packet,
                        inbound_iface,
                        context=manager_context,
                    )
                except TypeError as exc:
                    message = str(exc)
                    context_unsupported = (
                        "unexpected keyword argument 'context'" in message
                        or 'unexpected keyword argument "context"' in message
                    )
                    if not context_unsupported:
                        raise
                    observer(dns_packet, inbound_iface)
                result["called"] = True
                return result

            return result

        except Exception as exc:
            result["error"] = exc
            return result

    def _dispatch_dns_packet(
            self,
            packet,
            inbound_iface: str,
            *,
            src_ip=None,
            dst_ip=None,
    ) -> str:
        """Dispatch one DNS packet using wire-derived QR, questions, and answers."""
        metadata = self._dns_extract_packet_metadata(packet)
        dns_packet = metadata.get("dispatch_packet") or packet

        if not metadata["is_dns_related"]:
            return self.DNS_DISPOSITION_NOT_DNS
        if metadata["special"] is not None:
            return self.DNS_DISPOSITION_SPECIAL_NAME_SERVICE

        src_ip = self._dns_normalize_ip(src_ip)
        dst_ip = self._dns_normalize_ip(dst_ip)
        if not src_ip or not dst_ip:
            if packet.haslayer(IP):
                src_ip = self._dns_normalize_ip(packet[IP].src)
                dst_ip = self._dns_normalize_ip(packet[IP].dst)
            elif packet.haslayer(IPv6):
                src_ip = self._dns_normalize_ip(packet[IPv6].src)
                dst_ip = self._dns_normalize_ip(packet[IPv6].dst)

        local_ips = self._dns_router_ip_set()
        source_is_router = src_ip in local_ips
        destination_is_router = dst_ip in local_ips
        belongs_to_host = source_is_router or destination_is_router

        transport = metadata["transport"]
        sport = metadata["sport"]
        dport = metadata["dport"]
        dns = metadata["dns"]
        qr = metadata["qr"]
        fragmented = metadata["fragmented"]

        if transport == "tcp":
            # TCP capture gives us stream segments, not necessarily one complete
            # length-prefixed DNS message. Deliver the segment to DNSManager for
            # observation/stream handling, then preserve the host/transit path.
            tcp_context = {
                "capture_phase": "pre-nat",
                "capture_source": inbound_iface,
                "inbound_iface": inbound_iface,
                "src_ip": src_ip,
                "dst_ip": dst_ip,
                "source_is_router": source_is_router,
                "destination_is_router": destination_is_router,
                "is_transit": not belongs_to_host,
                "transport": "tcp",
                "sport": sport,
                "dport": dport,
                "dns_qr": qr,
                "dns_wire": b"",
                "tcp_stream_segment": True,
            }
            delivery = self._dns_deliver_to_manager(
                dns_packet,
                inbound_iface,
                qr=qr,
                context=tcp_context,
            )
            disposition = (
                self.DNS_DISPOSITION_HOST_PASSTHROUGH
                if belongs_to_host
                else self.DNS_DISPOSITION_TRANSIT_PASSTHROUGH
            )
            delivery_state = (
                "handled"
                if delivery.get("handled")
                else "observed/pass-through"
                if delivery.get("called")
                else "no-compatible-manager-hook"
            )
            if delivery.get("error") is not None:
                delivery_state = f"manager-error={delivery['error']}"
            self._dns_dispatch_log_limited(
                key=f"tcp-dns:{disposition}:{src_ip}:{sport}:{dst_ip}:{dport}",
                message=(
                    f"[DNS] 🧵 TCP/53 {'host-stack' if belongs_to_host else 'transit'} "
                    f"pass-through on {inbound_iface}: "
                    f"{src_ip}:{sport} -> {dst_ip}:{dport} | "
                    f"DNSManager={delivery_state} method={delivery.get('method') or '-'}"
                ),
                interval_sec=3.0,
            )
            return (
                self.DNS_DISPOSITION_HANDLED
                if delivery.get("handled")
                else disposition
            )

        if fragmented:
            disposition = (
                self.DNS_DISPOSITION_HOST_PASSTHROUGH
                if belongs_to_host
                else self.DNS_DISPOSITION_TRANSIT_PASSTHROUGH
            )
            self._dns_dispatch_log_limited(
                key=f"fragmented-dns:{disposition}:{src_ip}:{dst_ip}",
                message=(
                    f"[DNS] 🧩 Fragmented DNS {'host-stack' if belongs_to_host else 'transit'} "
                    f"pass-through on {inbound_iface}: "
                    f"{src_ip}:{sport} -> {dst_ip}:{dport}"
                ),
            )
            return disposition

        if metadata.get("wire_result") is None and dns is None:
            payload_length = len(self._dns_udp_payload_bytes(packet)) if transport == "udp" else 0
            self._dns_dispatch_log_limited(
                key=f"invalid-dns-wire:{transport}:{inbound_iface}:{src_ip}:{sport}:{dst_ip}:{dport}",
                message=(
                    f"[DNS] ⚠️ Port-53 packet has no structurally valid DNS message on "
                    f"{inbound_iface}: {src_ip}:{sport} -> {dst_ip}:{dport} "
                    f"payload_bytes={payload_length}"
                ),
                interval_sec=5.0,
            )
            return (
                self.DNS_DISPOSITION_HOST_PASSTHROUGH
                if belongs_to_host
                else self.DNS_DISPOSITION_TRANSIT_PASSTHROUGH
            )

        self._dns_correlate_wire_message(metadata, src_ip=src_ip, dst_ip=dst_ip)
        questions = list(metadata.get("questions") or [])
        answers = list(metadata.get("answers") or [])
        question_summary = self._dns_question_summary(questions)
        answer_summary = self._dns_answer_summary(answers)
        transaction_id = self._dns_safe_int(
            (metadata.get("wire_result") or {}).get("transaction_id", getattr(dns, "id", 0)),
            0,
        )

        if metadata.get("decoded_from_wire"):
            direction_word = "RESPONSE" if qr == 1 else "QUERY"
            detail = (
                f"answers={answer_summary}"
                if qr == 1
                else f"questions={question_summary}"
            )
            self._dns_dispatch_log_limited(
                key=(
                    f"wire-dns:{inbound_iface}:{src_ip}:{sport}:{dst_ip}:{dport}:"
                    f"{transaction_id}:{qr}:{question_summary}:{answer_summary}"
                ),
                message=(
                    f"[DNS] 🧬 Real UDP DNS {direction_word} from capture on {inbound_iface}: "
                    f"{src_ip}:{sport} -> {dst_ip}:{dport} id={transaction_id} "
                    f"rcode={metadata.get('rcode')}({metadata.get('rcode_name')}) "
                    f"{detail}"
                ),
                interval_sec=0.75,
            )

        if metadata.get("direction_mismatch"):
            port_direction = (
                "query" if dport == 53 and sport != 53
                else "response" if sport == 53 and dport != 53
                else "unknown"
            )
            dns_direction = "response" if qr == 1 else "query"
            self._dns_dispatch_log_limited(
                key=f"dns-direction-mismatch:{src_ip}:{sport}:{dst_ip}:{dport}:{transaction_id}",
                message=(
                    f"[DNS] 🔄 Direction mismatch on {inbound_iface}: ports imply "
                    f"{port_direction}, wire QR implies {dns_direction}; "
                    f"id={transaction_id} q={question_summary}"
                ),
                interval_sec=5.0,
            )

        context = {
            "capture_phase": "pre-nat",
            "capture_source": inbound_iface,
            "inbound_iface": inbound_iface,
            "src_ip": src_ip,
            "dst_ip": dst_ip,
            "source_is_router": source_is_router,
            "destination_is_router": destination_is_router,
            "is_transit": not belongs_to_host,
            "transport": transport,
            "sport": sport,
            "dport": dport,
            "dns_wire": bytes((metadata.get("wire_result") or {}).get("wire") or b""),
            "dns_wire_metadata": metadata.get("wire_result"),
            "dns_questions": questions,
            "dns_answers": answers,
            "dns_authorities": list(metadata.get("authorities") or []),
            "dns_additionals": list(metadata.get("additionals") or []),
            "dns_transaction_id": transaction_id,
            "dns_qr": qr,
            "dns_rcode": metadata.get("rcode"),
            "dns_rcode_name": metadata.get("rcode_name"),
            "decoded_from_udp_wire": bool(metadata.get("decoded_from_wire")),
        }

        delivery = self._dns_deliver_to_manager(
            dns_packet,
            inbound_iface,
            qr=qr,
            context=context,
        )

        if not delivery.get("available"):
            self._dns_dispatch_log_limited(
                key="dns-manager-unavailable",
                message=(
                    "[DNS][DISPATCH] ⚠️ Valid DNS packet decoded, but DNSManager "
                    "is not initialized."
                ),
                interval_sec=5.0,
            )
            return (
                self.DNS_DISPOSITION_HOST_PASSTHROUGH
                if belongs_to_host
                else self.DNS_DISPOSITION_TRANSIT_PASSTHROUGH
            )

        if delivery.get("error") is not None:
            self.router_logger.log_message(
                f"[DNS][DISPATCH] ❗ DNSManager delivery failed on {inbound_iface}: "
                f"{delivery['error']} | id={transaction_id} "
                f"q={question_summary} a={answer_summary}"
            )
            return (
                self.DNS_DISPOSITION_HOST_PASSTHROUGH
                if belongs_to_host
                else self.DNS_DISPOSITION_TRANSIT_PASSTHROUGH
            )

        delivery_state = (
            "handled"
            if delivery.get("handled")
            else "observed/pass-through"
            if delivery.get("called")
            else "no-compatible-manager-hook"
        )
        self._dns_dispatch_log_limited(
            key=(
                f"dns-manager-delivery:{inbound_iface}:{src_ip}:{sport}:"
                f"{dst_ip}:{dport}:{transaction_id}:{qr}:{delivery_state}"
            ),
            message=(
                f"[DNS][DISPATCH] 📬 DNSManager received "
                f"{'RESPONSE' if qr == 1 else 'QUERY'} on {inbound_iface}: "
                f"{src_ip}:{sport} -> {dst_ip}:{dport} id={transaction_id} "
                f"method={delivery.get('method') or '-'} decision={delivery_state} "
                f"q={question_summary} a={answer_summary}"
            ),
            interval_sec=0.75,
        )

        if delivery.get("handled"):
            return self.DNS_DISPOSITION_HANDLED

        if qr == 0 and source_is_router:
            self._dns_dispatch_log_limited(
                key=f"os-query:{src_ip}:{sport}:{dst_ip}:{dport}:{transaction_id}",
                message=(
                    f"[DNS] 🖥️ DNSManager observed host resolver query; host-stack pass-through on {inbound_iface}: "
                    f"{src_ip}:{sport} -> {dst_ip}:{dport} id={transaction_id} "
                    f"q={question_summary}"
                ),
                interval_sec=2.0,
            )
            return self.DNS_DISPOSITION_HOST_PASSTHROUGH

        if qr == 1 and destination_is_router:
            self._dns_dispatch_log_limited(
                key=f"os-response:{src_ip}:{sport}:{dst_ip}:{dport}:{transaction_id}",
                message=(
                    f"[DNS] 🖥️ DNSManager observed host resolver response; host-stack pass-through on {inbound_iface}: "
                    f"{src_ip}:{sport} -> {dst_ip}:{dport} id={transaction_id} "
                    f"rcode={metadata.get('rcode_name')} q={question_summary} "
                    f"a={answer_summary}"
                ),
                interval_sec=2.0,
            )
            return self.DNS_DISPOSITION_HOST_PASSTHROUGH

        if qr == 0 and destination_is_router:
            self._dns_dispatch_log_limited(
                key=f"local-listener-query:{src_ip}:{sport}:{dst_ip}:{dport}:{transaction_id}",
                message=(
                    f"[DNS] 🎧 Unclaimed local DNS query passed to host listener on "
                    f"{inbound_iface}: {src_ip}:{sport} -> {dst_ip}:{dport} "
                    f"id={transaction_id} q={question_summary}"
                ),
                interval_sec=2.0,
            )
            return self.DNS_DISPOSITION_HOST_PASSTHROUGH

        self._dns_dispatch_log_limited(
            key=f"transit:{qr}:{src_ip}:{sport}:{dst_ip}:{dport}:{transaction_id}",
            message=(
                f"[DNS] ↪️ Unclaimed DNS {'response' if qr == 1 else 'query'} continuing "
                f"as transit on {inbound_iface}: {src_ip}:{sport} -> {dst_ip}:{dport} "
                f"id={transaction_id} q={question_summary} a={answer_summary}"
            ),
            interval_sec=2.0,
        )
        return self.DNS_DISPOSITION_TRANSIT_PASSTHROUGH
    def _remember_codeoutput_flow(self, packet, inbound_iface: str, phase: str = "ingress") -> None:
        """Store a bounded, low-cost communication record for CodeOutput Chat."""
        try:
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if ip_layer is None:
                return
            protocol = "ip"
            sport = dport = 0
            if packet.haslayer(TCP):
                protocol = "tcp"
                sport = int(getattr(packet[TCP], "sport", 0) or 0)
                dport = int(getattr(packet[TCP], "dport", 0) or 0)
            elif packet.haslayer(UDP):
                protocol = "udp"
                sport = int(getattr(packet[UDP], "sport", 0) or 0)
                dport = int(getattr(packet[UDP], "dport", 0) or 0)
            elif packet.haslayer(ICMP) or packet.haslayer(ICMPv6EchoRequest):
                protocol = "icmpv6" if packet.haslayer(IPv6) else "icmp"
            if packet.haslayer(DNS):
                protocol = "dns"
            record = {
                "time": time.time(),
                "phase": str(phase or "ingress"),
                "interface": str(inbound_iface or "unknown"),
                "src": str(getattr(ip_layer, "src", "")),
                "dst": str(getattr(ip_layer, "dst", "")),
                "sport": sport,
                "dport": dport,
                "protocol": protocol,
                "summary": str(packet.summary()),
                "process_pid": getattr(packet, "_process_interface_pid", None),
                "codeoutput": bool(getattr(packet, "_codeoutput_packet", False)),
            }
            key = (
                record["interface"], record["protocol"], record["src"], record["sport"],
                record["dst"], record["dport"], record["phase"],
            )
            with self._codeoutput_flow_lock:
                self._codeoutput_recent_flows.append(record)
                self._codeoutput_flow_counters[key] += 1
                if len(self._codeoutput_flow_counters) > 8192:
                    self._codeoutput_flow_counters = collections.Counter(
                        dict(self._codeoutput_flow_counters.most_common(4096))
                    )
        except Exception:
            pass

    def resolve_interface_identity(self, selector: Optional[str]) -> dict:
        raw = str(selector or "").strip()
        if not raw:
            return {}
        raw_cf = raw.casefold()
        for full_name, config in list(self._interfaces_config.items()):
            if not isinstance(config, dict):
                continue
            aliases = {
                str(full_name), str(config.get("friendly_name") or ""),
                str(config.get("physical_iface") or ""), str(config.get("capture_iface") or ""),
                str(config.get("ip_addr") or ""), str(config.get("if_index") or ""),
            }
            if raw_cf in {value.casefold() for value in aliases if value}:
                return {
                    "selector": raw,
                    "full_name": str(full_name),
                    "friendly_name": str(config.get("friendly_name") or full_name),
                    "ipv4": str(config.get("ip_addr") or ""),
                    "if_index": config.get("if_index"),
                    "aliases": sorted(value for value in aliases if value),
                    "programmatic": bool(config.get("programmatic_interface")),
                    "wan_capable": bool(config.get("wan_capable")),
                }
        return {"selector": raw, "full_name": raw, "friendly_name": raw, "aliases": [raw]}

    def ingest_codeoutput_packet(
            self, packet, *, source_iface: Optional[str] = None,
            direction: str = "wan-in", metadata: Optional[dict] = None,
    ) -> bool:
        """Enter programmatic CodeOutput traffic through the Npcap ingress queue."""
        metadata = dict(metadata or {})
        iface = str(source_iface or CodeOutputInterfaceManager.LOGICAL_IFACE)
        try:
            setattr(packet, "_codeoutput_packet", True)
            setattr(packet, "_codeoutput_metadata", metadata)
            setattr(packet, "_codeoutput_direction", str(direction or "wan-in"))
            setattr(packet, "_router_ingress_owner", "CodeOutputInterfaceManager")
            setattr(packet, "_programmatic_ingress", True)
        except Exception:
            pass
        return bool(self.enqueue_ingress_packet(packet, iface))

    def route_codeoutput_packet(
            self, packet, *, inbound_iface: Optional[str] = None,
            egress_iface: Optional[str] = None,
            reason: str = "codeoutput-explicit",
    ) -> bool:
        """Route only an explicit CodeOutput transmission request.

        Passive observations cannot call this path, which prevents capture and
        reinjection loops.
        """
        try:
            setattr(packet, "_codeoutput_explicit_route", True)
            setattr(packet, "_codeoutput_route_reason", str(reason or "codeoutput-explicit"))
        except Exception:
            pass
        if egress_iface:
            return bool(self.packet_writer.queue_packet(packet, interface=str(egress_iface)))
        return bool(self.ingest_codeoutput_packet(
            packet,
            source_iface=inbound_iface or CodeOutputInterfaceManager.LOGICAL_IFACE,
            direction="explicit",
            metadata={"reason": reason, "explicit": True},
        ))

    def inject_codeoutput_packet(self, packet, metadata: Optional[dict] = None):
        """Inject PacketLab traffic through CodeOutput and the normal router pipeline."""
        metadata = dict(metadata or {})
        try:
            setattr(packet, "_codeoutput_packet", True)
            setattr(packet, "_codeoutput_metadata", metadata)
        except Exception:
            pass
        try:
            self.code_output_manager.submit_packet(
                packet,
                inbound_iface=CodeOutputInterfaceManager.LOGICAL_IFACE,
                phase="packetlab",
                component="codeoutput-interface",
                **metadata,
            )
        except Exception as exc:
            self.router_logger.log_message(f"[CodeOutputInterface] Learning submission warning: {exc}")
        self._remember_codeoutput_flow(
            packet, CodeOutputInterfaceManager.LOGICAL_IFACE, "packetlab"
        )
        self.router_logger.log_message(
            f"[CodeOutputInterface] ➡️ PacketLab injecting {packet.summary()} into router pipeline."
        )
        try:
            return {
                "status": "QUEUED" if self.code_output_manager.ingest_packet(
                    packet,
                    source_iface=CodeOutputInterfaceManager.LOGICAL_IFACE,
                    direction="packetlab",
                    metadata=metadata,
                ) else "REJECTED",
                "interface": CodeOutputInterfaceManager.LOGICAL_IFACE,
                "summary": packet.summary(),
            }
        except Exception:
            return self.codeoutput_interface_manager.submit_packet(
                packet,
                metadata=metadata,
                phase="packetlab",
            )

    def inject_process_packet(self, packet, metadata: Optional[dict] = None):
        """Public bridge used by ProcessTab/process capture to enter the router pipeline."""
        manager = getattr(self, "process_interface_manager", None)
        if manager is None:
            raise RuntimeError("ProcessInterfaceManager is unavailable.")
        return manager.submit_packet(packet, metadata=metadata)

    @staticmethod
    def _counter_lines(counter, *, limit: int = 10, formatter=None) -> list[str]:
        items = counter.most_common(max(1, int(limit)))
        if not items:
            return ["  none observed"]
        lines = []
        for value, count in items:
            label = formatter(value) if formatter else str(value)
            lines.append(f"  {label}: {count}")
        return lines

    def get_codeoutput_communication_snapshot(self, limit: int = 250) -> dict:
        with self._codeoutput_flow_lock:
            flows = list(self._codeoutput_recent_flows)[-max(1, int(limit)):]
        protocols = collections.Counter(x.get("protocol") for x in flows)
        interfaces = collections.Counter(x.get("interface") for x in flows)
        endpoints = collections.Counter()
        ports = collections.Counter()
        conversations = collections.Counter()
        phases = collections.Counter(x.get("phase") for x in flows)
        for item in flows:
            src = item.get("src") or "?"
            dst = item.get("dst") or "?"
            sport = int(item.get("sport") or 0)
            dport = int(item.get("dport") or 0)
            proto = item.get("protocol") or "ip"
            endpoints[src] += 1
            endpoints[dst] += 1
            if sport:
                ports[(proto, sport)] += 1
            if dport:
                ports[(proto, dport)] += 1
            conversations[(src, sport, dst, dport, proto)] += 1

        interface_status = {}
        try:
            interface_status = self.codeoutput_interface_manager.status()
        except Exception:
            pass
        manager_status = {}
        for method_name in ("status", "get_status", "stats", "get_stats"):
            method = getattr(self.code_output_manager, method_name, None)
            if callable(method):
                try:
                    value = method()
                    if isinstance(value, dict):
                        manager_status = value
                    else:
                        manager_status = {"value": str(value)}
                    break
                except Exception:
                    continue

        routes = []
        route_table = getattr(getattr(self, "rip_manager", None), "routing_table", None)
        if isinstance(route_table, dict):
            for network, value in list(route_table.items())[:64]:
                routes.append({"network": str(network), "value": str(value)})
        elif isinstance(route_table, (list, tuple)):
            routes = [str(x) for x in route_table[:64]]

        return {
            "captured": len(flows),
            "protocols": protocols,
            "interfaces": interfaces,
            "endpoints": endpoints,
            "ports": ports,
            "conversations": conversations,
            "phases": phases,
            "recent": flows[-30:],
            "interface_status": interface_status,
            "manager_status": manager_status,
            "routes": routes,
            "router_started": bool(self.started),
        }

    def ask_codeoutput(self, prompt: str = "", chat_history: Optional[list] = None) -> str:
        """Return an English text response grounded in chat context and live router state."""
        question = str(prompt or "summarize current communications").strip()
        history = list(chat_history or [])[-12:]
        prior_user_topics = [
            str(item.get("content") or "").strip()
            for item in history
            if isinstance(item, dict) and str(item.get("role") or "").lower() == "user"
        ]
        data = self.get_codeoutput_communication_snapshot()
        lines = [
            f"CodeOutput response: {question}",
            "I am responding in English text using the current PythonRouter communication state.",
            f"Router running: {'yes' if data['router_started'] else 'no'}; recent flow records: {data['captured']}.",
        ]
        if prior_user_topics:
            lines.append(
                "Chat context considered: " + " | ".join(prior_user_topics[-3:])[:900]
            )
        iface = data.get("interface_status") or {}
        lines.append(
            "CodeOutput interface: "
            + (
                f"ready on {iface.get('interface_alias') or iface.get('adapter_name')} "
                f"({iface.get('ipv4')}/{iface.get('prefix_length')}, capture={iface.get('interface_full_name') or 'pending'})."
                if iface.get("ready")
                else "not currently ready."
            )
        )
        lines.append("\nProtocols:")
        lines.extend(self._counter_lines(data["protocols"], limit=10))
        lines.append("\nInterfaces and routing stages:")
        lines.extend(self._counter_lines(data["interfaces"], limit=12))
        lines.append("\nMost active endpoints:")
        lines.extend(self._counter_lines(data["endpoints"], limit=12))
        lines.append("\nMost active ports:")
        lines.extend(self._counter_lines(
            data["ports"], limit=12,
            formatter=lambda value: f"{value[0].upper()}/{value[1]}",
        ))
        lines.append("\nTop conversations:")
        lines.extend(self._counter_lines(
            data["conversations"], limit=10,
            formatter=lambda value: (
                f"{value[4].upper()} {value[0]}:{value[1]} -> {value[2]}:{value[3]}"
            ),
        ))
        if data["recent"]:
            lines.append("\nRecent flows:")
            for item in data["recent"][-10:]:
                lines.append(
                    f"  [{item.get('interface')}/{item.get('phase')}] "
                    f"{str(item.get('protocol')).upper()} {item.get('src')}:{item.get('sport')} -> "
                    f"{item.get('dst')}:{item.get('dport')}"
                )
        if data.get("routes"):
            lines.append(f"\nKnown RIP routes: {len(data['routes'])} (showing up to 64 in the manager snapshot).")
        manager_status = data.get("manager_status") or {}
        if manager_status:
            preview = ", ".join(f"{k}={v}" for k, v in list(manager_status.items())[:8])
            lines.append(f"CodeOutput knowledge status: {preview}")
        return "\n".join(lines)

    def process_packet(self, packet, inbound_iface: str):
        """
        Main packet processing pipeline with a clear separation for router-destined
        vs. transit traffic.
        """
        yield_no_gil(2.0)
        try:
            iface_short = inbound_iface.split('_')[-1]

            if isinstance(packet, (bytes, bytearray, memoryview)):
                try:
                    raw_bytes = bytes(packet)
                    if not raw_bytes:
                        return

                    # NEW: ultra-early dedupe for loopback / WinDivertBridge echoes
                    if self._should_skip_raw_packet_parse(raw_bytes, inbound_iface):
                        return

                    parse_errors = []

                    def _safe_len(obj) -> int | None:
                        try:
                            return len(obj)
                        except Exception:
                            return None

                    def _raw_len(pkt_obj) -> int | None:
                        try:
                            rb = raw(pkt_obj)
                            return len(rb) if rb is not None else None
                        except Exception:
                            return None

                    def _score_candidate(pkt_obj, buf: bytes, decoder_name: str) -> int:
                        score = 0
                        buf_len = len(buf)

                        try:
                            score += 5

                            pkt_len = _raw_len(pkt_obj)
                            if pkt_len is not None:
                                if pkt_len == buf_len:
                                    score += 30
                                elif pkt_len <= buf_len:
                                    score += 20
                                else:
                                    score -= 10

                            if pkt_obj.haslayer(Raw):
                                score += 1

                            if pkt_obj.haslayer(Ether):
                                score += 15
                                eth = pkt_obj.getlayer(Ether)
                                if hasattr(eth, "type"):
                                    score += 3

                            dot1q_cls = globals().get("Dot1Q")
                            if dot1q_cls is not None and pkt_obj.haslayer(dot1q_cls):
                                score += 10

                            arp_cls = globals().get("ARP")
                            if arp_cls is not None and pkt_obj.haslayer(arp_cls):
                                score += 25

                            if pkt_obj.haslayer(IP):
                                score += 20
                                ip = pkt_obj.getlayer(IP)

                                try:
                                    ihl_words = int(getattr(ip, "ihl", 0) or 0)
                                    ihl_bytes = ihl_words * 4
                                    total_len = int(getattr(ip, "len", 0) or 0)

                                    if ihl_bytes >= 20:
                                        score += 4
                                    else:
                                        score -= 8

                                    if total_len >= max(ihl_bytes, 20):
                                        score += 8
                                    else:
                                        score -= 12

                                    proto = int(getattr(ip, "proto", -1))
                                    if proto in (1, 2, 6, 17, 47, 50, 58, 89):
                                        score += 4
                                except Exception:
                                    score -= 2

                            if pkt_obj.haslayer(IPv6):
                                score += 20
                                ip6 = pkt_obj.getlayer(IPv6)

                                try:
                                    plen = int(getattr(ip6, "plen", -1))
                                    nh = int(getattr(ip6, "nh", -1))
                                    if plen >= 0:
                                        score += 6
                                    if nh in (6, 17, 58, 43, 44, 47, 50, 51):
                                        score += 4
                                except Exception:
                                    score -= 2

                            udp_cls = globals().get("UDP")
                            tcp_cls = globals().get("TCP")
                            icmp_cls = globals().get("ICMP")
                            icmpv6_cls = globals().get("ICMPv6Unknown")

                            if udp_cls is not None and pkt_obj.haslayer(udp_cls):
                                score += 20
                                udp = pkt_obj.getlayer(udp_cls)
                                try:
                                    sport = int(getattr(udp, "sport", -1))
                                    dport = int(getattr(udp, "dport", -1))
                                    if 0 <= sport <= 65535 and 0 <= dport <= 65535:
                                        score += 5
                                    if sport in (53, 5353, 5355, 67, 68) or dport in (53, 5353, 5355, 67, 68):
                                        score += 20
                                except Exception:
                                    score -= 1

                            if tcp_cls is not None and pkt_obj.haslayer(tcp_cls):
                                score += 20
                                tcp = pkt_obj.getlayer(tcp_cls)
                                try:
                                    sport = int(getattr(tcp, "sport", -1))
                                    dport = int(getattr(tcp, "dport", -1))
                                    if 0 <= sport <= 65535 and 0 <= dport <= 65535:
                                        score += 5
                                    if sport in (53, 80, 443) or dport in (53, 80, 443):
                                        score += 8
                                except Exception:
                                    score -= 1

                            if icmp_cls is not None and pkt_obj.haslayer(icmp_cls):
                                score += 12

                            if icmpv6_cls is not None and pkt_obj.haslayer(icmpv6_cls):
                                score += 12

                            dns_cls = globals().get("DNS")
                            dhcp_cls = globals().get("DHCP")
                            bootp_cls = globals().get("BOOTP")

                            if dns_cls is not None and pkt_obj.haslayer(dns_cls):
                                score += 35

                            if dhcp_cls is not None and pkt_obj.haslayer(dhcp_cls):
                                score += 30

                            if bootp_cls is not None and pkt_obj.haslayer(bootp_cls):
                                score += 15

                            if decoder_name == "ARP" and not (
                                    globals().get("ARP") and pkt_obj.haslayer(globals()["ARP"])):
                                score -= 10

                        except Exception:
                            score -= 5

                        return score

                    def _candidate_decoders():
                        names = [
                            "Ether",
                            "IP",
                            "IPv6",
                            "ARP",
                        ]

                        seen = set()
                        out = []
                        for name in names:
                            cls = globals().get(name)
                            if cls is not None and cls not in seen:
                                out.append((name, cls))
                                seen.add(cls)
                        return out

                    best_pkt = None
                    best_score = None
                    candidate_debug = []

                    for decoder_name, decoder in _candidate_decoders():
                        try:
                            pkt_candidate = decoder(raw_bytes)
                            score = _score_candidate(pkt_candidate, raw_bytes, decoder_name)
                            candidate_debug.append(f"{decoder_name}:{score}")

                            if best_pkt is None or score > best_score:
                                best_pkt = pkt_candidate
                                best_score = score
                        except Exception as e:
                            parse_errors.append(f"{decoder_name}={e}")

                    if best_pkt is None:
                        for decoder_name, decoder in _candidate_decoders():
                            try:
                                best_pkt = decoder(raw_bytes)
                                best_score = -999
                                candidate_debug.append(f"{decoder_name}:fallback")
                                break
                            except Exception as e:
                                parse_errors.append(f"{decoder_name}={e}")

                    if best_pkt is None:
                        self.router_logger.log_message(
                            f"[Router] ⚠️ Could not parse packet on {iface_short}; "
                            f"len={len(raw_bytes)} errs={' | '.join(parse_errors[:4])}"
                        )
                        return

                    if best_score is not None and best_score < 10:
                        self.router_logger.log_message(
                            f"[Router] ⚠️ Weak parse on {iface_short}; "
                            f"len={len(raw_bytes)} candidates={' | '.join(candidate_debug[:5])}"
                        )

                    packet = best_pkt

                except Exception as e:
                    self.router_logger.log_message(
                        f"[Router] ⚠️ Packet parse failure on {iface_short}: {e}"
                    )
                    return

            process_interface = getattr(self, "process_interface_manager", None)
            if process_interface is not None:
                try:
                    routed_iface = process_interface.apply_packet_policy(
                        packet,
                        inbound_iface,
                    )
                    if routed_iface != inbound_iface:
                        inbound_iface = routed_iface
                        iface_short = inbound_iface.split('_')[-1]
                except Exception as exc:
                    self._ingress_log_sparse(
                        "process-interface-classify",
                        f"[ProcessInterface] ⚠️ Packet classification failed: {exc}",
                        every=2.0,
                    )

            self._remember_codeoutput_flow(packet, inbound_iface, "ingress")

            # HandshakeManager is an observer, not a consuming router stage.  It must
            # see TCP bytes before LAN/Gateway/peer managers can return early.  This
            # includes frames reinjected from PeerInterface and HyperVManager.
            if (
                    packet.haslayer(TCP)
                    and self.handshake_manager is not None
                    and self._manager_settings.get("enable_handshake", True)
                    and not bool(getattr(packet, "_router_handshake_observed", False))
            ):
                try:
                    self.handshake_manager.handle_packet(packet, inbound_iface)
                    setattr(packet, "_router_handshake_observed", True)
                except Exception as exc:
                    self.router_logger.log_message(
                        f"[Handshake] ⚠️ Early observation failed on {inbound_iface}: {exc}"
                    )

            # Mirror local frames to pure P2P peers without consuming the normal
            # router pipeline. Remote frames re-enter as PeerInterface and are not
            # reflected back, preventing a two-node loop.
            peer_wire_packet = False
            if packet.haslayer(UDP) and self._peerinterface_nat_ports:
                try:
                    peer_wire_packet = bool({
                        int(packet[UDP].sport), int(packet[UDP].dport)
                    } & set(self._peerinterface_nat_ports))
                except Exception:
                    peer_wire_packet = False
            if (
                    self.peerinterface_manager
                    and inbound_iface != "PeerInterface"
                    and not peer_wire_packet
            ):
                try:
                    self.peerinterface_manager.handle_packet(packet, inbound_iface)
                except Exception as exc:
                    self._ingress_log_sparse(
                        "peerinterface-mirror",
                        f"[PeerInterfaceManager] ⚠️ frame mirror failed: {exc}",
                        every=2.0,
                    )

            upstream_observer = self.upstream_manager or self.uplink_manager
            if upstream_observer:
                upstream_observer.observe_packet(packet, inbound_iface)
            if self.gateway_manager:
                self.gateway_manager.observe_packet(packet, inbound_iface)
            if self.lan_manager:
                self.lan_manager.observe_packet(packet, inbound_iface)

            if self.lan_manager and self.lan_manager.handle_packet(packet, inbound_iface):
                return

            if self.gateway_manager and self.gateway_manager.handle_packet(packet, inbound_iface):
                return
            if self.hypervrouter_manager and self.hypervrouter_manager.handle_packet(packet, inbound_iface) and inbound_iface != "HyperVManager":
                return
            if self.host_connectivity_boundary and self.host_connectivity_boundary.should_bypass_router(packet,
                                                                                                        inbound_iface):
                return
            if self.netroute_manager:
                self.netroute_manager.observe_packet(packet, inbound_iface)
            if self.python_server_manager:
                self.python_server_manager.handle_packet(
                    packet,
                    inbound_iface=inbound_iface,
                    component="router",
                    phase="processing",
                    direction="inbound",
                    source="router",
                    raw_bytes=bytes(packet)  # best fidelity
                )
            # --- early in the router packet-processing path ---
            if self.socket_interface and self.socket_interface.handle_packet(packet, inbound_iface):
                return True
            if self.packet_writer and self.packet_writer.observe_inbound_packet(packet, inbound_iface=inbound_iface, source="router-sniffer"):
                pass
            # ==========================================================
            # ✅ ARP HANDLING BLOCK (reply/learn) BEFORE "no IP layer" drop
            # ==========================================================
            if packet.haslayer(ARP):
                if not self.arp_manager.perform_arp_inspection(packet, inbound_iface):
                    self.router_logger.log_message(
                        f"[Router] 🚫 Dropped ARP on {iface_short} (failed inspection)."
                    )
                    return
                self.arp_manager._maybe_learn_passive_arp(packet,inbound_iface=inbound_iface)
                self.arp_manager.learn_from_packet(packet, inbound_iface)
                self.arp_manager.learn_arp_response(packet)
                self.arp_manager.reply_to_arp_request(packet, inbound_iface)
                return

            # 1) Bridge real Ethernet frames on bridge-member ports first
            if packet.haslayer(Ether):
                try:
                    if self.ethernet_manager.is_bridge_member(inbound_iface):
                        self.ethernet_l2_manager.handle_packet(packet, inbound_iface)

                        bridged = self.ethernet_manager.handle_frame(packet, inbound_iface)
                        if bridged:
                            return

                        # not actually sent by bridge, so fall through and let the rest
                        # of process_packet decide whether router logic should handle it
                except Exception as e:
                    self.router_logger.log_message(f"[L2][Bridge] ❌ ingress bridge error on {inbound_iface}: {e}")
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if not ip_layer:
                return

            src_ip=None
            dst_ip=None
            if packet.haslayer(IP):
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
            elif packet.haslayer(IPv6):
                src_ip = packet[IPv6].src
                dst_ip = packet[IPv6].dst

            if src_ip and (src_ip in self.sniffer.banned_ips or dst_ip in self.sniffer.banned_ips):
                banned_ip = src_ip if src_ip in self.sniffer.banned_ips else dst_ip
                if self.notification_manager:
                    self.notification_manager.send_notification({
                        "event": "Router Banned IP Detected",
                        "message": f"Packet on router from {src_ip} to {dst_ip} dropped due to banned IP: {banned_ip} on {inbound_iface}",
                        "iface": inbound_iface,
                        "timestamp": time.time(),
                        "emojis": ["🚫", "🧱", "🛑"]
                    }, cooldown_seconds=10, cooldown_key=f"banned_ip_{banned_ip}")
                return
            if packet.haslayer(IPv6):
                self.ndp_manager.learn_from_packet(packet, inbound_iface)
            if packet.haslayer(IP):
                self.arp_manager.learn_from_packet(packet, inbound_iface)
            if packet.haslayer(ICMPv6ND_NA):
                self.ndp_manager.learn_neighbor_advertisement(packet)
                return
            if (
                    self._manager_settings.get(
                        "enable_firewall",
                        True,
                    )
                    and not self.firewall_manager.process_packet(packet)
            ):
                self.router_logger.log_message(f"[Firewall] 🔥 Blocked packet on {iface_short}")
                return
            if self._manager_settings.get(
                    "enable_packet_analyzer",
                    True,
            ):
                self.packet_analyzer.execute(
                    packet,
                    params=self.default_analysis_extras
                )
            # ==========================================================
            # DNS CONTROL-PLANE DISPATCH — BEFORE HANDSHAKE AND NAT
            # ==========================================================
            dns_metadata = self._dns_extract_packet_metadata(packet)
            dns_display_packet = dns_metadata.get("dispatch_packet")
            if dns_display_packet is None:
                dns_display_packet = packet

            if dns_metadata["is_dns_related"]:
                # Dedicated multicast/local name-service protocols remain separate.
                if dns_metadata["special"] == "mdns":
                    if (
                            self._manager_settings.get(
                                "enable_mdns",
                                True,
                            )
                            and self.mdns_manager.handle_packet(packet)
                    ):
                        self.code_output_manager.submit_packet(
                            packet,
                            inbound_iface=inbound_iface,
                            phase="handled",
                            component="mdns",
                        )
                        return

                elif dns_metadata["special"] == "llmnr":
                    llmnr_manager = getattr(self, "llmnr_manager", None)

                    if (
                            llmnr_manager is not None
                            and llmnr_manager.handle_packet(packet, inbound_iface)
                    ):
                        self.code_output_manager.submit_packet(
                            packet,
                            inbound_iface=inbound_iface,
                            phase="handled",
                            component="llmnr",
                        )
                        return

                elif dns_metadata["special"] == "nbns":
                    nbns_manager = getattr(self, "nbns_manager", None)

                    if (
                            nbns_manager is not None
                            and nbns_manager.handle_packet(packet, inbound_iface)
                    ):
                        self.code_output_manager.submit_packet(
                            packet,
                            inbound_iface=inbound_iface,
                            phase="handled",
                            component="nbns",
                        )
                        return

                else:
                    dns_disposition = self._dispatch_dns_packet(
                        packet,
                        inbound_iface,
                        src_ip=src_ip,
                        dst_ip=dst_ip,
                    )

                    if dns_disposition == self.DNS_DISPOSITION_HANDLED:
                        dns_qr = self._dns_safe_int(
                            dns_metadata.get("qr"),
                            0,
                        )

                        self.code_output_manager.submit_packet(
                            dns_display_packet,
                            inbound_iface=inbound_iface,
                            phase="handled",
                            component=(
                                "dns-response"
                                if dns_qr == 1
                                else "dns-query"
                            ),
                        )
                        return

                    if (
                            dns_disposition
                            == self.DNS_DISPOSITION_HOST_PASSTHROUGH
                    ):
                        # This traffic belongs to Windows, the local DNS TCP listener,
                        # or a DNSManager OS-socket transport. Do not NAT it, duplicate it,
                        # or send it through _forward_general_ip_packet().
                        self.code_output_manager.submit_packet(
                            dns_display_packet,
                            inbound_iface=inbound_iface,
                            phase="bypass",
                            component="dns-host-stack",
                        )
                        return

                    if dns_disposition == self.DNS_DISPOSITION_DROP:
                        self.code_output_manager.submit_packet(
                            dns_display_packet,
                            inbound_iface=inbound_iface,
                            phase="dropped",
                            component="dns-invalid",
                        )
                        return

                    # transit-passthrough intentionally falls through to handshake,
                    # NAT, transport and ordinary router forwarding.
            transport_layer = self.sniffer._find_transport_layer(packet)
            if (
                    isinstance(transport_layer, TCP)
                    and self.handshake_manager is not None
                    and self._manager_settings.get(
                        "enable_handshake",
                        True,
                    )
            ):
                # Usually already observed before any consuming manager. Retain this
                # fallback for packets injected directly into the later pipeline.
                if not bool(getattr(packet, "_router_handshake_observed", False)):
                    if self.handshake_manager.handle_packet(packet, inbound_iface):
                        self.code_output_manager.submit_packet(
                            packet,
                            inbound_iface=inbound_iface,
                            phase="handled",
                            component="handshake",
                        )
                    setattr(packet, "_router_handshake_observed", True)
            nat_decision = self.nat_manager.handle_packet(
                packet,
                inbound_iface,
                router_ips=self._get_all_local_ips(),
                wan_ifaces=set(
                    self.outbound_load_balancer.get_configured_interfaces()
                ),
                lan_ifaces=self._current_lan_transit_ifaces(),
            )

            if nat_decision is False:
                # Dropped (e.g., banned or ICMP sent)
                return

            is_handled_by_transport = self.transport_manager.handle_packet(packet, inbound_iface)

            if is_handled_by_transport:
                if self.netroute_manager:
                    self.netroute_manager.handle_packet(
                        packet,
                        inbound_iface,
                        transport_handled=True,
                        transport_component="transport",
                        install_host_route=True,
                        host_route_cost=1,
                    )
                if self.python_server_manager:
                    self.python_server_manager.handle_packet(
                        packet,
                        inbound_iface=inbound_iface,
                        component="transport",
                        phase="processing",
                        direction="inbound",
                        source="router",
                        raw_bytes=bytes(packet)  # best fidelity
                    )
                self.code_output_manager.submit_packet(
                    packet,
                    inbound_iface=inbound_iface,
                    phase="processing",
                    component="transport"
                )
                return
            dst_ip = ip_layer.dst

            link_local_ip_bare = str(self.router_ipv6_link_local_out or "").split('%')[0]
            if link_local_ip_bare and (dst_ip == link_local_ip_bare or ip_layer.src == link_local_ip_bare):
                self.function_call_tracker.track(
                    identifier="DroppedLinkLocal",
                    threshold=100,
                    final_message=f"[Router] 💧 Dropping packet to our own link-local address: {dst_ip} Count: {{}}.",
                    count_message=None,
                )
                return # Stop processing immediately

            eth_type = self._eth_type_or_none(packet)
            if eth_type is None:
                self.router_logger.log_message("[Bridge] ⚠️ No Ether/IP/IPv6 layer; dropping.")
                return

            if (
                    packet.haslayer(ESP)
                    or packet.haslayer(AH)
                    or packet.haslayer(GRE)
                    or packet.haslayer(ISAKMP)
                    or packet.haslayer(IKEv2)
                    or (
                        packet.haslayer(UDP)
                        and ({int(packet[UDP].sport), int(packet[UDP].dport)} & {500, 4500})
                    )
            ):
                if packet.haslayer(ISAKMP) or packet.haslayer(IKEv2):
                    if self.isakmp_manager.handle_packet(packet, inbound_iface):
                        self.code_output_manager.submit_packet(
                            packet, inbound_iface=inbound_iface,
                            phase="handled", component="isakmp-manager",
                        )
                        return
                handled = self.esp_manager.handle_packet(
                    packet,
                    inbound_iface,
                    self._interfaces_config,
                    self.arp_manager.get_mac,
                    self.rip_manager.find_route,
                )
                if handled:
                    self.code_output_manager.submit_packet(
                        packet, inbound_iface=inbound_iface,
                        phase="handled", component="tunnel-manager",
                    )
                    return
                # Unhandled tunnel traffic stays in the ordinary forwarding path.
                # It is never diverted into a Hyper-V-only C++ pipe.


            is_for_router = dst_ip in self._get_all_local_ips()




            if (
                    packet.haslayer(DHCP)
                    or packet.haslayer(DHCP6)
                    or packet.haslayer(DHCP6_Solicit)
                    or packet.haslayer(DHCP6_InfoRequest)
                    or packet.haslayer(DHCP6_Reply)
            ):
                self.router_logger.log_message(
                    f"[DHCP] 📦 DHCP packet detected on "
                    f"{iface_short} for router"
                )

                dhcp_result = self._dispatch_dhcp_packet(
                    packet,
                    inbound_iface,
                )

                if dhcp_result == "served":
                    self.code_output_manager.submit_packet(
                        packet,
                        inbound_iface=inbound_iface,
                        phase="handled",
                        component="dhcp-control-plane",
                    )
                    return

                if dhcp_result == "bypass":
                    return
            if packet.haslayer(ICMP) or packet.haslayer(ICMPv6):
                self.router_logger.log_message(f"[ICMP] 📶 Processing ICMP on {iface_short} Packet: {packet.summary()}")
                if self.icmp_manager.handle_packet(packet, inbound_iface):
                    self.code_output_manager.submit_packet(
                        packet, inbound_iface=inbound_iface,
                        phase="handled",
                        component="icmp"
                    )
                return

            if (
                    self._manager_settings.get("enable_igmp", True)
                    and (
                        packet.haslayer(IGMP)
                        or packet.haslayer(IGMPv3)
                    )
            ):  # Echo Request
                self.router_logger.log_message(f"[IGMP] 📶 Processing IGMP on {iface_short} Packet: {packet.summary()}")
                if self.igmp_manager.handle_packet(packet, inbound_iface):
                    self.code_output_manager.submit_packet(
                        packet,
                        inbound_iface=inbound_iface,
                        phase="handled",
                        component="igmp",
                    )
                return


            if (
                    packet.haslayer("Kerberos")
                    or (UDP in packet and (int(packet[UDP].sport) in (88, 464) or int(packet[UDP].dport) in (88, 464)))
                    or (TCP in packet and (int(packet[TCP].sport) in (88, 464) or int(packet[TCP].dport) in (88, 464)))
            ):
                if self.kerberos_manager.handle_kerberos_packet(packet, inbound_iface, self._interfaces_config):
                    self.code_output_manager.submit_packet(packet, inbound_iface=inbound_iface,
                                                           phase="handled", component="kerberos")
                    return
            # Duplicate flow check (rate-limiting)
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
            sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else 0
            dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 0

            if self.forwarding_manager.is_duplicate(ip_layer.src, ip_layer.dst, sport, dport, proto):
                return
            if dst_ip in self._get_all_local_ips():
                self.function_call_tracker.track(
                    identifier="DroppedDstIPSame",
                    threshold=20,
                    final_message=f"[Router] 🚫 Skipping self-forwarded packet to {dst_ip} (router's own IP). Count: {{}}.",
                    count_message=None,
                )

                return
            # Final forwarding logic
            self.router_logger.log_message(
                RouterRandomMessages(
                    name="Router",
                    message=f"Forwarding: {packet.summary()} | In:{iface_short}",
                    emoticons=["🚚", "🚛","🚄", "🛻", "🚈", "🚐", "🚙", "🚎", "🚕", "🚑", "🚓", "⛵", "🛶", "🚤", "🛳️", "⛴️", "🛥️", "🚢", "🛩️", "🌁", "🌃", "🏙️", "🌄", "🌅", "🏝️"]
                )
            )
            self.code_output_manager.submit_packet(
                packet,
                inbound_iface=inbound_iface,
                phase="forwarding",
                component="forward",
            )
            self._forward_general_ip_packet(packet, inbound_iface)
        except Exception:
            self.router_logger.log_message(
                f"[Router] ❗ ERROR while processing on {inbound_iface}:\n{traceback.format_exc()}\nPacket: {packet.show(dump=True)}"
            )

    def _forward_general_ip_packet(self, packet, inbound_iface: str):
        """Forwards a transit packet, applying NAT, LAG, ARP resolution, and Layer 2 handling."""
        burn_no_gil(1.0, threads=4)
        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if not ip_layer:
            self.router_logger.log_message("[Router] ❗ No IP layer found in packet. Dropping.")
            return
        dst_ip = ip_layer.dst
        src_ip = ip_layer.src

        # Parse addresses once. Interface metadata can be supplied by JSON,
        # virtual adapters, DHCP profiles, or old cached state, so no forwarding
        # branch is allowed to depend on an unvalidated string network.
        try:
            dst_ip_obj = ipaddress.ip_address(str(dst_ip).split("%", 1)[0])
            src_ip_obj = ipaddress.ip_address(str(src_ip).split("%", 1)[0])
        except ValueError:
            self.router_logger.log_message(
                f"[Router] ❌ Invalid IP address src={src_ip!r} dst={dst_ip!r}. Dropping."
            )
            return

        inbound_is_loopback = self._is_loopback_iface_name(inbound_iface)

        # Windows exposes locally generated NetBIOS/APIPA broadcasts on the
        # Npcap loopback adapter. They are duplicate host-control traffic and
        # must not be routed to the WAN or re-injected onto another adapter.
        if isinstance(dst_ip_obj, ipaddress.IPv4Address):
            broadcast_owners = self._ipv4_broadcast_owner_ifaces(dst_ip_obj)
            is_limited_broadcast = dst_ip_obj == ipaddress.IPv4Address("255.255.255.255")
            is_link_local_control = src_ip_obj.is_link_local or dst_ip_obj.is_link_local
            is_netbios = bool(
                packet.haslayer(UDP)
                and (
                    int(getattr(packet[UDP], "sport", 0) or 0) in {137, 138}
                    or int(getattr(packet[UDP], "dport", 0) or 0) in {137, 138}
                )
            )
            is_directed_broadcast = bool(broadcast_owners)

            if is_netbios and (is_limited_broadcast or is_directed_broadcast or is_link_local_control):
                self._track_local_broadcast_drop(
                    "DroppedLocalNBNSBroadcast",
                    (
                        f"[Router] 🧭 Suppressed local NBNS broadcast "
                        f"{src_ip_obj} → {dst_ip_obj} on {inbound_iface}."
                    ),
                )
                return

            if inbound_is_loopback and (
                    is_limited_broadcast
                    or is_directed_broadcast
                    or is_link_local_control
            ):
                self._track_local_broadcast_drop(
                    "DroppedLoopbackLocalBroadcast",
                    (
                        f"[Router] 🧭 Suppressed loopback-captured local broadcast "
                        f"{src_ip_obj} → {dst_ip_obj} on {inbound_iface}."
                    ),
                )
                return

        # --- Multicast Handling (IPv4 and IPv6) ---
        if dst_ip_obj.is_multicast:
            is_loopback_capture = inbound_is_loopback
            hop_limit = 0
            try:
                hop_limit = int(
                    getattr(ip_layer, "ttl", 0)
                    if isinstance(ip_layer, IP)
                    else getattr(ip_layer, "hlim", 0)
                )
            except Exception:
                hop_limit = 0

            # Windows/Npcap exposes local SSDP, mDNS and LLMNR on the loopback
            # capture interface as well as on their real adapter.  Forwarding that
            # duplicate creates loops and violates TTL/Hop-Limit 1 scope.
            local_discovery_groups = {
                "224.0.0.1", "224.0.0.2", "224.0.0.9",
                "224.0.0.22", "224.0.0.251", "224.0.0.252",
                "239.255.255.250", "ff02::1", "ff02::2",
                "ff02::fb", "ff02::1:2", "ff02::c",
            }
            if is_loopback_capture and (hop_limit <= 1 or str(dst_ip_obj).lower() in local_discovery_groups):
                try:
                    self.function_call_tracker.track(
                        identifier="DroppedLoopbackScopedMulticast",
                        threshold=25,
                        final_message=(
                            f"[Router] 🧭 Suppressed loopback-scoped multicast to {dst_ip_obj} "
                            f"(hop-limit={hop_limit}). Count: {{}}."
                        ),
                        count_message=None,
                    )
                except Exception:
                    pass
                return

            # Compute L2 multicast destination (only needed when we actually send L2)
            mcast_dst_mac = None
            ip_bytes = dst_ip_obj.packed

            is_v4 = isinstance(ip_layer, IP)
            if is_v4:
                # 01:00:5e:0x:xx:xx (lower 23 bits of IPv4)
                mcast_dst_mac = "01:00:5e:%02x:%02x:%02x" % (ip_bytes[1] & 0x7F, ip_bytes[2], ip_bytes[3])
            else:
                # 33:33:xx:xx:xx:xx (lower 32 bits of IPv6)
                mcast_dst_mac = "33:33:%02x:%02x:%02x:%02x" % (ip_bytes[12], ip_bytes[13], ip_bytes[14], ip_bytes[15])

            # Choose egress (keep your own policy; here we mirror inbound)
            egress_iface = inbound_iface
            # L2 is only OK when the driver is NOT windivert/rawip/winfw AND we have a MAC
            egress_l2_ok = self._iface_supports_l2(egress_iface)
            src_mac = self.get_interface_mac(egress_iface) if egress_l2_ok else None
            use_l2 = bool(egress_l2_ok and src_mac)

            if use_l2:
                # L2 path (Npcap): set Ether dst and ensure a valid src MAC
                if not packet.haslayer(Ether):
                    packet = Ether(src=src_mac, dst=mcast_dst_mac) / packet
                else:
                    packet[Ether].src = src_mac
                    packet[Ether].dst = mcast_dst_mac
                self.router_logger.log_message(
                    RouterRandomMessages(
                        name="Router",
                        message=f"L2 multicast → {mcast_dst_mac} on {egress_iface}",
                        emoticons=["📢️", "🗂️", "🗳️", "🗃️", "➰", "📚", "🗄️"]
                    )
                )
                self.ethernet_manager.handle_frame(packet, inbound_iface)
                return

            # ---- L3 path (WinDivert/rawip/winfw/unknown-MAC): inject IP packet ----
            # Strip Ether if present (could be from capture side)
            if packet.haslayer(Ether):
                packet = packet.payload  # drop L2

            # Ensure TTL/Hop-Limit is sane for multicast forwarding
            try:
                if is_v4 and IP in packet:
                    packet[IP].ttl = max(1, int(getattr(packet[IP], "ttl", 1) or 1))
                elif not is_v4 and IPv6 in packet:
                    packet[IPv6].hlim = max(1, int(getattr(packet[IPv6], "hlim", 1) or 1))
            except Exception:
                pass

            try:
                egress_iface = self.outbound_load_balancer.get_best_interface()
                # Scapy will send the L3 packet out the given iface. For WinDivert, this
                # remains L3-only (no MAC), which is exactly what we want here.
                self.sniffer.send(packet, iface=egress_iface, verbose=0)

                self.router_logger.log_message(
                    RouterRandomMessages(
                        name="Router",
                        message=f"L3 multicast inject to {dst_ip} on {egress_iface}.",
                        emoticons=["🪂️", "🚆", "🚃", "🕍", "⛩️", "🕋", "🏗"]
                    )
                )
            except Exception as e:
                self.router_logger.log_message(
                    f"[Router] ❌ L3 multicast inject failed on {egress_iface} using inbound {inbound_iface}: {e}"
                )
            return

        # Unicast only: perform RIP/static/default-route lookup after multicast has
        # been completely handled.  This prevents SSDP/mDNS multicast from entering
        # longest-prefix matching and protects the forwarding path from malformed
        # route-table keys.
        route = self.rip_manager.get_forwarding_route(str(dst_ip_obj))

        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
        sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(
            UDP) else 0
        dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(
            UDP) else 0

        if not route:
            self.router_logger.log_message(f"[Router] 🗺️ No specific route for {dst_ip}, checking for default route...")

            default_route = self.rip_manager.get_forwarding_route("0.0.0.0")

            if default_route:
                route = default_route
            else:
                self.function_call_tracker.track(
                    identifier='DroppedRoute',
                    threshold=20,
                    final_message=f"[Router] 🛑 No route to {dst_ip}. Dropping. Count: {{}}.",
                    count_message=None)
                self.code_output_manager.submit_packet(
                    packet,
                    inbound_iface=inbound_iface,
                    phase="drop",
                    component="drop-route",
                )
                return
        initial_outbound_iface = route["interface"]
        next_hop_ip = dst_ip if route["next_hop"] in ("0.0.0.0", "::") else route["next_hop"]

        wan_ifaces = set(self.outbound_load_balancer.get_configured_interfaces())

        selected_iface = None
        if initial_outbound_iface in self.lag_manager.get_lag_members()["MyLANAggregation"]:
            selected_iface = self.lag_manager.get_member_interface("MyLANAggregation", packet)
            self.code_output_manager.submit_packet(
                packet,
                inbound_iface=inbound_iface,
                phase="interface",
                component="lag",
            )
        else:
            selected_iface = initial_outbound_iface

        if not selected_iface:
            self.router_logger.log_message("[Router] ❌ No outbound interface. Dropping packet.")
            return

        is_wan_egress = selected_iface in wan_ifaces
        if not is_wan_egress:
            # Not a WAN egress packet — do NOT handle it here.
            # Let it continue into your LAN/intra routing logic below this section.
            pass
        else:
            is_ipv6 = (ip_layer.version == 6)

            # L2 capability belongs to the actual selected egress adapter,
            # not to the capture adapter.
            egress_l2_ok = self._iface_supports_l2(selected_iface)

            if egress_l2_ok:
                if is_ipv6:
                    # Resolve on the *actual* egress iface (selected_iface) so LAG doesn't break neighbor discovery
                    next_hop_mac = self.ndp_manager.resolve(next_hop_ip, selected_iface)
                else:
                    next_hop_mac = self.arp_manager.resolve(next_hop_ip, iface=selected_iface)

                if not next_hop_mac:
                    self.router_logger.log_message(
                        f"[Router] 🕵️ No MAC for next hop {next_hop_ip} on {selected_iface.split('_')[-1]}. Dropping packet."
                    )
                    return

                # Rewrite MACs
                if packet.haslayer(Ether):
                    packet[Ether].src = self.get_interface_mac(selected_iface)
                    packet[Ether].dst = next_hop_mac
                else:
                    self.router_logger.log_message(
                        RouterRandomMessages(
                            name="Router",
                            message=f"Hardening WAN-bound packet for {dst_ip}: Reconstructing missing Ether layer.",
                            emoticons=["🛠️️", "🏭", "⚙️", "🛡️", "🔩"]
                        )
                    )
                    src_mac = self.get_interface_mac(selected_iface)
                    packet = Ether(src=src_mac, dst=next_hop_mac) / packet

            else:
                # L3-only egress path (WinDivert/rawip/etc)
                if packet.haslayer(Ether):
                    packet = packet.payload  # strip L2 if present
                    self.router_logger.log_message(
                        RouterRandomMessages(
                            name="Router",
                            message=f"Hardening WAN-bound packet for {dst_ip}: stripping Ether for L3-only egress on {selected_iface}.",
                            emoticons=["🛰️", "📡", "🛸", "⚓", "🛟"]
                        )
                    )

            # ---- NAT (IPv4): base it on WAN egress + private source, NOT Ether.src heuristics ----
            if not is_ipv6:
                if packet.haslayer(UDP) and packet[UDP].dport == self.nat_manager.KEEP_ALIVE_PORT:
                    self.nat_manager.handle_keep_alive(packet)
                    return

                try:
                    if IP in packet and ipaddress.ip_address(packet[IP].src).is_private:
                        self.nat_manager.translate_outbound(packet)
                except Exception:
                    # If IP parsing fails, don't NAT blindly
                    pass

            # ---- Fix checksums/lengths ----
            if is_ipv6:
                if IPv6 in packet and hasattr(packet[IPv6], "plen"):
                    del packet[IPv6].plen
            else:
                if IP in packet and hasattr(packet[IP], "chksum"):
                    del packet[IP].chksum

            # Log and send
            self.router_logger.log_message(
                RouterRandomMessages(
                    name="Router",
                    message=f"WAN-bound packet {self._proto_summary(packet)} to {selected_iface.split('_')[-1]}.",
                    emoticons=["👽", "🌍", "🌎", "🌏", "🌠", "🌌", "🪐", "🌗", "🌑", "🌈", "🎇", "🔮"]
                )
            )
            self.code_output_manager.submit_packet(
                packet,
                inbound_iface=inbound_iface,
                phase="handled",
                component="internet",
            )
            self.sniffer.send(packet, selected_iface, verbose=0)
            if self.netroute_manager:
                self.netroute_manager.mark_route_success(selected_iface, next_hop_ip)
            return
        # ===================== END PATCH =====================

        is_from_internal_bridge = self.ethernet_manager.is_bridge_member(inbound_iface)
        is_to_external_wan = initial_outbound_iface in self.outbound_load_balancer.get_configured_interfaces()
        if is_from_internal_bridge and is_to_external_wan:
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if not ip_layer.version == 6:
                self.nat_manager.translate_outbound(packet)

        if initial_outbound_iface in self.outbound_load_balancer.get_configured_interfaces():
            selected_iface = self.outbound_load_balancer.get_next_interface(packet)
        else:
            selected_iface = route["interface"]
        # --- [4] Intra-LAN Loop Prevention ---
        inbound_config = self._interfaces_config.get(inbound_iface)
        inbound_network = self._get_interface_network(
            inbound_iface,
            inbound_config if isinstance(inbound_config, dict) else None,
            version=dst_ip_obj.version,
        )
        is_intra_lan = bool(
                inbound_network is not None
                and dst_ip_obj in inbound_network
                and str(dst_ip_obj) != str((inbound_config or {}).get("ip_addr") or "")
        )
        loop_candidate = inbound_iface in {initial_outbound_iface, selected_iface}
        if loop_candidate:
            if not is_intra_lan:
                alternate_route = self.rip_manager.find_alternate_route(dst_ip, exclude_iface=inbound_iface)
                if alternate_route:  # ✅ Ensure alternate_route is valid first
                    actual_outbound_iface = alternate_route["interface"]
                    if actual_outbound_iface in self.lag_manager.get_lag_members()["MyLANAggregation"]:
                        actual_outbound_iface = self.lag_manager.get_member_interface("MyLANAggregation", packet)
                    if alternate_route:
                        self.router_logger.log_message(
                            f"[Router] 🛣️ Routing loop on {inbound_iface} for {dst_ip} — rerouting via {actual_outbound_iface.split('_')[-1]}"
                        )
                        self.forwarding_manager.record_flow(src_ip, dst_ip, sport, dport, proto)

                        initial_outbound_iface = actual_outbound_iface
                else:
                    default_route = self.rip_manager.find_route("0.0.0.0")
                    if default_route:
                        actual_outbound_iface = default_route["interface"]
                        self.router_logger.log_message(
                            RouterRandomMessages(
                                name="Router",
                                message=f"No alternate route to {dst_ip}. Using default route via {actual_outbound_iface.split('_')[-1]}",
                                emoticons=["🚵", "👣", "🥾"]
                            )
                        )
                        self.code_output_manager.submit_packet(
                            packet,
                            inbound_iface=inbound_iface,
                            phase="handled",
                            component="no-alternate-route",
                        )
                        self.forwarding_manager.record_flow(src_ip, dst_ip, sport, dport, proto)
                        initial_outbound_iface = actual_outbound_iface
                    else:
                        self.router_logger.log_message(
                            f"[Router] ❌ Routing loop on {inbound_iface} and no alternate or default route for {dst_ip}. Dropping.")
                        return
            else:
                self.router_logger.log_message(
                    RouterRandomMessages(
                        name="Router",
                        message=f"Intra-LAN forwarding: {packet.summary()} | In:{iface_short} -> Out:{iface_short}",
                        emoticons=["🏠", "🏡", "🏘️"]
                    )
                )
                self.code_output_manager.submit_packet(
                    packet,
                    inbound_iface=inbound_iface,
                    phase="handled",
                    component="intra-lan",
                )

        # --- [7] Prepare L2 Details ---
        outbound_config = self._interfaces_config.get(initial_outbound_iface)
        if not outbound_config:
            self.router_logger.log_message(
                f"[Router] ⚠️ Interface {initial_outbound_iface.split('_')[-1]} not in config. Dropping."
            )
            return

        is_loopback = (
                dst_ip_obj.is_loopback
                or self._is_loopback_iface_name(initial_outbound_iface)
        )
        outbound_network = self._get_interface_network(
            initial_outbound_iface,
            outbound_config,
            version=dst_ip_obj.version,
        )
        outbound_mac = (
            str(outbound_config.get("mac") or "").strip()
            or self.get_interface_mac(initial_outbound_iface)
        )
        target_mac = None

        # Link-local addresses are never routed between interfaces. A packet
        # captured on loopback is a duplicate; a packet seen on a real adapter
        # may only stay on that same link.
        if (
                (src_ip_obj.is_link_local or dst_ip_obj.is_link_local)
                and initial_outbound_iface != inbound_iface
        ):
            self._track_local_broadcast_drop(
                "DroppedCrossInterfaceLinkLocal",
                (
                    f"[Router] 🧭 Suppressed cross-interface link-local forwarding "
                    f"{src_ip_obj} → {dst_ip_obj}: {inbound_iface} -> {initial_outbound_iface}."
                ),
            )
            return

        # --- [8] MAC Resolution ---
        if is_loopback:
            target_mac = "00:00:00:00:00:00"
            if packet.haslayer(Ether):
                # This is a standard packet, just update the MAC addresses
                packet[Ether].src = outbound_mac or "00:00:00:00:00:00"
                packet[Ether].dst = target_mac
            else:
                # HARDENING: The packet is missing an Ether layer. We will build one.
                self.router_logger.log_message(
                    RouterRandomMessages(
                        name="Router",
                        message=f"Hardening packet for {dst_ip}: Reconstructing missing Ether layer for egress on {initial_outbound_iface.split('_')[-1]}.",
                        emoticons=["🛠️️", "🏭", "⚙️", "🛡️", "🔩"]
                    )
                )
                # The original 'packet' is the IP payload. We wrap it in a new Ether frame.
                packet = Ether(
                    src=outbound_mac or "00:00:00:00:00:00",
                    dst=target_mac,
                ) / packet

            self.router_logger.log_message(
                f"[Router] 🌀 Loopback forwarding for {dst_ip}. No ARP needed."
            )
            self.packet_writer._send_raw_packet(packet, interface=inbound_iface)
            return
        elif self._is_ipv4_broadcast(
                dst_ip_obj,
                network=outbound_network,
                config=outbound_config,
        ):
            target_mac = "ff:ff:ff:ff:ff:ff"
            self.router_logger.log_message(
                RouterRandomMessages(
                    name="Router",
                    message=f"Broadcast forwarding to {target_mac}",
                    emoticons=["️📺", "📼", "📽️", "🖨️", "🎥"]
                )
            )
        else:
            is_ipv6 = (ip_layer.version == 6)
            if is_ipv6:
                self.router_logger.log_message(
                    RouterRandomMessages(
                        name="Router",
                        message=f"Performing NDP lookup for {next_hop_ip}...",
                        emoticons=["️🕵️", "👨‍🏭", "👨‍✈️", "👨‍🎓", "👨‍🍳", "👨‍💻", "👩‍⚕️", "👩‍🏫", "🧑‍🔬", "👷‍♀️"]
                    )
                )
                target_mac = self.ndp_manager.resolve(next_hop_ip, initial_outbound_iface)
            else:
                self.router_logger.log_message(
                    RouterRandomMessages(
                        name="Router",
                        message=f"Performing ARP lookup for {next_hop_ip}...",
                        emoticons=["️🕵️", "👨‍🏭", "👨‍✈️", "👨‍🎓", "👨‍🍳", "👨‍💻", "👩‍⚕️", "👩‍🏫", "🧑‍🔬", "👷‍♀️", "💂"]
                    )
                )
                target_mac = self.arp_manager.resolve(next_hop_ip, initial_outbound_iface)

        if not target_mac:
            self.router_logger.log_message(
                f"[Router] 🕵️ No target mac for {next_hop_ip} on {initial_outbound_iface.split('_')[-1]}. Dropping."
            )
            return

        # --- [9] TTL Decrement ---
        # --- [0] Loopback Check (Crucial for your error) ---
        is_loopback_dest = ipaddress.ip_address(dst_ip).is_loopback

        # Only decrement TTL/HLIM if it's NOT a loopback destination
        # and if the packet is actually meant to be forwarded.
        if not is_loopback_dest:
            ttl_or_hlim = getattr(ip_layer, "ttl", None)
            if ttl_or_hlim is None:
                ttl_or_hlim = getattr(ip_layer, "hlim", None)

            if ttl_or_hlim is None:
                self.router_logger.log_message(f"[Router] ❗ Cannot find TTL/Hop Limit field for {dst_ip}. Dropping.")
                return

            if ttl_or_hlim <= 1:
                self.router_logger.log_message(
                    RouterRandomMessages(
                        name="Router",
                        message=f"TTL/Hop Limit expired for {dst_ip}. Dropping.",
                        emoticons=["️⌛", "⏱️", "⌚", "🕰️", "⏰", "⏲️"]
                    )
                )
                self.packet_writer.send_icmp_time_exceeded(original_packet=packet, inbound_iface=inbound_iface)
                return
            if hasattr(ip_layer, "ttl"):
                packet[IP].ttl -= 1
            elif hasattr(ip_layer, "hlim"):
                packet[IPv6].hlim -= 1
        # --- [10] Adjust or Apply Ether Layer ---
        if is_loopback:
            if packet.haslayer(Ether):
                packet = packet.payload  # Strip Ethernet layer for loopback processing
        elif packet.haslayer(Ether):
            # Standard case: The packet has a frame, so we just update the MACs.
            packet[Ether].src = outbound_mac or self.get_interface_mac(initial_outbound_iface)
            packet[Ether].dst = target_mac
        else:
            # HARDENING: Packet is missing the Ether layer. We will build one
            # .
            self.router_logger.log_message(
                RouterRandomMessages(
                    name="Router",
                    message=f"Hardening packet: Reconstructing missing Ether layer for egress on {initial_outbound_iface.split('_')[-1]}.",
                    emoticons=["🛠️️", "🏭", "⚙️", "🛡️", "🔩"]
                )
            )
            # The original 'packet' is the IP payload. We wrap it in a new Ether frame.
            packet = Ether(
                src=outbound_mac or self.get_interface_mac(initial_outbound_iface),
                dst=target_mac,
            ) / packet

        # --- [11] Fix Checksums ---
        # --- 7. Fix Checksums (IP-Version Aware) ---
        if not packet.haslayer(IPv6):
            del packet[IP].chksum

        if TCP in packet and hasattr(packet[TCP], "chksum"): del packet[TCP].chksum
        if UDP in packet and hasattr(packet[UDP], "chksum"): del packet[UDP].chksum

        self.sniffer.send(packet, iface=initial_outbound_iface)
        proto_str = self._proto_summary(packet)
        self.router_logger.log_message(
            RouterRandomMessages(
                name="Router",
                message=f"Packet sent to {initial_outbound_iface.split('_')[-1]} {proto_str}",
                emoticons=["🏢", "🚕", "🗽", "🏞️", "🎢", "🎡", "🦖", "📰", "🖼️", "⛲"]
            )
        )
        if self._manager_settings.get(
                "enable_packet_catcher",
                True,
        ):
            deterministic_value = abs(hash(str(packet))) / (2 ** 64 - 1)
            sampling_rate = self.packet_catcher_heuristic_rates.get(
                proto,
                self.packet_catcher_heuristic_rates['DEFAULT'],
            )
            if deterministic_value < sampling_rate:
                self.packet_catcher.process_packet(packet)
                self.code_output_manager.submit_packet(
                    packet,
                    inbound_iface=inbound_iface,
                    phase="handled",
                    component="packet-catch",
                )
        self.code_output_manager.submit_packet(
            packet,
            inbound_iface=inbound_iface,
            phase="queue",
            component="packet-writer",
        )

    def start_routing(self, use_dhcp_out, use_dhcp_in, router_ip_out, netmask_out, use_static, use_hyperv,
                      use_stratum_comm, p2pool_server_ip, ipc_emit_host, use_peer_to_peer, use_blocknet, blocknet_relay,
                      blocknet_token, use_netroute, use_hostbypass, use_gateway, use_lan, use_uplink, nat_os,
                      python_server, promisc, use_socket, use_ollama, use_scrapewebsite=False,
                      scrapewebsite_endpoint=None,
                      use_wifi_host=False,
                      wifi_ssid="PythonRouter",
                      wifi_password=None,
                      wifi_executable_path=None,
                      router_ip_in=None,
                      netmask_in="255.255.255.0",
                      enable_dhcp_server=True,
                      serve_dhcp_on_wan=False,
                      dhcp_server_settings=None,
                      wan_dhcp_server_settings=None,
                      dhcp_interface_profiles=None,
                      gateway_settings=None,
                      lan_settings=None,
                      uplink_settings=None,
                      python_server_settings=None,
                      wifi_settings=None,
                      stratum_connection_mode="auto",
                      stratum_pool_port=3333,
                      stratum_wallet="46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk",
                      stratum_password="x",
                      stratum_worker="PythonProxy",
                      stratum_proxy_host="127.0.0.1",
                      stratum_proxy_port=3334,
                      stratum_enable_proxy=True,
                      stratum_use_tls="auto",
                      stratum_tls_hostname=None,
                      stratum_user_agent="pystratum/0.5",
                      stratum_daemon_url="http://127.0.0.1:18081",
                      stratum_zmq_address="tcp://127.0.0.1:18083",
                      manager_settings=None,
                      transport_settings=None,
                      code_output_settings=None,
                      dhcp_out_mode="direct",
                      dhcp_in_mode="direct",
                      use_peerinterface=False,
                      peerinterface_settings=None,):
        """Configures interfaces and starts all manager threads."""
        try:
            if self.started:
                self.router_logger.log_message("[Router] Start requested while already running; ignoring.")
                return
            self._runtime_network_ready.clear()
            self._stop_sniffing_event.clear()
            self._stop_ingress_workers(discard=True)
            self.hyperv_enabled = use_hyperv
            self.peerinterface_enabled = bool(use_peerinterface)
            self._peerinterface_settings = dict(peerinterface_settings or {})
            self._peerinterface_nat_ports = set()
            self._dhcp_out_mode = str(dhcp_out_mode or "direct").strip().casefold()
            self._dhcp_in_mode = str(dhcp_in_mode or "direct").strip().casefold()
            valid_dhcp_modes = {"direct", "managed"}
            if self._dhcp_out_mode not in valid_dhcp_modes:
                raise ValueError("dhcp_out_mode must be direct or managed")
            if self._dhcp_in_mode not in valid_dhcp_modes:
                raise ValueError("dhcp_in_mode must be direct or managed")
            self._enable_dhcp_server = bool(enable_dhcp_server)
            self._serve_dhcp_on_wan = bool(serve_dhcp_on_wan)
            self._dhcp_server_settings = dict(
                dhcp_server_settings or {}
            )
            self._wan_dhcp_server_settings = dict(
                wan_dhcp_server_settings or {}
            )
            self._dhcp_interface_profiles = self._normalized_dhcp_interface_profiles(
                dhcp_interface_profiles or []
            )
            gateway_settings = dict(gateway_settings or {})
            lan_settings = dict(lan_settings or {})
            uplink_settings = dict(uplink_settings or {})
            python_server_settings = dict(
                python_server_settings or {}
            )
            wifi_settings = dict(wifi_settings or {})
            requested_manager_settings = dict(
                manager_settings or {}
            )
            requested_code_output_settings = dict(code_output_settings or {})
            interface_setting_names = {
                "interface_enabled", "interface_switch_name", "interface_adapter_name",
                "interface_ipv4", "interface_prefix_length", "interface_remove_on_shutdown",
                "switch_name", "adapter_name", "ipv4", "prefix_length", "remove_on_shutdown",
            }
            interface_settings = {
                key: requested_code_output_settings.pop(key)
                for key in list(requested_code_output_settings)
                if key in interface_setting_names
            }
            self.codeoutput_interface_manager.configure(**interface_settings)
            self.code_output_manager.configure(**requested_code_output_settings)
            allowed_manager_settings = set(
                self._manager_settings
            )
            unknown_manager_settings = (
                set(requested_manager_settings)
                - allowed_manager_settings
            )
            if unknown_manager_settings:
                raise ValueError(
                    "Unknown core manager setting(s): "
                    + ", ".join(sorted(unknown_manager_settings))
                )
            self._manager_settings.update(
                requested_manager_settings
            )
            self._ingress_max_frames = max(1024, min(
                262144, int(self._manager_settings.get("ingress_max_frames", 32768))
            ))
            self._ingress_max_bytes = max(16 * 1024 * 1024, min(
                1024 * 1024 * 1024,
                int(self._manager_settings.get("ingress_max_bytes", 192 * 1024 * 1024)),
            ))
            self._ingress_priority_reserve_frames = max(0, min(
                self._ingress_max_frames,
                int(self._manager_settings.get("ingress_priority_reserve_frames", 4096)),
            ))
            self._ingress_priority_reserve_bytes = max(0, min(
                self._ingress_max_bytes,
                int(self._manager_settings.get(
                    "ingress_priority_reserve_bytes", 64 * 1024 * 1024
                )),
            ))
            self._ingress_batch_size = max(1, min(
                512, int(self._manager_settings.get("ingress_batch_size", 64))
            ))
            self._ingress_summary_interval_sec = max(5.0, min(
                300.0, float(self._manager_settings.get("ingress_summary_interval_sec", 30.0))
            ))
            self.esp_manager.log_success_packets = bool(
                self._manager_settings.get("tunnel_log_success_packets", False)
            )

            bool_manager_settings = {
                "enable_firewall",
                "enable_packet_analyzer",
                "enable_packet_catcher",
                "enable_handshake",
                "enable_syn_scanner",
                "enable_igmp",
                "enable_mdns",
                "require_ethernet_on_physical_capture",
                "tunnel_log_success_packets",
                "handshake_log_tcp_lifecycle",
                "handshake_log_non_tls_tcp",
                "handshake_log_tls_records",
                "handshake_log_application_data",
                "handshake_log_tls13_key_events",
            }
            for setting_name in bool_manager_settings:
                self._manager_settings[setting_name] = bool(
                    self._manager_settings[setting_name]
                )

            for setting_name in (
                    "handshake_timeout_half_open",
                    "handshake_timeout_established",
                    "handshake_rate_limit_threshold",
                    "handshake_rate_limit_period",
                    "handshake_ban_duration",
                    "syn_scan_interval",
            ):
                parsed_value = int(
                    self._manager_settings[setting_name]
                )
                if parsed_value < 1:
                    raise ValueError(
                        f"{setting_name} must be at least 1."
                    )
                self._manager_settings[setting_name] = parsed_value

            for setting_name, protocol_name in (
                    ("packet_catcher_tcp_rate", "TCP"),
                    ("packet_catcher_udp_rate", "UDP"),
                    ("packet_catcher_default_rate", "DEFAULT"),
            ):
                parsed_rate = float(
                    self._manager_settings[setting_name]
                )
                if not 0.0 <= parsed_rate <= 1.0:
                    raise ValueError(
                        f"{setting_name} must be between 0 and 1."
                    )
                self._manager_settings[setting_name] = parsed_rate
                self.packet_catcher_heuristic_rates[
                    protocol_name
                ] = parsed_rate

            requested_transport_settings = dict(
                transport_settings or {}
            )
            allowed_transport_settings = {
                "enabled",
                "protocol_enabled",
                "stratum_ports",
                "monero_ports",
                "voip_port_start",
                "voip_port_end",
                "parallel_analysis",
                "inspection_log_rps",
                "inspection_log_burst",
                "inspection_flow_cooldown_sec",
                "stratum_log_rps",
                "stratum_log_burst",
                "stratum_flow_cooldown_sec",
                "monero_log_rps",
                "monero_log_burst",
                "monero_flow_cooldown_sec",
                "dns_pending_ttl_sec",
                "dns_gc_interval_sec",
                "dns_alert_on_rebind",
                "dhcp_transaction_ttl_sec",
                "dhcp_lease_ttl_sec",
                "https_logging",
                "https_parse_certificates",
                "https_parse_quic_crypto",
                "tls_learning_enabled",
                "https_init_context",
                "classification_mode",
                "stratum_port_policy",
                "stratum_tls_requires_endpoint_evidence",
                "analysis_payload_only",
                "analysis_sample_rate",
                "analysis_flow_cooldown_sec",
            }
            unknown_transport_settings = (
                set(requested_transport_settings)
                - allowed_transport_settings
            )
            if unknown_transport_settings:
                raise ValueError(
                    "Unknown transport manager setting(s): "
                    + ", ".join(
                        sorted(unknown_transport_settings)
                    )
                )
            self._transport_settings = (
                requested_transport_settings
            )
            self.transport_manager.configure(
                **self._transport_settings
            )
            self.transport_manager.start()

            stratum_mode = str(
                stratum_connection_mode or "auto"
            ).strip().casefold()
            if stratum_mode == "auto":
                stratum_mode = (
                    "daemon"
                    if not str(p2pool_server_ip or "").strip()
                    else "pool"
                )
            if stratum_mode not in {"pool", "daemon"}:
                raise ValueError(
                    "stratum_connection_mode must be pool, daemon, or auto."
                )

            self.started = True
            if use_wifi_host:
                try:
                    resolved_wifi_password = (
                            wifi_password
                            or os.environ.get(
                        "PYTHONROUTER_WIFI_PASSWORD",
                        "",
                    )
                    )

                    if not resolved_wifi_password:
                        raise ValueError(
                            "No wireless password was provided. Pass "
                            "wifi_password=... or define "
                            "PYTHONROUTER_WIFI_PASSWORD."
                        )

                    wifi_config = {
                        "ssid": wifi_ssid,
                        "password": resolved_wifi_password,
                        "executable_path": wifi_executable_path,
                        "start_timeout": 35.0,
                        "adapter_timeout": 45.0,
                        "enable_windows_forwarding": True,
                    }
                    allowed_wifi_settings = {
                        "state_file",
                        "start_timeout",
                        "adapter_timeout",
                        "adapter_poll_interval",
                        "enable_windows_forwarding",
                        "auto_restart",
                        "restart_backoff",
                        "max_restart_backoff",
                        "status_poll_interval",
                        "hotspot_router_ip",
                        "hotspot_prefix_length",
                        "enforce_fixed_hotspot_address",
                        "require_address_before_ready",
                        "address_verify_interval",
                        "address_policy_timeout",
                        "restore_dynamic_address_on_stop",
                    }
                    wifi_config.update({
                        key: value
                        for key, value in wifi_settings.items()
                        if key in allowed_wifi_settings
                    })
                    self.wifi_manager.configure(**wifi_config)
                    self.wifi_manager.start()
                except Exception as exc:
                    self.router_logger.log_message(
                        f"[WiFiManager] ❌ Wireless host startup failed: {exc}"
                    )
            try:
                self._initialize_interface_discovery()
                if not self._auto_configure_interfaces(
                        use_dhcp_out,
                        use_dhcp_in,
                        router_ip_in=router_ip_in,
                        router_netmask_in=netmask_in,
                        router_ip_out=router_ip_out,
                        router_netmask_out=netmask_out,
                ):
                    self.router_logger.log_message("[Router] ❌ Failed to auto-configure interfaces.")
            except Exception as e:
                self.router_logger.log_message(f"[Router] ❌ Crash in start_routing: {e}")
            if use_static:
                self._configure_interface_settings(
                    use_dhcp_out,
                    use_dhcp_in,
                    use_hyperv,
                    router_ip_in=router_ip_in,
                    router_netmask_in=netmask_in,
                    router_ip_out=router_ip_out,
                    router_netmask_out=netmask_out,
                )

            # Normalize every interface record before any forwarding, DNS,
            # DHCP, NAT, or packet-writer manager consumes the shared map.
            self._normalize_all_interface_networks()
            managed_dhcp_requested = (
                (bool(use_dhcp_out) and self._dhcp_out_mode == "managed")
                or (bool(use_dhcp_in) and self._dhcp_in_mode == "managed")
            )
            if use_uplink or managed_dhcp_requested:
                self._configure_host_preserving_upstream_mode()
            elif use_dhcp_out or use_dhcp_in:
                self.router_logger.log_message(
                    "[DHCP][DirectLease] ✅ Direct lease mode active; Windows/TransportDHCP accepts the lease without host-preserving or uplink orchestration."
                )
            if use_hostbypass:
                self.host_connectivity_boundary = HostConnectivityBoundaryManager(
                    self.router_logger,
                    get_local_ips_fn=self._get_all_local_ips,
                    get_router_macs_fn=lambda: self.router_macs or set(),
                    get_bridge_members_fn=lambda: self.ethernet_manager.get_bridge_members(),
                    get_wan_iface_fn=lambda: self.interface_out_full_name,
                    get_wan_ip_fn=lambda: self.router_ip_out,
                    get_gateway_ip_fn=lambda: self.router_gateway_out_ip,
                    health_probe_fn=self._probe_host_internet_health,
                    fail_open_after_failures=3,
                    recover_after_successes=3,
                    transit_ifaces_fn=self._boundary_transit_ifaces,  # <-- add this
                )
                self.host_connectivity_boundary.start()

            if use_socket:
                self.socket_interface = SocketInterface(self, self.router_logger)
                self.router_logger.log_message(
                    "[SocketInterface] ⏳ startup deferred until interfaces and routes are ready."
                )
            self.dns_manager = DNSManager(
                self.router_logger,
                self.packet_writer,
                self.router_ipv6_link_local_out,
            )

            self.dns_manager.router_ip_out = self.router_ip_out
            self.dns_manager.router_ipv4_out = self.router_ip_out
            self.dns_manager.router_ipv6_out = self.router_ipv6_out
            self.dns_manager.router_ipv6_link_local_out = (
                self.router_ipv6_link_local_out
            )
            if use_gateway:
                self.gateway_manager = GatewayManager(self, DNSManager)

                gateway_config = {
                    "packet_writer": self.packet_writer,
                    "nat_manager": self.nat_manager,
                    "dns_manager": getattr(
                        self,
                        "dns_manager",
                        None,
                    ),
                    "arp_manager": self.arp_manager,
                    "ndp_manager": self.ndp_manager,
                    "icmp_manager": self.icmp_manager,
                    "netroute_manager": self.netroute_manager,
                    "rip_manager": getattr(
                        self,
                        "rip_manager",
                        None,
                    ),
                    "ethernet_manager": getattr(
                        self,
                        "ethernet_manager",
                        None,
                    ),
                    "dhcp_manager": getattr(
                        self,
                        "dhcp_manager",
                        None,
                    ),
                    "sendback_manager": getattr(
                        self,
                        "sendback_manager",
                        None,
                    ),
                    "manager_inputs": {},
                    "attach_managers_to_router": True,
                    "manage_dns_lifecycle": True,
                    "stop_injected_managers_on_stop": False,
                    "sync_managers_on_gateway_change": True,
                    "dispatch_gateway_packets_to_managers": True,
                    "auto_configure_router_interfaces": False,
                    "use_dhcp_out": bool(use_dhcp_out and self._dhcp_out_mode == "managed"),
                    "use_dhcp_in": bool(use_dhcp_in and self._dhcp_in_mode == "managed"),
                    "router_ip_out": self.router_ip_out,
                    "router_netmask_out": self.router_netmask_out,
                    "force_wan_to_dhcp_on_start": False,
                    "ensure_host_dns_from_wan": False,
                    "repair_on_failure": True,
                    "pin_gateway_arp": True,
                    "runtime_set_wan_to_dhcp": bool(use_dhcp_out and self._dhcp_out_mode == "managed"),
                    "disable_netroute_default_sync": True,
                    "disable_netroute_metric_tuning": True,
                }
                allowed_gateway_settings = {
                    "repair_on_failure",
                    "pin_gateway_arp",
                    "enable_dns64",
                    "dns64_prefix",
                    "upstream_dns",
                    "enable_packet_observer",
                    "enable_arp_probes",
                    "enable_icmp_probes",
                    "enable_first_hop_probe",
                    "enable_gateway_dns_probe",
                    "enable_ipv6_router_solicitation",
                    "consume_own_probe_replies",
                    "health_interval_sec",
                    "wan_snapshot_interval_sec",
                    "route_refresh_interval_sec",
                    "dns_refresh_interval_sec",
                    "probe_cycle_interval_sec",
                    "arp_probe_interval_sec",
                    "icmp_probe_interval_sec",
                    "first_hop_probe_interval_sec",
                    "gateway_dns_probe_interval_sec",
                    "ipv6_rs_interval_sec",
                    "probe_budget_window_sec",
                    "probe_budget_max_packets",
                    "max_candidates_per_cycle",
                    "max_pending_probes",
                    "soft_repair_cooldown_sec",
                    "hard_repair_cooldown_sec",
                    "failure_threshold_for_soft_repair",
                    "failure_threshold_for_hard_repair",
                    "minimum_degraded_time_for_hard_repair_sec",
                }
                gateway_config.update({
                    key: value
                    for key, value in gateway_settings.items()
                    if key in allowed_gateway_settings
                })
                self.gateway_manager.configure(**gateway_config)

                self.gateway_manager.start()
            if python_server:
                python_server_config = {
                    "router": self,
                    "router_logger": self.router_logger,
                    "host": "0.0.0.0",
                    "port": 8844,
                    "dashboard_title": "Router Dashboard",
                    "store_raw_packets": True,
                    "max_raw_packet_bytes": 0,
                }
                allowed_python_server_settings = {
                    "host",
                    "port",
                    "dashboard_title",
                    "max_packets",
                    "max_logs",
                    "max_events",
                    "packet_window_sec",
                    "store_raw_packets",
                    "max_raw_packet_bytes",
                    "raw_hex_preview_bytes",
                    "max_logs_per_prefix",
                    "max_prefix_buckets",
                }
                python_server_config.update({
                    key: value
                    for key, value in python_server_settings.items()
                    if key in allowed_python_server_settings
                })
                self.python_server_manager = PythonServerManager(
                    **python_server_config
                )
                self.router_logger.log_message = self.python_server_manager.wrap_log_call(
                    self.router_logger.log_message,
                    source="Router",
                    level="info",
                )
                self.python_server_manager.start()
                self.arp_manager.add_trusted_port("Miner")
            if use_lan:
                self.lan_manager = LanManager(
                    self,
                    DHCPServer,
                    gateway_manager=self.gateway_manager,
                )

                lan_config = {
                    "bridge_name": "ManagedLANBridge",
                    "create_bridge": True,
                    "enable_dhcp_server": self._enable_dhcp_server,
                    "serve_on_all_lan_ifaces": False,
                    "authoritative": True,
                    "rogue_policy": "log",
                    "enforce_same_subnet": True,
                    "allow_out_of_pool": False,
                    "start_transport_dhcp_client": False,
                    "handle_icmp": True,
                }
                allowed_lan_settings = {
                    "bridge_name",
                    "create_bridge",
                    "member_ifaces",
                    "serve_on_all_lan_ifaces",
                    "health_interval_sec",
                    "start_transport_dhcp_client",
                    "handle_icmp",
                    "learn_ipv6_link_local",
                    "learn_ipv6_ula",
                }
                lan_config.update({
                    key: value
                    for key, value in lan_settings.items()
                    if key in allowed_lan_settings
                })

                # Global DHCP settings own the server configuration even when
                # LanManager is the component that constructs the instance.
                lan_config.update({
                    "enable_dhcp_server": self._enable_dhcp_server,
                    "authoritative": self._dhcp_server_settings.get(
                        "authoritative",
                        True,
                    ),
                    "rogue_policy": self._dhcp_server_settings.get(
                        "rogue_policy",
                        "log",
                    ),
                    "enforce_same_subnet": (
                        self._dhcp_server_settings.get(
                            "enforce_same_subnet",
                            True,
                        )
                    ),
                    "allow_out_of_pool": (
                        self._dhcp_server_settings.get(
                            "allow_out_of_pool",
                            False,
                        )
                    ),
                    "dns_v6": self._dhcp_server_settings.get(
                        "dns_v6",
                        ["fd00::1", "fd00::2"],
                    ),
                    "search_domains": (
                        self._dhcp_server_settings.get(
                            "search_domains",
                            ["lan.internal"],
                        )
                    ),
                    "dhcp_pool_start": (
                        self._dhcp_server_settings.get("pool_start")
                    ),
                    "dhcp_pool_end": (
                        self._dhcp_server_settings.get("pool_end")
                    ),
                    "dhcp_relay_target_ip": (
                        self._dhcp_server_settings.get(
                            "dhcp_relay_target_ip"
                        )
                    ),
                    "dhcp6_prefix": self._dhcp_server_settings.get(
                        "dhcp6_prefix"
                    ),
                    "dhcp6_relay_target_ip": (
                        self._dhcp_server_settings.get(
                            "dhcp6_relay_target_ip"
                        )
                    ),
                    "lease_duration_seconds": (
                        self._dhcp_server_settings.get(
                            "lease_duration_seconds",
                            600,
                        )
                    ),
                    "dns_v4": self._dhcp_server_settings.get(
                        "dns_v4",
                        [],
                    ),
                    "domain_name": self._dhcp_server_settings.get(
                        "domain_name",
                        "lan.internal",
                    ),
                    "max_leases": self._dhcp_server_settings.get(
                        "max_leases"
                    ),
                })
                self.lan_manager.configure(**lan_config)

                self.lan_manager.start()

                self._configure_dhcp_control_plane(
                    reason="lan-manager-start"
                )
            if use_uplink or (use_dhcp_out and self._dhcp_out_mode == "managed"):
                self.upstream_manager = UpstreamManager(
                    self,
                    gateway_manager=self.gateway_manager,
                )
                # Compatibility: existing managers and dependency injection still
                # refer to uplink_manager. Both names point at one enhanced object.
                self.uplink_manager = self.upstream_manager

                uplink_config = {
                    "health_interval_sec": 15.0,
                    "preferred_iface_names": [self.interface_out_friendly_name or "Wi-Fi"],
                    "allow_router_failover": bool(use_uplink),
                    "preserve_wifi_link": True,
                    "disable_netroute_default_sync": True,
                    "disable_netroute_metric_tuning": True,
                    "remove_public_host_routes": True,
                    "enable_wan_dhcp": bool(use_dhcp_out and self._dhcp_out_mode == "managed"),
                    "wan_dhcp_interfaces": [self.interface_out_friendly_name] if self.interface_out_friendly_name else [],
                    "wan_dhcp_bootstrap_timeout_sec": 35.0,
                    "wan_dhcp_retry_sec": 30.0,
                    "wan_dhcp_watch_interval_sec": 10.0,
                    "wan_dhcp_force_renew_on_start": False,
                    "wan_dhcp_renew_margin_sec": 120.0,
                    "ensure_host_default_route": True,
                    "reset_dns_from_dhcp": True,
                    "host_route_metric": 15,
                    "auto_acquire_missing_uplinks": bool(use_uplink),
                }
                allowed_uplink_settings = {
                    "health_interval_sec",
                    "preferred_iface_names",
                    "allow_router_failover",
                    "preserve_wifi_link",
                    "disable_netroute_default_sync",
                    "disable_netroute_metric_tuning",
                    "remove_public_host_routes",
                    "gateway_probe_ports",
                    "public_probes",
                    "candidate_stale_sec",
                    "minimum_public_score_to_activate",
                    "keep_current_if_public",
                    "enable_wan_dhcp",
                    "wan_dhcp_interfaces",
                    "wan_dhcp_bootstrap_timeout_sec",
                    "wan_dhcp_retry_sec",
                    "wan_dhcp_watch_interval_sec",
                    "wan_dhcp_force_renew_on_start",
                    "wan_dhcp_renew_margin_sec",
                    "ensure_host_default_route",
                    "reset_dns_from_dhcp",
                    "host_route_metric",
                    "auto_acquire_missing_uplinks",
                }
                uplink_config.update({
                    key: value
                    for key, value in uplink_settings.items()
                    if key in allowed_uplink_settings
                })
                self.upstream_manager.configure(**uplink_config)
                self.upstream_manager.start()

                if self.lan_manager is not None:
                    try:
                        self.lan_manager.uplink_manager = self.upstream_manager
                    except Exception:
                        pass
            # NEW
            self.stratum_manager = None
            self.stratum_connection_manager = None
            self.daemon_manager = None

            if use_stratum_comm:
                self.stratum_manager = StratumManager(self.code_output_manager, self.router_logger)
                self.stratum_connection_manager = StratumConnectionManager(
                    self.code_output_manager,
                    self.router_logger,
                    self.stratum_manager,
                )
            self.arp_manager.router_ip_out = self.router_ip_out
            self.arp_manager.set_default_gateway(self._interfaces_config, self.router_gateway_out_ip)

            self.icmp_manager = ICMPManager(self.router_logger, self.packet_writer, self._interfaces_config)
            self.packet_writer.update_interfaces(self._interfaces_config)
            if nat_os:
                self._enable_nat_forwarding()

            self.nat_manager = NATManager(
                router_logger=self.router_logger,
                sendback_manager=self.sendback_manager,
                router_public_ip=self.router_ip_out,  # initial OUT/WAN-side IP
                packet_writer=self.packet_writer,
                interfaces_config=self._interfaces_config,
                rip_manager_find_route=self.rip_manager.find_route,
                arp_manager_resolve=self.arp_manager.resolve,
                function_call_tracker=self.function_call_tracker,
            )
            self._sync_nat_public_identity(reason="startup", force=True)
            self.notification_manager = NotificationManager(
                self.router_logger,
                self.NOTIFICATION_TARGET_IP,
                self.NOTIFICATION_TARGET_PORT,
                self.interface_in_full_name
            )
            self.sniffer = SnifferSoftware(self.arp_manager, self.rip_manager, self.lag_manager, self.outbound_load_balancer, self.notification_manager, self._interfaces_config, self.router_logger, self.hyperv_manager, use_hyperv)
            self.transport_manager.sniffer = self.sniffer
            self._inject_dependencies()
            if use_wifi_host and self.wifi_manager:
                try:
                    self.wifi_manager.refresh_router_binding()
                except Exception as exc:
                    self.router_logger.log_message(
                        f"[WiFiManager] ⚠️ Router binding refresh failed: {exc}"
                    )

            managed_dhcp_client_ifaces = []
            direct_dhcp_client_ifaces = []
            if use_dhcp_out and self.interface_out_full_name:
                target = (
                    managed_dhcp_client_ifaces
                    if self._dhcp_out_mode == "managed"
                    else direct_dhcp_client_ifaces
                )
                target.append(self.interface_out_full_name)
            if use_dhcp_in and self.interface_in_full_name:
                target = (
                    managed_dhcp_client_ifaces
                    if self._dhcp_in_mode == "managed"
                    else direct_dhcp_client_ifaces
                )
                target.append(self.interface_in_full_name)

            if (
                    managed_dhcp_client_ifaces
                    and self.transport_manager.is_protocol_enabled("dhcp4")
            ):
                # Managed mode retains the active discover/request helper.
                self.transport_manager.transport_dhcp.enable_client(self.sniffer)
                for dhcp_client_iface in dict.fromkeys(managed_dhcp_client_ifaces):
                    self.transport_manager.transport_dhcp.client_start(dhcp_client_iface)
                self.parallel_python.inject_into(
                    self.transport_manager.transport_dhcp._active
                )

            if direct_dhcp_client_ifaces:
                # Direct mode is deliberately passive inside the router. Windows
                # owns DHCP discover/request/renew and the transport manager only
                # observes/logs the resulting lease packets.
                self.router_logger.log_message(
                    "[DHCP][DirectLease] 👁️ Passive lease observation on "
                    f"{list(dict.fromkeys(direct_dhcp_client_ifaces))}; no internal DHCP agent started."
                )

            self.isakmp_manager = ISAKMPManager(self.router_logger, self.packet_writer, self.notification_manager, self._interfaces_config)
            self.packet_catcher.notification_manager = self.notification_manager
            self.arp_manager.notification_manager = self.notification_manager

            self.packet_signer.notification_manager = self.notification_manager

            self.rip_manager.initialize_routes(
                interfaces_config=self._interfaces_config,
                default_gateway_ip=self.router_gateway_out_ip,
                default_gateway_iface=self.interface_out_full_name,
                router_gateway_out_ip=self.router_gateway_out_ip,
                interface_out_full_name=self.interface_out_full_name,
                interface_in_full_name=self.interface_in_full_name
            )
            self.dns_manager.start()
            if self._manager_settings.get(
                    "enable_handshake",
                    True,
            ):
                self.handshake_manager = HandshakeManager(
                    self.router_logger,
                    self.arp_manager,
                    self.nat_manager,
                    self.rip_manager,
                    self.packet_writer,
                    timeout_half_open=self._manager_settings[
                        "handshake_timeout_half_open"
                    ],
                    timeout_established=self._manager_settings[
                        "handshake_timeout_established"
                    ],
                )
                self.handshake_manager.sniffer = self.sniffer
                self.handshake_manager.set_thresholds(
                    rate_limit_threshold=self._manager_settings[
                        "handshake_rate_limit_threshold"
                    ],
                    rate_limit_period=self._manager_settings[
                        "handshake_rate_limit_period"
                    ],
                    ban_duration=self._manager_settings[
                        "handshake_ban_duration"
                    ],
                )
                self.handshake_manager.log_tcp_lifecycle = (
                    self._manager_settings[
                        "handshake_log_tcp_lifecycle"
                    ]
                )
                self.handshake_manager.log_non_tls_tcp = (
                    self._manager_settings[
                        "handshake_log_non_tls_tcp"
                    ]
                )
                self.handshake_manager.log_tls_records = (
                    self._manager_settings[
                        "handshake_log_tls_records"
                    ]
                )
                self.transport_manager.bind_handshake_manager(
                    self.handshake_manager
                )
                self.code_output_manager.bind_handshake_manager(
                    self.handshake_manager
                )
                self.handshake_manager.log_tls_application_data = (
                    self._manager_settings[
                        "handshake_log_application_data"
                    ]
                )
                self.handshake_manager.log_tls13_key_events = (
                    self._manager_settings[
                        "handshake_log_tls13_key_events"
                    ]
                )
                self.handshake_manager._tls_mgr.policy.ciphers.set_requirements(
                    require_pfs=True,
                    require_aead=True
                )
            else:
                self.handshake_manager = None
            self.router_logger.log_message("\n--- Python Router Starting Services ---")
            self._stop_sniffing_event.clear()


            if self._manager_settings.get(
                    "enable_syn_scanner",
                    True,
            ):
                self.syn_scanner = SYNScanner(
                    sniffer=self.sniffer,
                    router_logger=self.router_logger,
                    packet_writer=self.packet_writer,
                    interfaces_config=self._interfaces_config,
                    notification_manager=self.notification_manager,
                    arp_manager=self.arp_manager,
                    scan_targets=[
                        ("8.8.8.8", [53, 80]),
                        ("1.1.1.1", [443]),
                    ],
                    scan_interval=self._manager_settings[
                        "syn_scan_interval"
                    ],
                )
            else:
                self.syn_scanner = None
            self.dns_manager.configure_runtime(
                upstream_iface=self.interface_out_full_name,
                upstream_iface_selector=self._select_dns_upstream_iface,
                # Do not pin DNS sockets to a WAN address that may be stale
                # while DHCP, static mode, or AT&T IP passthrough converges.
                # DNSManager still accepts explicit sources, but OS route/source
                # selection is the safest default for long-running operation.
                socket_source_ipv4=None,
                socket_source_ipv6=None,
                socket_resolution_mode="prefer",
                reply_source_policy="query-destination",
            )

            if self.syn_scanner is not None:
                self.syn_scanner.start()
            self.rip_manager.start()
            self.packet_writer.sniffer = self.sniffer
            self.packet_writer.start()
            if self.handshake_manager is not None:
                self.handshake_manager.start()
            if self._manager_settings.get("enable_igmp", True):
                self.igmp_manager.set_interfaces_config(
                    self._interfaces_config
                )
                self.igmp_manager.start()
            self._start_dhcp_servers()
            self.ethernet_manager.start()
            self.nat_manager.start()
            self._setup_dynamic_firewall_manager_rules()
            # Send Gratuitous ARP for router's own IPs on startup
            if self.interface_in_full_name and self.router_ip_in and self.mac_in:
                self.arp_manager.send_gratuitous_arp(self.router_ip_in, self.mac_in, self.interface_in_full_name)
            if self.interface_out_full_name and self.router_ip_out and self.mac_out:
                self.arp_manager.send_gratuitous_arp(self.router_ip_out, self.mac_out, self.interface_out_full_name)
            if use_stratum_comm:
                configured_pool_host = (
                    str(p2pool_server_ip or "").strip()
                    or "127.0.0.1"
                )
                self.stratum_connection_manager.configure(
                    configured_pool_host,
                    int(stratum_pool_port),
                    str(stratum_wallet or "").strip(),
                    str(stratum_worker or "PythonProxy").strip(),
                    listen_port=int(stratum_proxy_port),
                    use_tls=stratum_use_tls,
                    pool_host=(
                        str(stratum_tls_hostname).strip()
                        if stratum_tls_hostname
                        else configured_pool_host
                    ),
                    user_agent=(
                        str(stratum_user_agent).strip()
                        or "pystratum/0.5"
                    ),
                    password=(
                        "x"
                        if stratum_password is None
                        else str(stratum_password)
                    ),
                    listen_host=(
                        str(stratum_proxy_host).strip()
                        or "127.0.0.1"
                    ),
                    enable_proxy=bool(stratum_enable_proxy),
                )

                if stratum_mode == "daemon":
                    self.daemon_manager = MoneroDaemonManager(
                        self.code_output_manager,
                        daemon_url=(
                            str(stratum_daemon_url).strip()
                            or "http://127.0.0.1:18081"
                        ),
                        zmq_address=(
                            str(stratum_zmq_address).strip()
                            or "tcp://127.0.0.1:18083"
                        ),
                        stratum_conn_manager=self.stratum_connection_manager,
                        logger=self.router_logger
                        )
                    self.daemon_manager.start()
                else:
                    self.stratum_connection_manager.start()
            if use_peer_to_peer:
                broadcast_ip = "255.255.255.255"
                if self.router_network_out:
                    broadcast_ip = str(self.router_network_out.broadcast_address)

                self.p2p_manager = P2PPeerManager(
                    router_logger=self.router_logger,
                    router_ip=self.router_ip_out,
                    broadcast_ip=broadcast_ip,
                    sniffer=self.sniffer,
                    out_iface=self.interface_out_full_name,
                )
                self.p2p_manager.set_managers(
                    self.arp_manager,
                    self.rip_manager,
                    broadcast_manager=getattr(self, "broadcast_manager", None),
                    firewall_manager=getattr(self, "firewall_manager", None),
                    netroute_manager=getattr(self, "netroute_manager", None),
                    transport_manager=getattr(self, "transport_manager", None),
                    interfaces_config=getattr(self, "_interfaces_config", None),
                    router_network=getattr(self, "router_network_out", None),
                )
                self.p2p_manager.start()
            if use_netroute:
                self.netroute_manager = NetRouteManager(
                    self.router_logger,
                    self.rip_manager,
                    self.arp_manager,
                    self.ndp_manager,
                    outbound_load_balancer=self.outbound_load_balancer,
                    interfaces_config=self._interfaces_config,
                    enable_os_route_sync=True,
                    enable_host_route_sync=True,
                    enable_default_route_sync=True,  # safest for Wi-Fi stability
                    enable_ipv6_os_sync=True,
                    enable_metric_tuning=True,  # safest for Wi-Fi stability
                )
                self.netroute_manager.set_interfaces_config(self._interfaces_config)
                self.netroute_manager.start()
            else:
                self.netroute_manager = False
            self.code_output_manager.start()
            try:
                self.codeoutput_interface_manager.start()
            except Exception as exc:
                # Hyper-V is unavailable on Windows Home. Keep the manager bound
                # to PythonRouterManager.process_packet() and continue with the
                # stable logical CodeOutput ingress instead of rolling back the router.
                self.router_logger.log_message(
                    f"[CodeOutputInterface] ⚠️ Physical interface unavailable; "
                    f"continuing in logical process_packet mode: {exc}"
                )
                self.codeoutput_interface_manager.interface_ready = False
                self.codeoutput_interface_manager.capture_started = False
                self.codeoutput_interface_manager.last_error = str(exc)
            if install_ollama_on_router is not None and self.ollama_assistant is None and use_ollama:
                try:
                    self.ollama_assistant = install_ollama_on_router(self, self.router_logger)
                    self.router_logger.log_message("[Ollama] ✅ Router packet learning bridge installed.")
                except Exception as e:
                    self.router_logger.log_message(f"[Ollama] ⚠️ Failed to install bridge: {e}")

            # Verbosity and active-probe behavior now come from GUI settings.
            # TLS learning is bound to the real HandshakeManager above.

            self.default_analysis_extras = create_pipeline_extras(
                logger=self.router_logger,  # <-- Pass your logger instance here
                stages="init_packet|parse_l2|parse_arp|parse_l3|parse_l4|parse_app|analyze_payload|ipc_emit",
                memory_key="last_analyzed_packet",
                debug=False,
                stop_on_error=True,
                router_ip_in=ipc_emit_host
            )
            self.router_logger.log_message(f"[IPCEmit][Pipeline] Hosting on {ipc_emit_host}")

            sniffing_tasks = []
            for iface_name, iface_config in list(self._interfaces_config.items()):
                if isinstance(iface_config, dict) and iface_config.get("logical_only"):
                    continue
                if iface_name not in ["WireShark", "Nate's Tunnel", "WinDivertBridge"]:
                    sniffing_tasks.append((self._start_single_sniffer, (iface_name,promisc,)))
            self.parallel_python.run_all_parallel(sniffing_tasks, return_type="void")
            self.parallel_python.increase_ram_usage(1000)
            pcores = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]  # example: your P-cores (adjust for your CPU)
            unhinge_process(cores=pcores, high_priority=True, disable_eco=True)
            if use_scrapewebsite:
                self.scrapewebsite_manager = ScrapeWebsiteManager(
                    self.router_logger,
                    endpoint=scrapewebsite_endpoint or ScrapeWebsiteManager.DEFAULT_ENDPOINT,
                    router_id="main",
                    allow_private_dst=False,
                )
                self.scrapewebsite_manager.start()
            start_cpu_boost(threads=len(pcores), target_util=0.75, cores=pcores, pin_per_thread=True, unhinge=True)
            if use_hyperv:
                # after creating managers
                self.hypervrouter_manager = HyperVRouterManager(self.router_logger)

                self.hypervrouter_manager.configure(
                    segment_id="main-lan",
                    bind_ip=self.router_ip_out or self.router_ip_in or "127.0.0.1",
                )
                self.hypervrouter_manager.configure_ip_passthrough(
                    public_ip=(self.public_ip_observed or self.router_ip_out),
                    gateway_ip=self.router_gateway_out_ip,
                    private_networks=[
                        str(self.router_network_in)
                        if getattr(self, "router_network_in", None)
                        else "192.168.0.0/16"
                    ],
                    allow_dhcp_control=True,
                    allow_tcp_ack_bridge=True,
                )

                self.hypervrouter_manager.register_hyperv_backend(
                    "hyperv-main",
                    self.hyperv_manager,
                    start_backend=False,
                )

                self.hypervrouter_manager.attach_wintun_manager(
                    self.wintun_manager,
                    start_manager=False,
                    expose_as_sender=False,  # set True only if you have a real wintun send callable
                )

                self.hypervrouter_manager.attach_windivert_manager(
                    self.windivert_manager,
                    start_manager=False,
                    expose_as_sender=False,  # set True only if you have a real windivert reinject callable
                )

                if self.host_connectivity_boundary:
                    self.hypervrouter_manager.attach_hostboundary_manager(self.host_connectivity_boundary)

                self.hyperv_manager.start()
                self.windivert_manager.start()
                self.wintun_manager.start()
                self.hypervrouter_manager.start()
                self.hyperv_enabled = True
                self.arp_manager.add_trusted_port("WinDivertBridge")
                self.arp_manager.add_trusted_port("Nate's Tunnel")
                self.parallel_python.increase_ram_usage(1500)
            else:
                self.hyperv_enabled = False

            if use_peerinterface:
                peer_cfg = dict(peerinterface_settings or {})
                discovery_group = str(peer_cfg.get("discovery_group") or "239.255.78.78").strip()
                discovery_port = int(peer_cfg.get("discovery_port") or 47781)
                data_port = int(peer_cfg.get("data_port") or peer_cfg.get("frame_port") or 47782)
                segment_id = str(peer_cfg.get("segment_id") or "peer-main").strip() or "peer-main"
                requested_bind = str(peer_cfg.get("bind_ip") or "").strip()
                bind_candidates = [requested_bind, self.router_ip_out, self.router_ip_in]
                bind_ip = next((str(ip).strip() for ip in bind_candidates if str(ip or "").strip() not in {"", "0.0.0.0", "127.0.0.1"}), "")
                if not bind_ip:
                    for name, addrs in psutil.net_if_addrs().items():
                        for addr in addrs:
                            if addr.family == socket.AF_INET:
                                candidate = str(addr.address or "").strip()
                                try:
                                    ip_obj = ipaddress.ip_address(candidate)
                                except ValueError:
                                    continue
                                if not (ip_obj.is_loopback or ip_obj.is_link_local or ip_obj.is_multicast or ip_obj.is_unspecified):
                                    bind_ip = candidate
                                    break
                        if bind_ip:
                            break
                if not bind_ip:
                    raise RuntimeError("PeerInterface requires one usable local IPv4 address")

                self.peerinterface_manager = PeerInterfaceManager(
                    self.router_logger,
                    discovery_group=discovery_group,
                    discovery_port=discovery_port,
                    data_port=data_port,
                    heartbeat_sec=float(peer_cfg.get("heartbeat_sec") or 15.0),
                    peer_timeout_sec=float(peer_cfg.get("peer_timeout_sec") or 45.0),
                    max_network_queue=int(peer_cfg.get("max_network_queue") or 128),
                )
                lan_bind_ips = [ip for ip in (self.router_ip_in, self.router_ip_out) if ip]
                self.peerinterface_manager.configure(
                    segment_id=segment_id,
                    bind_ip=bind_ip,
                    lan_bind_ips=lan_bind_ips,
                    auto_detect_local_ips=True,
                )
                configure_security = getattr(self.peerinterface_manager, "configure_wire_security", None)
                if callable(configure_security):
                    configure_security(
                        shared_secret=str(peer_cfg.get("shared_secret") or ""),
                        require_auth=bool(peer_cfg.get("require_auth", False)),
                    )
                self.peerinterface_manager.attach_router(self)
                if self.host_connectivity_boundary:
                    self.peerinterface_manager.attach_hostboundary_manager(self.host_connectivity_boundary)
                self.peerinterface_manager.start()
                self.peerinterface_enabled = True
                self._peerinterface_nat_ports = {discovery_port, data_port}
                self._interfaces_config.setdefault("PeerInterface", {
                    "friendly_name": "PeerInterface",
                    "full_name": "PeerInterface",
                    "logical": True,
                    "virtual": True,
                    "capture_enabled": False,
                    "bind_ip": bind_ip,
                    "segment_id": segment_id,
                })
                self._ensure_peerinterface_firewall_rules(sorted(self._peerinterface_nat_ports))
                self.router_logger.log_message(
                    f"[PeerInterfaceManager] ✅ Started {segment_id} on {bind_ip}; "
                    f"discovery=UDP/{discovery_port} frames=UDP/{data_port}."
                )
                # Add software-NAT self-service mappings after the manager knows its
                # actual ports. These mappings are independent from Windows NetNat.
                if self.nat_manager:
                    try:
                        configure_services = getattr(self.nat_manager, "configure_router_self_services", None)
                        if callable(configure_services):
                            existing_udp = set(
                                getattr(self.nat_manager, "_router_self_service_udp_ports", set()) or set()
                            )
                            configure_services(
                                udp_ports=sorted(existing_udp | self._peerinterface_nat_ports),
                            )
                        else:
                            for port in sorted(self._peerinterface_nat_ports):
                                self.nat_manager.add_port_forward_rule(
                                    external_port=port,
                                    internal_ip=self.router_ip_in or bind_ip,
                                    internal_port=port,
                                    protocol="udp",
                                )
                    except Exception as exc:
                        self.router_logger.log_message(
                            f"[PeerInterfaceManager][NAT] ⚠️ Software mapping failed: {exc}"
                        )
                if nat_os:
                    self._install_peerinterface_netnat_mappings(
                        sorted(self._peerinterface_nat_ports),
                        internal_ip=self.router_ip_in or bind_ip,
                    )

            self._runtime_network_ready.set()
            if self.hypervrouter_manager:
                try:
                    notify_ready = getattr(self.hypervrouter_manager, "notify_network_ready", None)
                    if callable(notify_ready):
                        notify_ready()
                except Exception as exc:
                    self.router_logger.log_message(
                        f"[HyperVRouterManager] ⚠️ Network-ready notification deferred: {exc}"
                    )
            if self.peerinterface_manager:
                try:
                    notify_ready = getattr(self.peerinterface_manager, "notify_network_ready", None)
                    if callable(notify_ready):
                        notify_ready()
                except Exception as exc:
                    self.router_logger.log_message(
                        f"[PeerInterfaceManager] ⚠️ Network-ready notification deferred: {exc}"
                    )
            if self.socket_interface:
                self.socket_interface.start()
            self.started = True
            self.router_logger.log_message(
                "[Router] ✅ Runtime ready; capture, virtual pipes, and socket promotion are isolated."
            )
        except Exception as e:
            self._best_effort_runtime_core_stop(
                use_hyperv=bool(use_hyperv),
                use_peerinterface=bool(use_peerinterface),
                use_stratum_comm=bool(use_stratum_comm),
            )
            self.router_logger.log_message(
                f"[Router] ❌ Startup failed and runtime rollback completed: "
                f"{type(e).__name__}: {e}"
            )


    def stop_routing(self,use_dhcp_out, use_dhcp_in, use_static, use_hyperv, use_stratum_comm, use_netroute, nat_os, use_ollama, use_peerinterface=False):
        """Stops all manager threads and cleans up network interfaces."""
        try:
            self.router_logger.log_message("[Router] --- Python Router Stopping Services ---")
            try:
                if self.process_interface_manager is not None:
                    self.process_interface_manager.disable_process()
            except Exception as exc:
                self.router_logger.log_message(
                    f"[ProcessInterface] ⚠️ Stop error: {exc}"
                )
            self._runtime_network_ready.clear()
            self._stop_sniffing_event.set()
            self._stop_ingress_workers(discard=True)
            if use_peerinterface or self.peerinterface_enabled or self.peerinterface_manager:
                self._safe_stop_component("PeerInterfaceManager", self.peerinterface_manager)
                self.peerinterface_manager = None
                self.peerinterface_enabled = False
            if use_hyperv:
                self.hypervrouter_manager.stop()
                self.windivert_manager.stop()
                self.wintun_manager.stop()
                self.hyperv_manager.teardown()
                self.hyperv_enabled = False
            try:
                if self.transport_manager:
                    self.transport_manager.stop()
            except Exception as exc:
                self.router_logger.log_message(
                    f"[Transport] ⚠️ Stop error: {exc}"
                )
            self.parallel_python.release_ram_usage()
            try:
                if self.scrapewebsite_manager:
                    self.scrapewebsite_manager.stop()
                    self.scrapewebsite_manager = None
            except Exception as e:
                self.router_logger.log_message(f"[ScrapeWebsite] Stop error: {e}")
            if self.socket_interface:
                self.socket_interface.stop()
            if use_stratum_comm:
                if self.daemon_manager:
                    self.daemon_manager.stop()
                if self.stratum_connection_manager:
                    self.stratum_connection_manager.stop()
            try:
                self.codeoutput_interface_manager.shutdown()
            except Exception as exc:
                self.router_logger.log_message(f"[CodeOutputInterface] ⚠️ Stop error: {exc}")
            self.code_output_manager.stop()
            try:
                if self.ollama_assistant and use_ollama:
                    self.ollama_assistant.unbind_router()
                    self.ollama_assistant = None
            except Exception as e:
                self.router_logger.log_message(f"[Ollama] ⚠️ Unbind failed: {e}")
            try:
                if self.wifi_manager:
                    self.wifi_manager.stop(
                        force=False,
                        detach_router=True,
                    )
            except Exception as exc:
                self.router_logger.log_message(
                    f"[WiFiManager] ⚠️ Wireless host stop failed: {exc}"
                )
            if use_static:
                self._deconfigure_interface_settings()
            self.parallel_python.stop()
            stopped_dhcp_ids = set()

            for dhcp_server in (
                    self.dhcp_server_in,
                    self.dhcp_server_out,
                    *list((getattr(self, "dhcp_interface_servers", {}) or {}).values()),
            ):
                if dhcp_server is None:
                    continue

                server_id = id(dhcp_server)

                if server_id in stopped_dhcp_ids:
                    continue

                stopped_dhcp_ids.add(server_id)

                try:
                    dhcp_server.stop()
                except Exception as exc:
                    self.router_logger.log_message(
                        f"[DHCP] ⚠️ Error stopping DHCP server: {exc}"
                    )
            self.dhcp_interface_servers = {}
            self.rip_manager.stop()
            self.ethernet_manager.stop()
            self.packet_writer.stop()
            if nat_os:
                self._disable_nat_forwarding()
            if self.nat_manager:
                self.nat_manager.stop()
            self.dns_manager.stop()
            if self.p2p_manager:
                self.p2p_manager.stop()
            if use_netroute:
                if self.netroute_manager:
                    self.netroute_manager.stop()
            if self.host_connectivity_boundary:
                self.host_connectivity_boundary.stop()
            if self.lan_manager:
                self.lan_manager.stop()
                self.lan_manager = None
            if self.python_server_manager:
                self.python_server_manager.unwrap_logger_method(self.router_logger, "log_message")
                self.python_server_manager.stop()
                self.python_server_manager = None
            if self.gateway_manager:
                self.gateway_manager.stop()
                self.gateway_manager = None
            upstream_manager = self.upstream_manager or self.uplink_manager
            if upstream_manager:
                upstream_manager.stop()
            self.upstream_manager = None
            self.uplink_manager = None
            self.router_logger.log_message("[Router] Waiting for worker threads to finish...")
            self.router_logger.log_message("[Router] Worker threads stopped.")
            self.router_logger.log_message("[Router] Worker threads stopped.")
            # 5. Join sniffer threads (these should have died or be dying from _stop_sniffing_event)
            self.router_logger.log_message("[Router] Waiting for sniffer threads to finish...")
            # Access _sniff_threads with lock, as monitor might be trying to remove/add.

            self.router_logger.log_message("[Router] Sniffer threads stopped.")
            stop_cpu_boost()
            self._sniff_threads.clear()
            if self._manager_settings.get("enable_igmp", True):
                self.igmp_manager.stop()
            if self.handshake_manager:
                self.handshake_manager.stop()
            self.remove_l2_bridge("MyLANBridge")
            self.remove_link_aggregation_group("MyLANAggregation")
            if self.interface_out_full_name:
                self.remove_outbound_load_balancing_interface(self.interface_out_full_name)
            if self.interface_lac_full_name:
                self.remove_outbound_load_balancing_interface(self.interface_lac_full_name)
            if self.interface_lac_2_full_name:
                self.remove_outbound_load_balancing_interface(self.interface_lac_2_full_name)
            if self.syn_scanner:
                self.syn_scanner.stop()
            self.cleanup_all_network_changes()
            self.started = False
            self.router_logger.log_message("[Router] All services stopped.")
        except Exception as e:
            self.router_logger.log_message(
                f"[Router] Error during normal shutdown: {type(e).__name__}: {e}; "
                "running best-effort cleanup."
            )
            self._best_effort_runtime_core_stop(
                use_hyperv=bool(use_hyperv),
                use_peerinterface=bool(use_peerinterface),
                use_stratum_comm=bool(use_stratum_comm),
            )
        finally:
            self._runtime_network_ready.clear()
            self._stop_sniffing_event.set()
            self.started = False

    def _select_dns_upstream_iface(
            self,
            target_ip: str,
            inbound_iface: Optional[str] = None,
    ) -> Optional[str]:
        """
        Select the interface used to send a raw upstream DNS query.

        This implementation does not depend on GatewayManager.

        Selection order:
          1. Loopback targets use the loopback interface.
          2. Targets located on a directly connected network use that interface.
          3. Public, private, and unmatched upstream resolvers use the WAN interface.
          4. The inbound interface is used only as a final fallback.

        DNSManager's preferred OS-socket mode normally allows Windows to select
        the route. This selector is primarily used by the raw-packet fallback.
        """
        target_text = str(target_ip or "").strip()

        if not target_text:
            return self.interface_out_full_name or inbound_iface

        # Remove an IPv6 scope suffix before parsing, such as:
        # fe80::1%12 -> fe80::1
        target_host = target_text.split("%", 1)[0]

        try:
            target = ipaddress.ip_address(target_host)
        except ValueError:
            self.router_logger.log_message(
                f"[DNS][ROUTE] ⚠️ Invalid upstream address '{target_text}'; "
                f"using WAN interface."
            )
            return self.interface_out_full_name or inbound_iface

        # A resolver explicitly configured on localhost must use loopback.
        if target.is_loopback:
            return (
                    self.interface_loopback_full_name
                    or self.interface_out_full_name
                    or inbound_iface
            )

        connected_matches = []

        # Find the interface whose configured network contains the resolver.
        for iface_name, iface_config in list(self._interfaces_config.items()):
            if not iface_name or not isinstance(iface_config, dict):
                continue

            network = iface_config.get("network")
            if network is None:
                continue

            try:
                if not isinstance(
                        network,
                        (ipaddress.IPv4Network, ipaddress.IPv6Network),
                ):
                    network = ipaddress.ip_network(str(network), strict=False)
            except (TypeError, ValueError):
                continue

            if network.version != target.version:
                continue

            try:
                if target not in network:
                    continue
            except TypeError:
                continue

            # Do not select loopback for a non-loopback resolver.
            if (
                    self.interface_loopback_full_name
                    and iface_name == self.interface_loopback_full_name
            ):
                continue

            connected_matches.append(
                (
                    int(network.prefixlen),
                    1 if iface_name == self.interface_out_full_name else 0,
                    iface_name,
                )
            )

        if connected_matches:
            # Prefer the most specific connected network.
            # Prefer WAN if two entries have the same prefix length.
            connected_matches.sort(reverse=True)
            selected_iface = connected_matches[0][2]

            return selected_iface

        # Unscoped link-local DNS normally belongs to the active WAN.
        # A scoped address is also sent through WAN unless it matched a
        # directly connected configured network above.
        if target.version == 6 and target.is_link_local:
            return self.interface_out_full_name or inbound_iface

        # Public resolvers such as 1.1.1.1, 8.8.8.8 and 9.9.9.9 use WAN.
        if target.is_global:
            return self.interface_out_full_name or inbound_iface

        # A private resolver that did not match a LAN network is most likely
        # the upstream gateway/router DNS server on the WAN side.
        if target.is_private or target.is_link_local:
            return self.interface_out_full_name or inbound_iface

        return self.interface_out_full_name or inbound_iface
    # -----------------------------
    # add inside PythonRouterManager
    # -----------------------------
    def _byte_parse_scope(self, inbound_iface: str | None) -> str:
        """
        Group interfaces into dedupe scopes.
        Loopback + WinDivertBridge share one scope so the same host-local packet
        seen from both paths can be dropped early.
        """
        s = str(inbound_iface or "").strip().lower()

        if "loopback" in s:
            return "host-local"
        if "windivertbridge" in s or "windivert" in s:
            return "host-local"

        return s or "unknown"

    def _prune_byte_parse_dedupe_cache(self, now: float | None = None) -> None:
        now = time.monotonic() if now is None else now
        ttl = float(getattr(self, "_byte_parse_dedupe_ttl", 0.50) or 0.50)

        cache = self._byte_parse_dedupe_cache
        if not cache:
            return

        expired = [fp for fp, ts in cache.items() if (now - ts) > ttl]
        for fp in expired:
            cache.pop(fp, None)

        max_items = int(getattr(self, "_byte_parse_dedupe_max", 8192) or 8192)
        while len(cache) > max_items:
            try:
                oldest_key = next(iter(cache))
                cache.pop(oldest_key, None)
            except Exception:
                break

    def _fingerprint_raw_packet_for_parse(self, raw_bytes: bytes, inbound_iface: str | None) -> str:
        """
        Fast, stable fingerprint for pre-parse dedupe.

        We intentionally do NOT hash the entire packet for big frames.
        Prefix + suffix + length is enough for a short TTL dedupe cache.
        """
        scope = self._byte_parse_scope(inbound_iface)

        h = hashlib.blake2b(digest_size=16)
        h.update(scope.encode("utf-8", errors="ignore"))
        h.update(len(raw_bytes).to_bytes(4, "big", signed=False))

        if len(raw_bytes) <= 192:
            h.update(raw_bytes)
        else:
            h.update(raw_bytes[:128])
            h.update(raw_bytes[-32:])

        return h.hexdigest()

    def _should_skip_raw_packet_parse(self, raw_bytes: bytes, inbound_iface: str | None) -> bool:
        """
        Returns True if this raw packet was seen recently enough that we should
        skip Scapy parsing work for it.
        """
        if not raw_bytes:
            return True

        now = time.monotonic()
        fp = self._fingerprint_raw_packet_for_parse(raw_bytes, inbound_iface)

        with self._byte_parse_dedupe_lock:
            self._prune_byte_parse_dedupe_cache(now)

            last_seen = self._byte_parse_dedupe_cache.get(fp)
            if last_seen is not None:
                ttl = float(getattr(self, "_byte_parse_dedupe_ttl", 0.50) or 0.50)
                if (now - last_seen) <= ttl:
                    return True

            self._byte_parse_dedupe_cache[fp] = now
            max_items = int(getattr(self, "_byte_parse_dedupe_max", 8192) or 8192)
            while len(self._byte_parse_dedupe_cache) > max_items:
                try:
                    oldest_key = next(iter(self._byte_parse_dedupe_cache))
                    self._byte_parse_dedupe_cache.pop(oldest_key, None)
                except Exception:
                    break

        return False
    def _probe_host_internet_health(self) -> bool:
        targets = [("1.1.1.1", 443), ("8.8.8.8", 443), ("208.67.222.222", 443)]
        for host, port in targets:
            s = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(1.0)
                if self.router_ip_out:
                    s.bind((self.router_ip_out, 0))
                s.connect((host, port))
                return True
            except Exception:
                pass
            finally:
                try:
                    if s:
                        s.close()
                except Exception:
                    pass
        return False
    def _proto_summary(self, pkt):
        """
        Inspect the packet structure only:
          - L3: IPv4/IPv6 addresses
          - L4: first non-Raw/non-Padding layer under IP/IPv6
          - Ports if that layer exposes sport/dport
          - App: first meaningful layer after L4 (if decoded), e.g., TLS/DNS
        """
        try:
            # ---- L3 (addresses) ----
            v6 = False
            if pkt.haslayer(IP):
                ip = pkt[IP]
                src, dst = ip.src, ip.dst
            elif pkt.haslayer(IPv6):
                ip = pkt[IPv6]
                src, dst = ip.src, ip.dst
                v6 = True
            else:
                # L2 or unknown
                if pkt.haslayer(Ether):
                    e = pkt[Ether]
                    return f"Ether {e.src} → {e.dst} type=0x{int(getattr(e, 'type', 0) or 0):04x}"
                return pkt.summary()

            def addr(a):
                return f"[{a}]" if v6 else a

            # ---- Walk down from IP/IPv6 payload ----
            lay = ip.payload
            IGNORE = {"Raw", "Padding", "NoPayload"}
            l4_name = None
            app_name = None
            sport = dport = None
            depth = 0

            while getattr(lay, "name", "NoPayload") != "NoPayload":
                lname = getattr(lay, "name", lay.__class__.__name__) or lay.__class__.__name__

                if lname not in IGNORE:
                    if l4_name is None:
                        # First meaningful layer under IP/IPv6 = transport protocol
                        l4_name = lname
                        if hasattr(lay, "sport"):
                            try:
                                sport = int(getattr(lay, "sport") or 0)
                            except Exception:
                                sport = None
                        if hasattr(lay, "dport"):
                            try:
                                dport = int(getattr(lay, "dport") or 0)
                            except Exception:
                                dport = None
                    elif app_name is None:
                        # First meaningful layer after L4 = application protocol (if decoded)
                        app_name = lname
                        break

                lay = getattr(lay, "payload", None)
                if lay is None:
                    break
                depth += 1
                if depth > 16:  # safety
                    break

            # ---- Compose line ----
            if l4_name:
                name = f"{l4_name}/{app_name}" if app_name else l4_name
                if sport and dport:
                    return f"{name} {addr(src)}:{sport} → {addr(dst)}:{dport}"
                else:
                    return f"{name} {addr(src)} → {addr(dst)}"

            # Fallback: just L3
            return f"{'IPv6' if v6 else 'IPv4'} {addr(src)} → {addr(dst)}"
        except Exception:
            return "IP"

    def _pick_lag_member(self, packet, inbound_iface, candidate_iface: str) -> str:
        try:
            groups = self.lag_manager.get_lag_members() or {}  # may be None/empty
        except Exception as e:
            self.router_logger.log_message(f"[LAG] ⚠️ get_lag_members() error: {e}")
            return candidate_iface

        # groups: {group_name: [ifaceA, ifaceB, ...]}
        for group_name, members in (groups.items() if isinstance(groups, dict) else []):
            members_set = set(members or [])
            if candidate_iface in members_set:
                try:
                    chosen = self.lag_manager.get_member_interface(group_name, packet)
                    if chosen:
                        self.code_output_manager.submit_packet(packet, inbound_iface=inbound_iface,
                                                               phase="interface", component="lag")
                        return chosen
                except Exception as e:
                    self.router_logger.log_message(f"[LAG] ⚠️ get_member_interface({group_name}) error: {e}")
                # If selection fails, fall back to candidate
                break
        return candidate_iface

    def _eth_type_or_none(self, pkt):
        if pkt.haslayer(Ether):
            return pkt[Ether].type
        if pkt.haslayer(IP):
            return 0x0800  # IPv4
        if pkt.haslayer(IPv6):
            return 0x86DD  # IPv6
        if pkt.haslayer(ARP):
            return 0x0806  # (won’t appear from WinDivert, but safe)
        return None

    def trigger_arp_via_ping(self, ip: str, timeout: float = 1.0):
        try:
            subprocess.run(["ping", "-n", "1", "-w", str(int(timeout * 1000)), ip],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass  # Suppress all errors

    # --- add this helper inside PythonRouterManager ---

    def _get_windows_dns_servers(self, iface_friendly_name: Optional[str]) -> list[str]:
        if not iface_friendly_name:
            return []

        quoted = str(iface_friendly_name).replace("'", "''")
        ps_cmd = rf"""
    $servers = Get-DnsClientServerAddress -InterfaceAlias '{quoted}' -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Select-Object -ExpandProperty ServerAddresses -ErrorAction SilentlyContinue
    if ($servers) {{ $servers | ForEach-Object {{ $_ }} }}
    """
        try:
            proc = subprocess.run(
                ["powershell.exe", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", ps_cmd],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                out = []
                for line in (proc.stdout or "").splitlines():
                    line = line.strip()
                    try:
                        ipaddress.IPv4Address(line)
                        out.append(line)
                    except Exception:
                        pass
                if out:
                    return out
        except Exception:
            pass

        try:
            proc = subprocess.run(
                ["netsh", "interface", "ipv4", "show", "dnsservers", f"name={iface_friendly_name}"],
                capture_output=True,
                text=True,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            if proc.returncode == 0:
                found = re.findall(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", proc.stdout or "")
                out = []
                for x in found:
                    try:
                        ipaddress.IPv4Address(x)
                        out.append(x)
                    except Exception:
                        pass
                if out:
                    return out
        except Exception:
            pass

        return []

    # -----------------------------
    # Add these helpers to PythonRouterManager
    # -----------------------------

    def _should_skip_managed_iface_config(self, iface_full_name: str, iface_friendly_name: str) -> bool:
        """
        Skip only true internal/virtual helper interfaces.
        Never skip the currently active IN or OUT interface just because its name is 'Ethernet'.
        """
        full = str(iface_full_name or "").strip()
        friendly = str(iface_friendly_name or "").strip().lower()

        # Never skip the live IN/OUT interfaces.
        if full and full in {
            getattr(self, "interface_in_full_name", None),
            getattr(self, "interface_out_full_name", None),
        }:
            return False

        # Loopback / synthetic capture only.
        if full and full == getattr(self, "interface_loopback_full_name", None):
            return True
        if friendly in {"adapter for loopback traffic capture", "lo", "loopback"}:
            return True

        # Keep your LAC helper adapters skipped unless they are explicitly the live WAN/LAN.
        if "local area connection*" in friendly:
            return True

        return False

    def _mark_default_gateway_iface(self, outbound_iface_name: str | None, gateway_ip: str | None = None) -> bool:
        """
        Make exactly one interface the default-gateway interface.
        Clears stale flags everywhere else.
        """
        if not outbound_iface_name:
            self.router_logger.log_message(
                "[Router] ERROR: No outbound interface provided for default-gateway marking.")
            return False

        if outbound_iface_name not in self._interfaces_config:
            self.router_logger.log_message(
                f"[Router] ERROR: Outbound interface '{outbound_iface_name}' not configured for default gateway."
            )
            return False

        # Clear stale flags first.
        for iface_name, cfg in self._interfaces_config.items():
            if isinstance(cfg, dict):
                cfg["is_default_gateway_iface"] = (iface_name == outbound_iface_name)

        self.default_gateway_ip = gateway_ip
        if gateway_ip:
            self._interfaces_config[outbound_iface_name]["gateway"] = gateway_ip

        self.router_logger.log_message(
            f"[Router] Set default gateway owner: {outbound_iface_name.split('_')[-1]} "
            f"(gateway={gateway_ip or 'unchanged'})"
        )
        return True
    def _configure_interface_settings(self, use_dhcp_out: bool, use_dhcp_in: bool, use_hyperv: bool,
                                      router_ip_in: str = None,
                                      router_netmask_in: str = "255.255.255.0",
                                      router_ip_out: str = None,
                                      router_netmask_out: str = "255.255.255.0") -> bool:
        """Apply GUI static/DHCP settings through the verified IPv4 helpers."""
        all_success = True
        for iface_full_name, config in list(self._interfaces_config.items()):
            if not isinstance(config, dict):
                continue
            iface_friendly_name = str(
                config.get("friendly_name")
                or self._get_friendly_name_from_full(iface_full_name)
                or iface_full_name
            ).strip()
            if self._should_skip_managed_iface_config(iface_full_name, iface_friendly_name):
                self.router_logger.log_message(
                    f"[Router] ⏭️ Skipping configuration for internal/virtual interface: '{iface_friendly_name}'."
                )
                continue

            is_out_iface = iface_full_name == self.interface_out_full_name
            is_in_iface = iface_full_name == self.interface_in_full_name
            should_use_dhcp = (
                (is_out_iface and bool(use_dhcp_out))
                or (is_in_iface and bool(use_dhcp_in))
            )
            if should_use_dhcp:
                # Native WAN DHCP is not router-owned and therefore is not
                # scheduled for cleanup. IN DHCP is recorded because the router
                # explicitly changed that adapter's state.
                ok = self._set_interface_dhcp(
                    iface_friendly_name,
                    reset_dns=True,
                    trigger_renew=False,
                    record_change=not is_out_iface,
                )
                if not ok:
                    all_success = False
                continue

            network_config = self._get_interface_network(
                iface_full_name, config, persist=True
            )
            ip_to_assign = str(config.get("ip_addr") or "").strip()
            netmask_to_assign = str(config.get("netmask") or "").strip()
            gateway_to_assign = ""

            if is_out_iface:
                ip_to_assign = str(router_ip_out or ip_to_assign).strip()
                netmask_to_assign = str(
                    router_netmask_out
                    or (network_config.netmask if network_config is not None else netmask_to_assign)
                    or "255.255.255.0"
                )
                gateway_to_assign = str(self.router_gateway_out_ip or "").strip()
            elif is_in_iface:
                ip_to_assign = str(router_ip_in or ip_to_assign).strip()
                netmask_to_assign = str(
                    router_netmask_in
                    or (network_config.netmask if network_config is not None else netmask_to_assign)
                    or "255.255.255.0"
                )
            else:
                netmask_to_assign = str(
                    (network_config.netmask if network_config is not None else netmask_to_assign)
                    or "255.255.255.0"
                )

            if not ip_to_assign:
                self.router_logger.log_message(
                    f"[Router] ⚠️ Skipping '{iface_friendly_name}' — no static IPv4 address is available."
                )
                all_success = False
                continue

            if not self._assign_ip_to_interface(
                    iface_friendly_name,
                    ip_to_assign,
                    netmask_to_assign,
                    gateway_to_assign,
            ):
                all_success = False
                continue

            # DNS is intentionally configured after address verification.
            dns_servers = []
            if is_out_iface:
                dns_servers = self._get_windows_dns_servers(iface_friendly_name)
                if not dns_servers and gateway_to_assign:
                    dns_servers = [gateway_to_assign]
            elif is_in_iface and ip_to_assign:
                dns_servers = [ip_to_assign]

            if dns_servers:
                ps_alias = self._powershell_literal(iface_friendly_name)
                ps_dns = ",".join(self._powershell_literal(x) for x in dns_servers[:4])
                dns_script = f"""
$ErrorActionPreference = 'Stop'
$adapter = Get-NetAdapter -Name {ps_alias} -IncludeHidden -ErrorAction Stop |
    Sort-Object ifIndex | Select-Object -First 1
Set-DnsClientServerAddress -InterfaceIndex $adapter.ifIndex -ServerAddresses @({ps_dns}) -ErrorAction Stop
Write-Output ('DNS updated on ' + $adapter.Name)
"""
                if not self._run_network_powershell(
                        dns_script, f"set DNS on {iface_friendly_name}"
                ):
                    all_success = False

        return all_success

    def _deconfigure_interface_settings(self) -> bool:
        """
        Reverts the static configuration of all managed interfaces (except "Ethernet")
        back to DHCP for IP, DNS, and routing.

        Returns:
            bool: True if deconfiguration succeeded for all managed interfaces, False otherwise.
        """
        all_success = True

        # Iterate over a copy of the keys to avoid issues if the dictionary changes
        for iface_full_name in list(self._interfaces_config.keys()):
            partial_name = self._get_friendly_name_from_full(iface_full_name)
            iface_friendly_name = self._get_real_adapter_name(partial_name) or partial_name

            # Skip the "Ethernet" interface as requested
            if self._should_skip_managed_iface_config(iface_full_name, iface_friendly_name):
                self.router_logger.log_message(
                    f"[Router] ⏭️ Skipping deconfiguration for internal/virtual interface: '{iface_friendly_name}'."
                )
                continue

            self.router_logger.log_message(f"[Router] 🧹 Deconfiguring '{iface_friendly_name}' to DHCP...")
            try:
                ps_command = f"""
                $iface = Get-NetAdapter | Where-Object {{ $_.Name -eq '{iface_friendly_name}' }}
                if (-not $iface) {{
                    Write-Error "Interface '{iface_friendly_name}' not found. Skipping deconfiguration."
                    exit 1
                }}

                # Set IP configuration to DHCP
                Set-NetIPInterface -InterfaceIndex $iface.IfIndex -Dhcp Enabled -ErrorAction Stop

                # Reset DNS servers to clear any static entries
                Set-DnsClientServerAddress -InterfaceIndex $iface.IfIndex -ResetServerAddresses -ErrorAction Stop

                # Remove any default routes associated with this interface
                Get-NetRoute -InterfaceIndex $iface.IfIndex -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue

                Write-Host "Successfully deconfigured '{iface_friendly_name}' to DHCP."
                """
                result = subprocess.run(["powershell.exe", "-Command", ps_command], capture_output=True, text=True,
                                        creationflags=subprocess.CREATE_NO_WINDOW)

                if result.returncode == 0:
                    self.router_logger.log_message(f"[Router] ✅ Successfully deconfigured '{iface_friendly_name}'.")
                else:
                    self.router_logger.log_message(f"[Router] ❌ Failed to deconfigure '{iface_friendly_name}'.")
                    self.router_logger.log_message(f"[Router] PowerShell STDOUT: {result.stdout.strip()}")
                    self.router_logger.log_message(f"[Router] PowerShell STDERR: {result.stderr.strip()}")
                    all_success = False

            except Exception as e:
                self.router_logger.log_message(f"[Router] ❌ Exception deconfiguring '{iface_friendly_name}': {e}")
                all_success = False

        return all_success

    def _get_real_adapter_name(self, partial_name: str) -> str | None:
        """Attempts to resolve the full adapter name by partial match (case-insensitive)."""
        ps_script = "Get-NetAdapter | Select-Object -ExpandProperty Name"
        result = subprocess.run(["powershell.exe", "-Command", ps_script], capture_output=True, text=True)
        if result.returncode != 0:
            return None

        all_names = result.stdout.splitlines()
        for name in all_names:
            if partial_name.lower().replace("*", "") in name.lower():
                return name.strip()
        return None

    def _get_friendly_name_from_full(self, full_name: str) -> str:

        for iface in self._discovered_tshark_interfaces:
            if iface['full_name'] == full_name:
                return iface['friendly_name']
        return full_name

    def _enable_nat_forwarding(self):
        if platform.system() != "Windows" or not self.router_network_in:
            return

        lan_network_cidr = str(self.router_network_in)
        nat_name = self.nat_instance_name

        self.router_logger.log_message(f"[NAT Setup] 🚀 Initializing NAT '{nat_name}' for {lan_network_cidr}...")

        try:
            # 1. Broad Cleanup: Find ANY NAT object managing this subnet and remove it
            # This prevents the "Duplicate Name/Subnet" error if a previous instance died
            cleanup_script = f"""
            $existing = Get-NetNat | Where-Object {{ $_.InternalIPInterfaceAddressPrefix -eq '{lan_network_cidr}' }}
            if ($existing) {{
                $existing | Remove-NetNat -Confirm:$false
            }}
            if (Get-NetNat -Name '{nat_name}' -ErrorAction SilentlyContinue) {{
                Remove-NetNat -Name '{nat_name}' -Confirm:$false
            }}
            """
            subprocess.run(["powershell.exe", "-Command", cleanup_script], capture_output=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)

            # 2. Create the new unique NAT rule
            ps_command = [
                "powershell.exe", "-Command",
                f'New-NetNat -Name "{nat_name}" -InternalIPInterfaceAddressPrefix "{lan_network_cidr}"'
            ]
            result = subprocess.run(ps_command, capture_output=True, text=True, check=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)

            self.router_logger.log_message(f"[NAT Setup] ✅ NAT '{nat_name}' successfully bound to {lan_network_cidr}")
            if self._peerinterface_nat_ports:
                self._install_peerinterface_netnat_mappings(
                    sorted(self._peerinterface_nat_ports),
                    internal_ip=self.router_ip_in,
                )

        except subprocess.CalledProcessError as e:
            self.router_logger.log_message(f"[NAT Setup] ❌ Kernel Error: {e.stderr.strip()}")

    def _ensure_peerinterface_firewall_rules(self, ports) -> None:
        """Allow the configured PeerInterface UDP listeners through Windows Firewall."""
        if platform.system() != "Windows":
            return
        for raw_port in ports or ():
            try:
                port = int(raw_port)
                if not 1 <= port <= 65535:
                    continue
                name = f"PythonRouter-Allow-PeerInterface-UDP-{port}"
                script = f"""
                $ErrorActionPreference = 'Stop'
                Get-NetFirewallRule -DisplayName '{name}' -ErrorAction SilentlyContinue |
                    Remove-NetFirewallRule -ErrorAction SilentlyContinue
                New-NetFirewallRule -DisplayName '{name}' -Direction Inbound -Action Allow `
                    -Protocol UDP -LocalPort {port} -Profile Any
                """
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if result.returncode == 0:
                    self.router_logger.log_message(
                        f"[PeerInterfaceManager][Firewall] ✅ Allowed inbound UDP/{port}."
                    )
                else:
                    detail = (result.stderr or result.stdout or "unknown PowerShell failure").strip()
                    self.router_logger.log_message(
                        f"[PeerInterfaceManager][Firewall] ⚠️ Could not allow UDP/{port}: {detail}"
                    )
            except Exception as exc:
                self.router_logger.log_message(
                    f"[PeerInterfaceManager][Firewall] ⚠️ UDP/{raw_port} rule failed: {exc}"
                )

    def _install_peerinterface_netnat_mappings(self, ports, *, internal_ip: str) -> None:
        """Install explicit Windows NetNat UDP mappings for PeerInterface ports.

        NetNat translations are best-effort: LAN peer discovery continues even if
        Windows rejects a public static mapping (for example, when the upstream
        gateway owns NAT). Existing mappings owned by this NAT name are replaced.
        """
        if platform.system() != "Windows":
            return
        target = str(internal_ip or "").strip()
        try:
            target_obj = ipaddress.ip_address(target)
            if target_obj.version != 4 or target_obj.is_unspecified:
                raise ValueError(target)
        except ValueError:
            self.router_logger.log_message(
                f"[PeerInterfaceManager][NAT] ⚠️ Invalid internal IPv4 for NetNat mappings: {target!r}"
            )
            return
        for raw_port in ports or ():
            try:
                port = int(raw_port)
                if not 1 <= port <= 65535:
                    raise ValueError(port)
                script = f"""
                $ErrorActionPreference = 'Stop'
                $old = Get-NetNatStaticMapping -NatName '{self.nat_instance_name}' -ErrorAction SilentlyContinue |
                    Where-Object {{ $_.Protocol -eq 'UDP' -and $_.ExternalPort -eq {port} }}
                if ($old) {{ $old | Remove-NetNatStaticMapping -Confirm:$false -ErrorAction SilentlyContinue }}
                Add-NetNatStaticMapping -NatName '{self.nat_instance_name}' -Protocol UDP `
                    -ExternalIPAddress '0.0.0.0' -ExternalPort {port} `
                    -InternalIPAddress '{target}' -InternalPort {port}
                """
                result = subprocess.run(
                    ["powershell.exe", "-NoProfile", "-NonInteractive", "-Command", script],
                    capture_output=True,
                    text=True,
                    creationflags=subprocess.CREATE_NO_WINDOW,
                )
                if result.returncode == 0:
                    self.router_logger.log_message(
                        f"[PeerInterfaceManager][NAT] ✅ NetNat UDP/{port} -> {target}:{port}"
                    )
                else:
                    detail = (result.stderr or result.stdout or "unknown PowerShell failure").strip()
                    self.router_logger.log_message(
                        f"[PeerInterfaceManager][NAT] ⚠️ NetNat UDP/{port} mapping unavailable: {detail}"
                    )
            except Exception as exc:
                self.router_logger.log_message(
                    f"[PeerInterfaceManager][NAT] ⚠️ UDP/{raw_port} mapping failed: {exc}"
                )

    def _disable_nat_forwarding(self):
        """
        Removes only the NAT forwarding rule owned by this instance.
        """
        nat_name = self.nat_instance_name
        self.router_logger.log_message(f"[NAT Setup] 🧹 Removing NAT rule: {nat_name}")

        if platform.system() != "Windows":
            return

        ps_command = [
            "powershell.exe", "-Command",
            f'Remove-NetNat -Name "{nat_name}" -Confirm:$false -ErrorAction SilentlyContinue'
        ]
        try:
            subprocess.run(ps_command, capture_output=True, text=True, check=False,
                           creationflags=subprocess.CREATE_NO_WINDOW)
        except Exception as e:
            self.router_logger.log_message(f"[NAT Setup] ⚠️ Error during NAT cleanup: {e}")

    def _get_default_gateway_for_interface(self, iface_friendly_name: str) -> str | None:
        """
        Parses 'ipconfig /all' and returns the FIRST listed default gateway for the given interface.
        Prefers IPv4 if both IPv4 and IPv6 are shown.
        """
        self.router_logger.log_message(f"[Router] Parsing ipconfig for default gateway of '{iface_friendly_name}'...")
        try:
            result = subprocess.run(["ipconfig", "/all"], capture_output=True, text=True, check=True)
            output = result.stdout

            def extract_first_gateway(adapter_block: list[str]) -> str | None:
                gw_lines_started = False
                candidates: list[str] = []

                for l in adapter_block:
                    # Start capture at the "Default Gateway" line
                    if "Default Gateway" in l:
                        parts = l.split(":", 1)
                        gw_lines_started = True
                        if len(parts) > 1:
                            val = parts[1].strip()
                            if val:
                                candidates.append(val)
                        continue

                    # After the label line, capture subsequent indented lines until blank / next label
                    if gw_lines_started:
                        s = l.strip()
                        if not s:
                            break
                        if ":" in l:  # next labeled field encountered
                            break
                        candidates.append(s)

                if not candidates:
                    return None

                # Prefer the first IPv4, else take the very first candidate
                ipv4_re = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
                for c in candidates:
                    if ipv4_re.search(c):
                        return ipv4_re.search(c).group(0)
                return candidates[0]  # likely IPv6

            current_adapter = None
            adapter_block: list[str] = []

            lines = output.splitlines()
            for line in lines:
                line = line.rstrip()

                # New adapter header?
                if re.match(r"^[A-Z].*adapter .*:$", line):
                    # Process the block we just finished if it was the target
                    if current_adapter == iface_friendly_name and adapter_block:
                        gw = extract_first_gateway(adapter_block)
                        if gw:
                            self.router_logger.log_message(
                                f"[Router] Found default gateway for '{iface_friendly_name}': {gw}"
                            )
                            return gw

                    # Start new block
                    current_adapter = line.strip(":").split("adapter", 1)[-1].strip()
                    adapter_block = []
                else:
                    if current_adapter:
                        adapter_block.append(line)

            # Process the last collected block
            if current_adapter == iface_friendly_name and adapter_block:
                gw = extract_first_gateway(adapter_block)
                if gw:
                    self.router_logger.log_message(
                        f"[Router] Found default gateway for '{iface_friendly_name}': {gw}"
                    )
                    return gw

            self.router_logger.log_message(
                f"[Router] No gateway found for '{iface_friendly_name}' in ipconfig output."
            )
            return None

        except subprocess.CalledProcessError as e:
            self.router_logger.log_message(f"[Router] ❌ Failed to run ipconfig: {e}")
            return None

    def _setup_dynamic_firewall_manager_rules(self):
        """
        Adds firewall rules based on the dynamically configured LAN network.
        """
        if not self.router_network_in:
            self.router_logger.log_message("[Firewall] Skipping dynamic rule setup: LAN network not configured.")
            return

        lan_network_cidr = str(self.router_network_in)
        self.router_logger.log_message(f"[Firewall] Adding dynamic rules for LAN: {lan_network_cidr}")
        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip='any', dst_ip='any',
            src_port='any', dst_port=9999
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip='any', dst_ip='any',
            src_port='any', dst_port=9999
        )
        # Rule 1: Allow all traffic within the LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='any', src_ip=lan_network_cidr, dst_ip=lan_network_cidr,
            src_port='any', dst_port='any'
        )
        # Rule 2: Allow outbound HTTP/HTTPS from LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port=80
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port=443
        )
        # Rule 3: Allow outbound DNS from LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port=53
        )
        # Rule 4: Allow outbound ICMP (ping) from LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='icmp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port='any'
        )
        # Rule 5: Allow inbound traffic for established connections to the LAN
        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip='any', dst_ip=lan_network_cidr,
            src_port='any', dst_port='1024-65535'
        )
        self.firewall_manager.add_rule(
            action='deny', protocol='tcp', src_ip='any', dst_ip=lan_network_cidr, dst_port=22,
        )
        self.firewall_manager.add_rule(
            action='deny', protocol='tcp', src_ip='any', dst_ip=lan_network_cidr, dst_port=3389,
        )
        self.firewall_manager.add_rule(
            action='deny', protocol='tcp', src_ip='any', dst_ip=lan_network_cidr, dst_port=445,
        )
        self.firewall_manager.add_rule(action='permit', protocol='udp', src_ip='0.0.0.0', dst_ip='255.255.255.255',
                                       src_port=68,
                                       dst_port=67)
        self.firewall_manager.add_rule(action='permit', protocol='udp', src_ip='any', dst_ip='255.255.255.255',
                                       src_port=67,
                                       dst_port=68)

        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip=lan_network_cidr, dst_ip='224.0.0.9',
            src_port='any', dst_port=520
        )

        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip='any', dst_ip=lan_network_cidr,
            src_port=520, dst_port='any'
        )

        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip='any', dst_ip='any',
            src_port='any', dst_port=53
        )

        self.firewall_manager.add_rule(
            action='permit', protocol='tcp', src_ip='any', dst_ip='any',
            src_port='any', dst_port=53
        )

        self.firewall_manager.add_rule(
            action='permit', protocol='igmp', src_ip='any', dst_ip='any',
            src_port='any', dst_port='any'  # Ports are 'any' as IGMP doesn't use them
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip='any', dst_ip=lan_network_cidr,
            src_port='any', dst_port=500
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port=500
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip='any', dst_ip=lan_network_cidr,
            src_port='any', dst_port=4500
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port=4500
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='esp', src_ip='any', dst_ip=lan_network_cidr,
            src_port='any', dst_port='any'
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='esp', src_ip=lan_network_cidr, dst_ip='any',
            src_port='any', dst_port='any'
        )
        self.firewall_manager.add_rule(
            action='permit', protocol='udp', src_ip='any', dst_ip=lan_network_cidr,
            src_port='any', dst_port=4500
        )

    def set_default_gateway(self, gateway_ip: str, outbound_iface_name: str) -> bool:
        """
        Sets the default gateway IP and the interface through which to reach it.
        outbound_iface_name here is the full Scapy interface name.
        """
        ok = self._mark_default_gateway_iface(outbound_iface_name, gateway_ip)
        if not ok:
            return False

        # Keep router-facing state in sync with the flag owner.
        if outbound_iface_name == self.interface_out_full_name:
            self.router_gateway_out_ip = gateway_ip

        self.router_logger.log_message(
            f"[Router] Set default gateway: {gateway_ip} via {outbound_iface_name.split('_')[-1]}"
        )
        return True
    def cleanup_all_network_changes(self):
        """Restore only IPv4 adapters modified by this router run."""
        self.router_logger.log_message("\n--- Cleaning up all network changes made by Python Router ---")
        self._remove_firewall_rules()

        changed = dict(self._router_changed_ipv4_aliases)
        self._router_changed_ipv4_aliases.clear()
        if not changed:
            self.router_logger.log_message(
                "[Router] No router-owned IPv4 changes require cleanup."
            )
        for alias_key, previous_mode in changed.items():
            alias = None
            for candidate in psutil.net_if_addrs().keys():
                if str(candidate).strip().casefold() == alias_key:
                    alias = str(candidate)
                    break
            alias = alias or alias_key
            self.router_logger.log_message(
                f"[Router] Cleaning up router-owned IPv4 state on '{alias}' (was {previous_mode})..."
            )
            self._cleanup_interface_ip(alias)

        self.router_logger.log_message("--- Network cleanup complete. ---")

    def _cleanup_interface_ip(self, iface_friendly_name: str):
        """Return a router-modified interface to native DHCP."""
        self.router_logger.log_message(
            f"[Router] Cleaning up IP for '{iface_friendly_name}' (setting to DHCP)...")
        if self._set_interface_dhcp(
                iface_friendly_name,
                reset_dns=True,
                trigger_renew=False,
                record_change=False,
        ):
            self.router_logger.log_message(
                f"[Router] Successfully set '{iface_friendly_name}' to DHCP."
            )
            return True
        self.router_logger.log_message(
            f"[Router] WARNING: Failed to set '{iface_friendly_name}' to DHCP. "
            "The detailed PowerShell/netsh error is shown above."
        )
        return False

    def _get_all_local_ips(self) -> set[str]:
        """
        Returns a comprehensive set of all IPv4 and IPv6 addresses assigned
        to the router's interfaces.
        """
        local_ips = set()
        for config in self._interfaces_config.values():
            # Add the IPv4 address if it exists
            if config.get("ip_addr"):
                local_ips.add(config["ip_addr"])

        local_ips.add(self.router_ipv6_link_local_out)
        return local_ips

    def get_interface_mac(self, iface_full_name: str) -> str:
        """
        Always returns a usable MAC address for the given interface.

        Resolution order:
        - cached value from self.interface_macs
        - Scapy's get_if_hwaddr()
        - Windows interface list
        - netifaces
        - deterministic synthetic MAC fallback

        Notes:
        - Normalizes to lowercase
        - Caches all successful results, including synthetic MACs
        - Logs synthetic MAC generation only once per interface
        """
        try:
            if not hasattr(self, "interface_macs") or self.interface_macs is None:
                self.interface_macs = {}
        except Exception:
            self.interface_macs = {}

        iface_key = str(iface_full_name or "").strip()
        if not iface_key:
            iface_key = "<unknown-iface>"

        # -----------------------------
        # Cache hit
        # -----------------------------
        try:
            cached = self.interface_macs.get(iface_key)
            if cached:
                cached = str(cached).strip().lower()
                if cached and cached != "00:00:00:00:00:00":
                    return cached
        except Exception:
            pass

        def _is_valid_mac(value) -> bool:
            try:
                s = str(value or "").strip().lower()
                if not s or s == "00:00:00:00:00:00":
                    return False
                parts = s.split(":")
                if len(parts) != 6:
                    return False
                for part in parts:
                    if len(part) != 2:
                        return False
                    int(part, 16)
                return True
            except Exception:
                return False

        def _store(mac_value: str) -> str:
            mac_value = str(mac_value).strip().lower()
            try:
                self.interface_macs[iface_key] = mac_value
            except Exception:
                pass
            return mac_value

        # -----------------------------
        # Try Scapy
        # -----------------------------
        try:
            from scapy.all import get_if_hwaddr
            mac = get_if_hwaddr(iface_key)
            if _is_valid_mac(mac):
                return _store(mac)
        except Exception:
            pass

        # -----------------------------
        # Try Windows API
        # -----------------------------
        try:
            from scapy.arch.windows import get_windows_if_list

            iface_key_lower = iface_key.lower()
            for iface in get_windows_if_list():
                candidates = [
                    iface.get("name"),
                    iface.get("win_name"),
                    iface.get("friendlyname"),
                    iface.get("description"),
                    iface.get("guid"),
                ]

                matched = False
                for candidate in candidates:
                    try:
                        if candidate and str(candidate).strip().lower() == iface_key_lower:
                            matched = True
                            break
                    except Exception:
                        continue

                if not matched:
                    continue

                mac = iface.get("mac")
                if _is_valid_mac(mac):
                    return _store(mac)
        except Exception:
            pass

        # -----------------------------
        # Try netifaces
        # -----------------------------
        try:
            import netifaces as ni

            iface_key_lower = iface_key.lower()
            for name in ni.interfaces():
                try:
                    if str(name).strip().lower() != iface_key_lower:
                        continue

                    addrs = ni.ifaddresses(name).get(ni.AF_LINK, [])
                    for addr_info in addrs:
                        mac = addr_info.get("addr")
                        if _is_valid_mac(mac):
                            return _store(mac)
                except Exception:
                    continue
        except Exception:
            pass

        # -----------------------------
        # Final fallback: stable synthetic MAC
        # -----------------------------
        h = abs(hash(iface_key)) & 0xFFFFFFFFFFFF
        fake_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
            (h >> 32) & 0xFF,
            (h >> 24) & 0xFF,
            (h >> 16) & 0xFF,
            (h >> 8) & 0xFF,
            h & 0xFF,
        )

        try:
            self.interface_macs[iface_key] = fake_mac
        except Exception:
            pass

        self.router_logger.log_message(
            RouterRandomMessages(
                name="Router",
                message=f"Synthesized MAC {fake_mac} for iface '{iface_key}'",
                emoticons=["⚠️", "🧪", "🧨", "🧧", "🌡️", "⚗️"],
            )
        )
        return fake_mac

    def _iface_supports_l2(self, iface: str) -> bool:
        # Interfaces that should never be used as an L2 egress
        if iface in ("WinDivertBridge", "WireShark", "Nate's Tunnel"):
            return False
        try:
            return bool(self.get_interface_mac(iface))
        except Exception:
            return False
    def create_l2_bridge(self, bridge_name: str, member_iface_full_names: List[str]) -> bool:
        """
        Public method to create a Layer 2 bridge.
        Args:
            bridge_name: A logical name for the bridge (e.g., "LAN_Bridge").
            member_iface_full_names: List of full Scapy interface names to include in the bridge.
        """
        # Ensure that these interfaces are already discovered and configured with MACs
        for iface_name in member_iface_full_names:
            if iface_name not in self._interfaces_config:
                self.router_logger.log_message(f"[Router] ❌ Cannot add '{iface_name.split('_')[-1]}' to bridge: Interface not configured in router.")
                return False
            # IMPORTANT: Interfaces in a Layer 2 bridge usually should NOT have IP addresses assigned
            # on the OS level, as the bridge itself will have the IP. If they have IPs, it can cause issues.
            # Your current auto-config *will* assign IPs. You might need to adjust this.
            # For a pure Layer 2 bridge, the *bridge* itself would have the IP if it's also a router interface.
            # Here, we'll assume they just pass L2 frames.

        return self.ethernet_manager.create_bridge(bridge_name, member_iface_full_names)

    def remove_l2_bridge(self, bridge_name: str) -> bool:
        """Public method to remove a Layer 2 bridge."""
        return self.ethernet_manager.remove_bridge(bridge_name)

    # --- New Methods for Static Route Management ---


    def get_routing_table(self) -> list[dict]:
        """
        Returns a human-readable list of all entries in the router's routing table.
        """
        return self.rip_manager.get_routing_table_view()

    # --- New Methods for ARP Management ---
    def add_trusted_arp_port(self, iface_full_name: str):
        """Adds an interface to the list of trusted ports for ARP inspection."""
        self.arp_manager.add_trusted_port(iface_full_name)

    def remove_trusted_arp_port(self, iface_full_name: str):
        """Removes an interface from the list of trusted ports for ARP inspection."""
        self.arp_manager.remove_trusted_port(iface_full_name)

    def add_static_arp_entry(self, ip_address: str, mac_address: str):
        """Adds a static ARP entry to the ARP manager."""
        self.arp_manager.add_static_arp_entry(ip_address, mac_address)

    def remove_static_arp_entry(self, ip_address: str):
        """Removes a static ARP entry from the ARP manager."""
        self.arp_manager.remove_static_arp_entry(ip_address)


    # --- New Methods for Outbound Load Balancing ---
    def add_outbound_load_balancing_interface(self, iface_full_name: str):
        """Adds an interface to the pool used for outbound load balancing."""
        self.outbound_load_balancer.add_outbound_interface(iface_full_name)

    def remove_outbound_load_balancing_interface(self, iface_full_name: str):
        """Removes an interface from the pool used for outbound load balancing."""
        self.outbound_load_balancer.remove_outbound_interface(iface_full_name)

    # --- New Methods for Link Aggregation (LAG) ---
    def create_link_aggregation_group(self, lag_name: str, member_interfaces: List[str]) -> bool:
        """
        Creates a new Link Aggregation Group (LAG).
        Args:
            lag_name (str): The logical name for the LAG (e.g., "PortChannel1").
            member_interfaces (List[str]): A list of full Scapy interface names that are part of this LAG.
                                            These interfaces should be configured via add_interface first.
        Returns True if LAG created/updated, False otherwise.
        """
        # Ensure all member interfaces are known physical interfaces
        for member_iface in member_interfaces:
            if member_iface not in self._interfaces_config:
                self.router_logger.log_message(
                    f"[Router] ❌ Cannot create LAG '{lag_name}': Member interface '{member_iface.split('_')[-1]}' is not a known physical interface.")
                return False
        return self.lag_manager.create_lag(lag_name, member_interfaces)

    def remove_link_aggregation_group(self, lag_name: str) -> bool:
        """Removes a Link Aggregation Group."""
        return self.lag_manager.remove_lag(lag_name)

    # --- New Methods for Firewall Management ---
    def add_firewall_rule(self, action: str, protocol: str = 'any', src_ip: str = 'any', dst_ip: str = 'any',
                          src_port: Any = 'any', dst_port: Any = 'any', position: int = None) -> bool:
        """Adds a new firewall rule to the FirewallManager."""
        return self.firewall_manager.add_rule(action, protocol, src_ip, dst_ip, src_port, dst_port, position)

    def remove_firewall_rule(self, index: int) -> bool:
        """Removes a firewall rule from the FirewallManager by its index."""
        return self.firewall_manager.remove_rule(index)

    def get_firewall_rules(self) -> List[Dict[str, Any]]:
        """Returns the current list of firewall rules."""
        return self.firewall_manager.get_rules()






class PacketManager:
    """
    Packet builder + direct sender + router injector.

    If self.router is bound and has process_packet(), packets are injected into
    the router pipeline using the selected interface as the inbound interface.
    Otherwise the manager falls back to direct Scapy send/sr1 behavior.

    Public send_* signatures are preserved so PacketSendingThread can stay unchanged.
    """

    def __init__(self, packet_logger):
        self.packet_logger = packet_logger
        self._tshark_interfaces = []
        self._tshark_path = None
        self.router = None
        self.sniffer = None
        self._initialize_interface_discovery()
        self.packet_logger.log_message("[PacketManager] Initialized and ready.")

    def set_router(self, router_instance):
        self.router = router_instance
        if router_instance is None:
            self.packet_logger.log_message("[PacketManager] Router binding cleared.")
        else:
            self.packet_logger.log_message(
                f"[PacketManager] Router bound: {router_instance.__class__.__name__}"
            )

    def get_interfaces(self) -> List[dict]:
        """
        Prefer router-discovered interfaces when a router is bound and has them,
        otherwise use PacketManager discovery.
        """
        try:
            if self.router and hasattr(self.router, "_discovered_tshark_interfaces"):
                router_ifaces = getattr(self.router, "_discovered_tshark_interfaces", None)
                if router_ifaces:
                    return list(router_ifaces)
        except Exception:
            pass
        return self._tshark_interfaces

    def _get_tshark_path(self) -> Optional[str]:
        if getattr(sys, "frozen", False):
            tshark_exe = Path(sys._MEIPASS) / "tools" / "Wireshark" / "tshark.exe"
            if tshark_exe.exists():
                return str(tshark_exe)

        server_dir = Path(__file__).resolve().parent
        project_root = server_dir.parent
        tools_dir = project_root / "client" / "tools" / "Wireshark"
        candidate = tools_dir / "tshark.exe"
        if candidate.exists():
            return str(candidate)

        system_tshark = shutil.which("tshark")
        if system_tshark:
            return system_tshark

        self.packet_logger.log_message("[PacketManager] Error: tshark.exe not found.")
        return None

    def _initialize_interface_discovery(self):
        self._tshark_path = self._get_tshark_path()
        if not self._tshark_path:
            return

        self.packet_logger.log_message("[PacketManager] Discovering network interfaces via tshark -D...")
        try:
            proc = subprocess.run(
                [self._tshark_path, "-D"],
                capture_output=True,
                text=True,
                check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            pattern = re.compile(r"(\d+)\.\s+([^(]+)(?:\((.*)\))?")
            self._tshark_interfaces.clear()

            for line in proc.stdout.strip().split("\n"):
                match = pattern.match(line)
                if match:
                    self._tshark_interfaces.append({
                        "id": match.group(1),
                        "full_name": match.group(2).strip(),
                        "friendly_name": match.group(3).strip() if match.group(3) else match.group(2).strip()
                    })

            self.packet_logger.log_message(
                f"[PacketManager] Discovered {len(self._tshark_interfaces)} interfaces."
            )
        except Exception as e:
            self.packet_logger.log_message(f"[PacketManager] Error during interface discovery: {e}")

    def _resolve_inbound_iface(self, iface: Optional[str]) -> Optional[str]:
        """
        Accept either full tshark/scapy name or friendly name and return the
        full inbound interface name that router.process_packet expects.
        """
        if not iface:
            try:
                if self.router:
                    for cand in (
                        getattr(self.router, "interface_in_full_name", None),
                        getattr(self.router, "interface_loopback_full_name", None),
                        getattr(self.router, "interface_ethernet_2_full_name", None),
                        getattr(self.router, "interface_lac_full_name", None),
                        getattr(self.router, "interface_lac_2_full_name", None),
                    ):
                        if cand:
                            return cand
            except Exception:
                pass
            return None

        iface_str = str(iface).strip()

        # Exact full-name match
        for item in self.get_interfaces():
            if str(item.get("full_name", "")).strip() == iface_str:
                return iface_str

        # Friendly-name match
        iface_lower = iface_str.lower()
        for item in self.get_interfaces():
            if str(item.get("friendly_name", "")).strip().lower() == iface_lower:
                return item.get("full_name")

        return iface_str

    def _can_use_router(self) -> bool:
        return self.router is not None and hasattr(self.router, "process_packet")

    def _inject_into_router(self, packet: Packet, iface: Optional[str], desc: str) -> Tuple[str, Optional[Packet]]:
        """
        Push a built packet into the router ingress pipeline.
        """
        if not self._can_use_router():
            return "NO_ROUTER", None

        inbound_iface = self._resolve_inbound_iface(iface)
        if not inbound_iface:
            self.packet_logger.log_message(
                f"[PacketManager] No inbound iface resolved for router injection ({desc})."
            )
            return "NO_INTERFACE", None

        try:
            pkt = packet

            # Reuse router coercion if present
            coerce = getattr(self.router, "_coerce_ingress_packet", None)
            if callable(coerce):
                coerced = coerce(packet)
                if coerced is not None:
                    pkt = coerced

            self.router.process_packet(pkt, inbound_iface)
            self.packet_logger.log_message(
                f"[PacketManager] Injected {desc} into router via {inbound_iface.split('_')[-1]}"
            )
            return "ROUTED", pkt

        except Exception as e:
            self.packet_logger.log_message(
                f"[PacketManager] Router injection failed for {desc}: {e}"
            )
            return "ERROR", None

    @staticmethod
    def _is_router_sniffer_method(method: Any) -> bool:
        """Return True only for this project's routed SnifferSoftware methods.

        Generic Scapy L3 send()/sr1() accepts an ``iface`` keyword for legacy
        compatibility but warns that it has no effect.  The local
        SnifferSoftware methods intentionally accept ``iface`` because they
        resolve a Windows/Npcap route and construct an Ethernet frame.
        """
        try:
            module_name = str(getattr(method, "__module__", "") or "")
            owner = getattr(method, "__self__", None)
            owner_module = str(getattr(type(owner), "__module__", "") or "") if owner is not None else ""
            return module_name == "p2pool_sniffer" or owner_module == "p2pool_sniffer"
        except Exception:
            return False

    def _direct_sr1(self, packet: Packet, iface: Optional[str], timeout: int):
        """Use the routed sniffer when present; otherwise use pure Scapy L3 I/O.

        ``iface`` is never passed to generic Scapy ``sr1``.  For L3 I/O Scapy
        selects the egress path from its route table and the packet source.
        Multicast/link-local packets that require an exact adapter are handled
        by SnifferSoftware's L2/Npcap implementation instead.
        """
        try:
            method = getattr(self.sniffer, "sr1", None) if self.sniffer is not None else None
            if callable(method) and self._is_router_sniffer_method(method):
                return method(packet, timeout=timeout, verbose=0, iface=iface)
        except Exception:
            pass

        return sr1(packet, timeout=timeout, verbose=0)

    def _direct_send(self, packet: Packet, iface: Optional[str]) -> None:
        """Send through SnifferSoftware or generic Scapy without invalid iface use."""
        try:
            method = getattr(self.sniffer, "send", None) if self.sniffer is not None else None
            if callable(method) and self._is_router_sniffer_method(method):
                method(packet, iface=iface, verbose=0)
                return
        except Exception:
            pass

        # Generic Scapy send() is Layer 3.  Passing iface= emits the warning:
        # "'iface' has no effect on L3 I/O send()".  Route selection belongs to
        # Scapy's route table; exact-interface multicast/link-local traffic must
        # use the project's sendp()/srp1() path instead.
        send(packet, verbose=0)

    @staticmethod
    def _decode_packetlab_payload(value, encoding: str) -> bytes:
        text = str(value or "")
        mode = str(encoding or "UTF-8").strip().casefold()
        if mode in {"hex", "hexadecimal"}:
            compact = re.sub(r"[^0-9a-fA-F]", "", text)
            if len(compact) % 2:
                raise ValueError("Hex payload must contain complete byte pairs.")
            return bytes.fromhex(compact)
        if mode in {"base64", "b64"}:
            return base64.b64decode(text, validate=True)
        return text.encode("utf-8")

    @staticmethod
    def _resolve_packetlab_target(host: str, ip_version: int) -> str:
        text = str(host or "").strip()
        if not text:
            raise ValueError("PacketLab target is required.")
        try:
            parsed = ipaddress.ip_address(text.split("%", 1)[0])
        except ValueError as original:
            if any(ch.isalpha() for ch in text):
                family = socket.AF_INET6 if ip_version == 6 else socket.AF_INET
                results = socket.getaddrinfo(text, None, family, socket.SOCK_STREAM)
                if not results:
                    raise ValueError(f"Could not resolve hostname: {text}")
                return str(results[0][4][0]).split("%", 1)[0]
            raise original
        if parsed.version != ip_version:
            raise ValueError(f"Target is IPv{parsed.version}, but IPv{ip_version} was selected.")
        return str(parsed)

    def build_packetlab_packet(self, config: dict) -> Packet:
        config = dict(config or {})
        version_text = str(config.get("ip_version") or "IPv4").casefold()
        ip_version = 6 if "6" in version_text else 4
        protocol = str(config.get("protocol") or "TCP").strip().casefold()
        target_value = config.get("dns_server") if protocol == "dns" else config.get("target")
        target = self._resolve_packetlab_target(target_value, ip_version)
        source = str(config.get("source") or "").strip()
        if source:
            source = str(ipaddress.ip_address(source.split("%", 1)[0]))
            if ipaddress.ip_address(source).version != ip_version:
                raise ValueError("Source address version does not match the selected IP version.")
        ttl = max(1, min(255, int(config.get("ttl") or 64)))
        network_layer = IPv6(dst=target, hlim=ttl) if ip_version == 6 else IP(dst=target, ttl=ttl)
        if source:
            network_layer.src = source

        source_port = int(config.get("source_port") or 0)
        if not source_port:
            source_port = 49152 + (int(time.time() * 1000) % 16000)
        dest_port = int(config.get("dest_port") or 0)
        payload = self._decode_packetlab_payload(
            config.get("payload") or "", config.get("payload_encoding") or "UTF-8"
        )

        if protocol == "tcp":
            if not 1 <= dest_port <= 65535:
                raise ValueError("TCP destination port must be between 1 and 65535.")
            flags = str(config.get("tcp_flags") or "S").strip().upper() or "S"
            packet = network_layer / TCP(sport=source_port, dport=dest_port, flags=flags)
            if payload:
                packet /= Raw(load=payload)
            return packet
        if protocol == "udp":
            if not 1 <= dest_port <= 65535:
                raise ValueError("UDP destination port must be between 1 and 65535.")
            packet = network_layer / UDP(sport=source_port, dport=dest_port)
            if payload:
                packet /= Raw(load=payload)
            return packet
        if protocol == "dns":
            query_name = str(config.get("dns_name") or config.get("target") or "").strip()
            if not query_name:
                raise ValueError("DNS query name is required.")
            query_type = str(config.get("dns_type") or "A").strip().upper()
            dns_transport = str(config.get("dns_transport") or "UDP").strip().upper()
            dest_port = dest_port or 53
            l4 = TCP(sport=source_port, dport=dest_port, flags="PA") if dns_transport == "TCP" else UDP(sport=source_port, dport=dest_port)
            return network_layer / l4 / DNS(rd=1, qd=DNSQR(qname=query_name, qtype=query_type))
        if protocol in {"icmp", "icmpv4", "icmpv6"}:
            packet = network_layer / (ICMPv6EchoRequest() if ip_version == 6 else ICMP())
            if payload:
                packet /= Raw(load=payload)
            return packet
        if protocol in {"raw", "raw ip", "ip"}:
            if payload:
                return network_layer / Raw(load=payload)
            return network_layer
        raise ValueError(f"Unsupported PacketLab protocol: {protocol}")

    def send_packetlab(self, config: dict) -> Tuple[str, Optional[Packet]]:
        config = dict(config or {})
        packet = self.build_packetlab_packet(config)
        iface = str(config.get("iface") or "CodeOutput").strip() or "CodeOutput"
        route_via_codeoutput = bool(config.get("route_via_codeoutput", True))
        self.packet_logger.log_message(
            f"[PacketLab] Built {packet.summary()} via {iface}; codeoutput={route_via_codeoutput}."
        )
        if route_via_codeoutput and self.router is not None and hasattr(self.router, "inject_codeoutput_packet"):
            result = self.router.inject_codeoutput_packet(
                packet,
                metadata={
                    "packetlab_protocol": str(config.get("protocol") or ""),
                    "packetlab_target": str(config.get("target") or config.get("dns_server") or ""),
                },
            )
            self.packet_logger.log_message(
                f"[PacketLab] Routed through CodeOutputInterface: {result.get('summary', packet.summary())}"
            )
            return "ROUTED_CODEOUTPUT", packet
        if self._can_use_router():
            return self._inject_into_router(packet, iface, f"PacketLab {packet.summary()}")
        self._direct_send(packet, iface)
        return "SENT", packet

    def send_ping(
        self,
        target_ip: str,
        iface: str,
        src_ip: Optional[str] = None,
        timeout: int = 2
    ) -> Tuple[str, Optional[Packet]]:
        self.packet_logger.log_message(f"[PacketManager] Sending Ping to {target_ip} via {iface}...")

        try:
            packet = IP(dst=target_ip)
            if src_ip:
                packet.src = src_ip
            packet /= ICMP()

            if self._can_use_router():
                return self._inject_into_router(packet, iface, f"ICMP Echo to {target_ip}")

            response = self._direct_sr1(packet, iface, timeout)
            if response is None:
                return "TIMEOUT", None
            if response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
                return "REPLY", response
            return "UNEXPECTED_RESPONSE", response

        except Exception as e:
            self.packet_logger.log_message(f"[Ping] Error sending on {iface}: {e}")
            return "ERROR", None

    def send_tcp_syn(
        self,
        target_ip: str,
        target_port: int,
        iface: str,
        src_ip: Optional[str] = None,
        timeout: int = 2
    ) -> Tuple[str, Optional[Packet]]:
        self.packet_logger.log_message(
            f"[PacketManager] Sending TCP SYN to {target_ip}:{target_port} via {iface}..."
        )

        try:
            packet = IP(dst=target_ip)
            if src_ip:
                packet.src = src_ip
            packet /= TCP(dport=target_port, sport=54321, flags="S")

            if self._can_use_router():
                return self._inject_into_router(packet, iface, f"TCP SYN to {target_ip}:{target_port}")

            response = self._direct_sr1(packet, iface, timeout)

            if response is None:
                return "FILTERED", None

            if response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)

                if tcp_layer.flags == 0x12:  # SYN+ACK
                    rst_src_ip = response[IP].dst
                    rst_packet = IP(dst=target_ip, src=rst_src_ip) / TCP(
                        dport=target_port,
                        sport=packet[TCP].sport,
                        flags="R",
                        seq=tcp_layer.ack
                    )
                    self._direct_send(rst_packet, iface)
                    return "OPEN", response

                if tcp_layer.flags & 0x04:
                    return "CLOSED", response

            return "UNEXPECTED_RESPONSE", response

        except Exception as e:
            self.packet_logger.log_message(f"[TCP-SYN] Error sending on {iface}: {e}")
            return "ERROR", None

    def send_udp_packet(
        self,
        target_ip: str,
        target_port: int,
        payload: bytes,
        iface: str,
        src_ip: Optional[str] = None,
        timeout: int = 2
    ) -> Tuple[str, Optional[Packet]]:
        self.packet_logger.log_message(
            f"[PacketManager] Sending UDP to {target_ip}:{target_port} via {iface}..."
        )

        try:
            packet = IP(dst=target_ip)
            if src_ip:
                packet.src = src_ip
            packet /= UDP(dport=target_port, sport=54322) / payload

            if self._can_use_router():
                return self._inject_into_router(packet, iface, f"UDP to {target_ip}:{target_port}")

            response = self._direct_sr1(packet, iface, timeout)
            if response is None:
                return "NO_RESPONSE", None
            if response.haslayer(ICMP):
                return "ICMP_RESPONSE", response
            return "REPLY", response

        except Exception as e:
            self.packet_logger.log_message(f"[UDP] Error sending on {iface}: {e}")
            return "ERROR", None

    def send_dns_query(
        self,
        dns_server: str,
        domain: str,
        record_type: str,
        iface: str,
        src_ip: Optional[str] = None,
        timeout: int = 2
    ) -> Tuple[str, Optional[Packet]]:
        self.packet_logger.log_message(
            f"[PacketManager] Sending DNS Query for {domain} ({record_type}) to {dns_server} via {iface}..."
        )

        try:
            packet = IP(dst=dns_server)
            if src_ip:
                packet.src = src_ip
            packet /= UDP(dport=53, sport=54323) / DNS(
                rd=1,
                qd=DNSQR(qname=domain, qtype=record_type)
            )

            if self._can_use_router():
                return self._inject_into_router(packet, iface, f"DNS {record_type} query for {domain}")

            response = self._direct_sr1(packet, iface, timeout)
            if response is None:
                return "TIMEOUT", None
            if response.haslayer(DNS):
                return "REPLY", response
            return "UNEXPECTED_RESPONSE", response

        except Exception as e:
            self.packet_logger.log_message(f"[DNS] Error sending on {iface}: {e}")
            return "ERROR", None

class WiresharkManager:


    def __init__(self, p2pool_data, logger):
        self.p2pool_data = p2pool_data
        self.logger = logger
        self.tshark_procs = {}
        self.redirect_threads = {}
        self.stderr_threads = {}
        self.stop_event = threading.Event()
        self.geoip_reader = None
        self._decompressed_db_path = None

        # Stateful correlation engine.
        self.correlation_lock = threading.Lock()
        self.stream_map = {}
        self.loopback_interface_id = None
        self.vpn_interface_id = None
        self.min_packet_len = 0
        self.router_manager = None

        # Live-capture bookkeeping.  tshark is intentionally kept outside the
        # Qt thread; all packet and stderr readers are bounded daemon threads.
        self._capture_lock = threading.RLock()
        self._capture_iface_names = {}
        self._capture_commands = {}
        self._stderr_tail = collections.defaultdict(lambda: deque(maxlen=40))
        self._capture_stats = collections.defaultdict(lambda: {
            "packets": 0,
            "stdout_lines": 0,
            "stdout_bytes": 0,
            "parse_errors": 0,
            "empty_records": 0,
            "stderr_lines": 0,
            "router_accepted": 0,
            "router_rejected": 0,
            "started_at": 0.0,
            "last_packet_at": 0.0,
        })
        self._status_thread = None
        self._status_interval = 5.0
        self._last_status_total = -1
        self._last_status_log = 0.0

        self._capture_settings = {
            "main_interface": "Auto",
            "include_loopback": True,
            "include_vpn": True,
            "include_multicast": False,
            "include_discovery": False,
            "include_dhcp": True,
            "include_localhost": True,
            "promiscuous": True,
            "full_details": True,
            "feed_router": False,
            "log_packet_summaries": False,
            "log_payloads": False,
            "log_filtered_packets": False,
            "min_packet_len": 0,
            "max_interfaces": 8,
            "custom_bpf": "",
        }

    def _looks_like_json_text(self, value: str) -> bool:
        s = str(value or "").lstrip()
        if not s:
            return False
        if s.startswith("{") or s.startswith("["):
            return True
        if '"jsonrpc"' in s or '"method"' in s or '"params"' in s:
            return True
        if '"id"' in s and '"result"' in s:
            return True
        return False

    def _looks_like_xml_or_http_text(self, value: str) -> bool:
        s = str(value or "").lstrip()
        if not s:
            return False
        if s.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/")):
            return True
        if s.startswith("<") or s.startswith("<?xml"):
            return True
        if "</" in s or "<root" in s or "<html" in s or "<device" in s:
            return True
        return False

    def _decode_best_payload_text(self, payload_bytes: bytes) -> str:
        if not payload_bytes:
            return ""
        for enc in ("utf-8", "utf-16", "latin-1"):
            try:
                txt = payload_bytes.decode(enc, errors="replace")
                if txt:
                    return txt
            except Exception:
                pass
        return ""

    def _classify_application_layer(
            self,
            layers: Dict[str, Any],
            payload_bytes: bytes,
            src_ip: str = "",
            dst_ip: str = "",
            src_port: int | str = 0,
            dst_port: int | str = 0,
            interface_id: str = "",
    ) -> tuple[str, str]:
        """
        Returns (app_layer, detail).

        app_layer examples:
          HTTP, HTTP2, WS, TLS, QUIC, DNS, MDNS, SSDP, DHCP, DHCPv6, NTP, STUN,
          TURN, JSON, JSON-RPC, XML, SOAP, MQTT, AMQP, Redis, Memcached, RTP,
          RTSP, SIP, SMB, LDAP, KERBEROS, RDP, IKEv2, WireGuard, BitTorrent,
          STRATUM, MONERO, TEXT, BINARY, UNKNOWN
        """
        sp = self._as_int(src_port, 0) or 0
        dp = self._as_int(dst_port, 0) or 0
        ports = {sp, dp}
        text = self._decode_best_payload_text(payload_bytes) if payload_bytes else ""
        text_l = text.lstrip() if text else ""
        text_lower = text_l.lower() if text_l else ""
        payload_len = len(payload_bytes or b"")

        def has_layer(*names: str) -> bool:
            return any(name in layers for name in names)

        def first_layer(*names: str):
            for name in names:
                if name in layers:
                    return layers.get(name)
            return {}

        def starts_with_bytes(prefix: bytes) -> bool:
            return bool(payload_bytes and payload_bytes.startswith(prefix))

        def contains_bytes(fragment: bytes) -> bool:
            return bool(payload_bytes and fragment in payload_bytes)

        # ----------------------------
        # 1) tshark-decoded high confidence protocols
        # ----------------------------

        if has_layer("http2"):
            h2 = first_layer("http2")
            stream_id = ""
            if isinstance(h2, dict):
                stream_id = str(h2.get("http2.streamid", "") or "")
            if "content-type" in text_lower and "application/grpc" in text_lower:
                return "gRPC", f"http2 stream={stream_id}".strip()
            return "HTTP2", f"stream={stream_id}".strip() if stream_id else "http2"

        if has_layer("websocket"):
            ws = first_layer("websocket")
            opcode = ""
            if isinstance(ws, dict):
                opcode = str(ws.get("websocket.opcode", "") or "")
            return "WS", f"opcode={opcode}" if opcode else "websocket"

        if has_layer("http"):
            http = first_layer("http")
            if isinstance(http, dict):
                if "http.request.method" in http:
                    method = http.get("http.request.method", "")
                    host = http.get("http.host", "")
                    uri = http.get("http.request.full_uri", "") or http.get("http.request.uri", "")
                    detail = f"request {method}".strip()
                    if host or uri:
                        detail += f" host={host} uri={uri}".strip()
                    return "HTTP", detail.strip()
                if "http.response.code" in http:
                    code = http.get("http.response.code", "")
                    return "HTTP", f"response {code}".strip()
            return "HTTP", "http"

        if has_layer("tls", "ssl"):
            tls = first_layer("tls", "ssl")
            if isinstance(tls, dict):
                sni = str(tls.get("tls.handshake.extensions_server_name", "") or "")
                content_type = str(tls.get("tls.record.content_type", "") or "")
                handshake_type = str(tls.get("tls.handshake.type", "") or "")
                version = str(
                    tls.get("tls.record.version", "") or
                    tls.get("tls.handshake.version", "") or
                    ""
                )
                bits = []
                if sni:
                    bits.append(f"sni={sni}")
                if handshake_type:
                    bits.append(f"hs={handshake_type}")
                if version:
                    bits.append(f"ver={version}")
                if content_type:
                    bits.append(f"ct={content_type}")
                return "TLS", " ".join(bits).strip() if bits else "tls"
            return "TLS", "tls"

        if has_layer("quic"):
            quic = first_layer("quic")
            if isinstance(quic, dict):
                version = str(quic.get("quic.version", "") or "")
                dcid = str(quic.get("quic.dcid", "") or "")
                bits = []
                if version:
                    bits.append(f"ver={version}")
                if dcid:
                    bits.append(f"dcid={dcid}")
                return "QUIC", " ".join(bits).strip() if bits else "quic"
            return "QUIC", "quic"

        if has_layer("dns"):
            dns = first_layer("dns")
            qname = ""
            qtype = ""
            if isinstance(dns, dict):
                qname = str(dns.get("dns.qry.name", "") or "")
                qtype = str(dns.get("dns.qry.type", "") or "")
            if 5353 in ports:
                return "MDNS", qname or "mdns"
            if 5355 in ports:
                return "LLMNR", qname or "llmnr"
            return "DNS", f"{qname} ({qtype})".strip() if (qname or qtype) else "dns"

        if has_layer("nbns"):
            return "NBNS", "netbios-name-service"

        if has_layer("ssdp"):
            return "SSDP", "ssdp"

        if has_layer("dhcp"):
            return "DHCP", "dhcp"

        if has_layer("dhcpv6"):
            return "DHCPv6", "dhcpv6"

        if has_layer("ntp"):
            return "NTP", "ntp"

        if has_layer("stun"):
            stun = first_layer("stun")
            if isinstance(stun, dict):
                klass = str(stun.get("stun.class", "") or "")
                method = str(stun.get("stun.method", "") or "")
                detail = " ".join(x for x in (klass, method) if x).strip()
                return "STUN", detail or "stun"
            return "STUN", "stun"

        if has_layer("turnchannel", "turn"):
            return "TURN", "turn"

        if has_layer("rtp"):
            return "RTP", "rtp"

        if has_layer("rtcp"):
            return "RTCP", "rtcp"

        if has_layer("sip"):
            sip = first_layer("sip")
            if isinstance(sip, dict):
                method = str(sip.get("sip.Method", "") or sip.get("sip.method", "") or "")
                return "SIP", method or "sip"
            return "SIP", "sip"

        if has_layer("rtsp"):
            return "RTSP", "rtsp"

        if has_layer("mqtt"):
            mqtt = first_layer("mqtt")
            if isinstance(mqtt, dict):
                msgtype = str(mqtt.get("mqtt.msgtype", "") or "")
                return "MQTT", f"type={msgtype}" if msgtype else "mqtt"
            return "MQTT", "mqtt"

        if has_layer("amqp"):
            return "AMQP", "amqp"

        if has_layer("redis"):
            return "Redis", "resp"

        if has_layer("memcache"):
            return "Memcached", "memcache"

        if has_layer("ldap"):
            return "LDAP", "ldap"

        if has_layer("kerberos"):
            return "KERBEROS", "kerberos"

        if has_layer("smb", "smb2"):
            return "SMB", "smb"

        if has_layer("rdp", "tpkt", "t125"):
            return "RDP", "rdp"

        if has_layer("isakmp", "ikev2"):
            return "IKEv2", "ike"

        if has_layer("bittorrent"):
            return "BitTorrent", "bittorrent"

        # ----------------------------
        # 2) Strong port heuristics + binary signatures
        # ----------------------------

        # QUIC usually UDP/443 with long-header patterns
        if "udp" in layers and 443 in ports and payload_len >= 1:
            first = payload_bytes[0]
            if first & 0x40 or first & 0x80:
                return "QUIC", f"udp/443 first=0x{first:02x}"

        # WireGuard: common ports 51820/udp etc. First message type byte often 1..4 in little-endian format
        if "udp" in layers and any(p in ports for p in {51820, 51821, 51822}) and payload_len >= 4:
            msg_type = int.from_bytes(payload_bytes[:4], "little", signed=False)
            if msg_type in {1, 2, 3, 4}:
                return "WireGuard", f"msg_type={msg_type}"

        # STUN magic cookie 0x2112A442 at bytes 4:8
        if "udp" in layers and payload_len >= 20 and payload_bytes[4:8] == b"\x21\x12\xa4\x42":
            return "STUN", "magic-cookie"

        # TLS handshake records
        if payload_len >= 5:
            content_type = payload_bytes[0]
            version_major = payload_bytes[1]
            version_minor = payload_bytes[2]
            if content_type in {20, 21, 22, 23, 24} and version_major == 3:
                if content_type == 22 and payload_len >= 6:
                    hs_type = payload_bytes[5]
                    hs_name = {
                        1: "client_hello",
                        2: "server_hello",
                        11: "certificate",
                        12: "server_key_exchange",
                        14: "server_hello_done",
                        16: "client_key_exchange",
                        20: "finished",
                    }.get(hs_type, f"hs={hs_type}")
                    return "TLS", hs_name
                return "TLS", f"record_type={content_type}"

        # HTTP/2 client preface
        if payload_bytes.startswith(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"):
            return "HTTP2", "client-preface"

        # WebSocket upgrade visible in HTTP headers
        if "upgrade: websocket" in text_lower or "sec-websocket-key:" in text_lower:
            return "WS", "http-upgrade"

        # SSDP / UPnP
        if 1900 in ports and (
                text_l.startswith("M-SEARCH ") or
                text_l.startswith("NOTIFY ") or
                "ssdp:discover" in text_lower
        ):
            return "SSDP", "upnp"

        # SIP text signaling
        if 5060 in ports and (
                text_l.startswith(("INVITE ", "REGISTER ", "ACK ", "BYE ", "OPTIONS ", "SIP/2.0"))
        ):
            return "SIP", "sip-text"

        # RTSP text
        if 554 in ports and (
                text_l.startswith(("OPTIONS ", "DESCRIBE ", "SETUP ", "PLAY ", "PAUSE ", "TEARDOWN ", "RTSP/"))
        ):
            return "RTSP", "rtsp-text"

        # MQTT fixed header heuristic
        if payload_len >= 2 and any(p in ports for p in {1883, 8883}):
            packet_type = (payload_bytes[0] >> 4) & 0x0F
            if 1 <= packet_type <= 14:
                return "MQTT", f"type={packet_type}"

        # Redis RESP
        if text_l.startswith(("*", "+", "-", ":", "$")) and any(
                token in text_l[:64] for token in ["\r\n", "PING", "SET", "GET", "INFO", "AUTH"]
        ):
            if any(p in ports for p in {6379, 6380}):
                return "Redis", "resp"

        # Memcached ASCII
        if any(p in ports for p in {11211, 11212}) and text_l.startswith(
                ("get ", "set ", "add ", "replace ", "delete ", "incr ", "decr ", "VALUE ", "STAT ")
        ):
            return "Memcached", "ascii"

        # BitTorrent handshake
        if payload_len >= 20 and payload_bytes[:20].startswith(b"\x13BitTorrent protocol"):
            return "BitTorrent", "handshake"

        # ----------------------------
        # 3) Mining / Monero / Stratum heuristics
        # ----------------------------

        if self._looks_like_json_text(text_l):
            try:
                obj = json.loads(text_l)
                if isinstance(obj, dict):
                    if "jsonrpc" in obj:
                        method = str(obj.get("method", "") or "")
                        params = obj.get("params", {})
                        method_l = method.lower()

                        if method_l in {"login", "submit", "job", "keepalived", "submit_hashrate"}:
                            return "STRATUM", f"method={method}" if method else "stratum-jsonrpc"

                        if method_l in {"get_block_template", "submit_block", "get_info", "get_height"}:
                            return "MONERO", f"rpc={method}"

                        if "blob" in str(text_l) and "target" in str(text_l):
                            return "STRATUM", f"method={method or 'job'}"

                        return "JSON-RPC", f"method={method}" if method else "json-rpc"

                    if "method" in obj and "params" in obj:
                        method = str(obj.get("method", "") or "")
                        if method.lower() in {"mining.subscribe", "mining.authorize", "mining.notify", "mining.submit"}:
                            return "STRATUM", f"method={method}"
                        return "JSON", "method+params"

                    if "id" in obj and ("result" in obj or "error" in obj):
                        if any(k in text_lower for k in ("job", "blob", "target", "seed_hash", "height")):
                            return "STRATUM", "result"
                        return "JSON", "id+result"
            except Exception:
                pass

        # Binary Monero/P2Pool-ish heuristic
        if any(p in ports for p in
               {18080, 28080, 38080, 41257, 37888, 37889, 3333, 4444, 5555, 6666, 7777, 8888, 9999}):
            if payload_len:
                if text_l and any(tok in text_lower for tok in
                                  ("jsonrpc", "login", "submit", "job", "blob", "target", "seed_hash")):
                    return "STRATUM", "port+json"
                if contains_bytes(b"top_id") or contains_bytes(b"rpc_port") or contains_bytes(b"pruning_seed"):
                    return "MONERO", "portable-storage-ish"
                return "BINARY", f"mining-port {payload_len} bytes"

        # ----------------------------
        # 4) XML / SOAP / HTTP-ish / plain text
        # ----------------------------

        if "xml" in layers or (text_l and (text_l.startswith("<?xml") or text_l.startswith("<"))):
            if "soap" in text_lower or ":envelope" in text_lower:
                return "SOAP", "xml-soap"
            return "XML", "xml"

        if self._looks_like_json_text(text_l):
            try:
                obj = json.loads(text_l)
                if isinstance(obj, dict):
                    if "jsonrpc" in obj:
                        method = obj.get("method", "")
                        return "JSON-RPC", f"method={method}" if method else "json-rpc"
                    if "method" in obj and "params" in obj:
                        return "JSON", "method+params"
                    if "type" in obj:
                        return "JSON", f"type={obj.get('type')}"
                return "JSON", type(obj).__name__
            except Exception:
                return "JSON", "json-text"

        if self._looks_like_xml_or_http_text(text_l):
            if text_l.startswith(("GET ", "POST ", "PUT ", "DELETE ", "HEAD ", "OPTIONS ", "PATCH ", "HTTP/")):
                return "HTTP", "http-text"
            if text_l.startswith("<") or text_l.startswith("<?xml"):
                return "XML", "xml-ish"

        # ----------------------------
        # 5) Generic text / binary fallback
        # ----------------------------

        if text_l:
            printable = sum(1 for ch in text[: min(len(text), 256)] if ch.isprintable() or ch in "\r\n\t")
            sample_len = max(1, min(len(text), 256))
            ratio = printable / sample_len
            if ratio > 0.85:
                return "TEXT", f"printable={ratio:.2f}"

        if payload_bytes:
            entropy_hint = self._rough_entropy(payload_bytes[:512])
            if entropy_hint >= 7.2:
                return "BINARY", f"high-entropy {payload_len} bytes"
            return "BINARY", f"{payload_len} bytes"

        return "UNKNOWN", ""

    def _rough_entropy(self, data: bytes) -> float:
        if not data:
            return 0.0
        from math import log2
        counts = {}
        for b in data:
            counts[b] = counts.get(b, 0) + 1
        total = len(data)
        ent = 0.0
        for c in counts.values():
            p = c / total
            ent -= p * log2(p)
        return ent

    def _extract_best_payload_bytes(self, layers: Dict[str, Any]) -> Optional[bytes]:
        """
        Best-effort payload extraction from tshark JSON.
        Prefers true hex payloads, then falls back to JSON / XML / HTTP / text-ish fields.
        """

        def _hex_from(value) -> Optional[bytes]:
            if not isinstance(value, str) or not value:
                return None
            return self._hexdump_to_bytes(value)

        def _text_to_bytes(value) -> Optional[bytes]:
            if isinstance(value, list):
                value = "\n".join(str(x) for x in value if x is not None)
            if not isinstance(value, str):
                return None
            s = value.strip()
            if not s:
                return None
            try:
                return s.encode("utf-8", errors="ignore")
            except Exception:
                return None

        tcp = layers.get("tcp", {})
        udp = layers.get("udp", {})
        data = layers.get("data", {})

        # 1) Preferred raw hex payload sources
        for key, src in (
                ("tcp.payload", tcp),
                ("udp.payload", udp),
                ("data.data", data),
        ):
            blob = _hex_from(src.get(key))
            if blob:
                return blob

        # 2) High-level text carriers, now including JSON
        for layer_name, key_names in (
                ("json", None),
                ("jsonvalue", None),
                ("data-text-lines", None),
                ("http", (
                        "http.file_data",
                        "http.request.line",
                        "http.response.line",
                        "http.request.full_uri",
                )),
                ("xml", None),
                ("line-based-text-data", None),
                ("text", None),
        ):
            layer_obj = layers.get(layer_name)
            if layer_obj is None:
                continue

            if isinstance(layer_obj, (str, list)):
                txt = "\n".join(layer_obj) if isinstance(layer_obj, list) else layer_obj
                if self._looks_like_json_text(txt) or self._looks_like_xml_or_http_text(txt) or txt.strip():
                    text_blob = _text_to_bytes(txt)
                    if text_blob:
                        return text_blob

            if isinstance(layer_obj, dict):
                if key_names:
                    for key in key_names:
                        val = layer_obj.get(key)
                        if isinstance(val, str):
                            if self._looks_like_json_text(val) or self._looks_like_xml_or_http_text(val) or val.strip():
                                text_blob = _text_to_bytes(val)
                                if text_blob:
                                    return text_blob

                for _, val in layer_obj.items():
                    if isinstance(val, str):
                        if self._looks_like_json_text(val) or self._looks_like_xml_or_http_text(val) or val.strip():
                            text_blob = _text_to_bytes(val)
                            if text_blob:
                                return text_blob
                    elif isinstance(val, list):
                        joined = "\n".join(str(x) for x in val if x is not None)
                        if self._looks_like_json_text(joined) or self._looks_like_xml_or_http_text(
                                joined) or joined.strip():
                            text_blob = _text_to_bytes(joined)
                            if text_blob:
                                return text_blob

        return None

    def _build_scapy_from_tshark(self, layers: Dict[str, Any]) -> Optional[Packet]:
        """
        Best-effort Scapy reconstruction from tshark JSON.
        Supports: Ether (if present), IPv4/IPv6 + TCP/UDP, ICMPv6 echo, and Raw payloads.
        """
        eth = layers.get("eth", {})
        eth_src = eth.get("eth.src")
        eth_dst = eth.get("eth.dst")

        ipver, src_ip, dst_ip = self._get_ip_pair(layers)
        raw_bytes = self._extract_best_payload_bytes(layers)

        l4_layer = None

        if "tcp" in layers:
            tcp = layers["tcp"]
            sport = self._as_int(tcp.get("tcp.srcport"), 0) or 0
            dport = self._as_int(tcp.get("tcp.dstport"), 0) or 0
            seq = self._as_int(tcp.get("tcp.seq"), None)
            ack = self._as_int(tcp.get("tcp.ack"), None)
            window = self._as_int(tcp.get("tcp.window_size_value"), None)

            flags = 0
            flag_map = {
                "tcp.flags.fin": 0x01,
                "tcp.flags.syn": 0x02,
                "tcp.flags.reset": 0x04,
                "tcp.flags.push": 0x08,
                "tcp.flags.ack": 0x10,
                "tcp.flags.urg": 0x20,
                "tcp.flags.ecn": 0x40,
                "tcp.flags.cwr": 0x80,
            }
            for key, bit in flag_map.items():
                try:
                    if str(tcp.get(key, "0")) in {"1", "True", "true"}:
                        flags |= bit
                except Exception:
                    pass

            tcp_kwargs = {"sport": sport, "dport": dport}
            if seq is not None:
                tcp_kwargs["seq"] = seq
            if ack is not None:
                tcp_kwargs["ack"] = ack
            if window is not None:
                tcp_kwargs["window"] = window
            if flags:
                tcp_kwargs["flags"] = flags

            l4_layer = TCP(**tcp_kwargs)
            if raw_bytes:
                l4_layer = l4_layer / Raw(load=raw_bytes)

        elif "udp" in layers:
            udp = layers["udp"]
            sport = self._as_int(udp.get("udp.srcport"), 0) or 0
            dport = self._as_int(udp.get("udp.dstport"), 0) or 0
            l4_layer = UDP(sport=sport, dport=dport)
            if raw_bytes:
                l4_layer = l4_layer / Raw(load=raw_bytes)

        elif "icmpv6" in layers:
            ic6 = layers["icmpv6"]
            t = self._as_int(ic6.get("icmpv6.type"), -1)
            if t == 128:
                ident = self._as_int(ic6.get("icmpv6.echo.identifier"), 0) or 0
                seq = self._as_int(ic6.get("icmpv6.echo.sequence_number"), 0) or 0
                l4_layer = ICMPv6EchoRequest(id=ident, seq=seq)
            elif t == 129:
                ident = self._as_int(ic6.get("icmpv6.echo.identifier"), 0) or 0
                seq = self._as_int(ic6.get("icmpv6.echo.sequence_number"), 0) or 0
                l4_layer = ICMPv6EchoReply(id=ident, seq=seq)
            elif raw_bytes:
                l4_layer = Raw(load=raw_bytes)

        else:
            if raw_bytes:
                l4_layer = Raw(load=raw_bytes)

        net = None
        if ipver == "ipv4":
            net = IP(src=src_ip, dst=dst_ip)
        elif ipver == "ipv6":
            net = IPv6(src=src_ip, dst=dst_ip)

        out = None
        if eth_src and eth_dst:
            out = Ether(src=str(eth_src), dst=str(eth_dst))
            if net is not None:
                out = out / net
        else:
            out = net if net is not None else None

        if out is None:
            return None

        if l4_layer is not None:
            out = out / l4_layer

        return out

    def _initialize_geoip(self):
        """Finds and loads the GeoLite2-City database."""
        try:
            # Determine base path for GeoIP files based on execution mode
            if getattr(sys, "frozen", False):
                # Running in bundled mode (PyInstaller)
                # sys._MEIPASS is the path to the temporary directory where PyInstaller extracts files
                base_path = Path(sys._MEIPASS)
                self._decompressed_db_path = base_path / "tools" / "GeoLite2-City.mmdb"
            else:
                # Running in development mode
                # Path(__file__).resolve().parent is 'server' directory, .parent gets 'project_root'
                base_path = Path(__file__).resolve().parent.parent
                self._decompressed_db_path = base_path / "server" / "tools" / "GeoLite2-City.mmdb"

            # Define path for the uncompressed database file


            # Ensure the target directory exists
            self._decompressed_db_path.parent.mkdir(parents=True, exist_ok=True)

            # Try to load the .mmdb file directly
            if not self._decompressed_db_path.exists() or self._decompressed_db_path.stat().st_size == 0:
                self.logger.log_message(
                    f"[GeoIP] Warning: GeoIP database not found or is empty at {self._decompressed_db_path}. GeoIP lookups disabled.")
                self.geoip_reader = None
                self._decompressed_db_path = None
                return  # Exit if the file doesn't exist or is empty

            self.logger.log_message(f"[GeoIP] Attempting to load GeoIP database from {self._decompressed_db_path}...")

            # Attempt to load the GeoIP database with retries
            max_retries = 5
            for attempt in range(max_retries):
                try:
                    self.geoip_reader = geoip2.database.Reader(str(self._decompressed_db_path))
                    self.logger.log_message("[GeoIP] Successfully loaded GeoIP database.")
                    break  # Exit loop if successful
                except geoip2.errors.AddressNotFoundError as e:
                    # This error can sometimes indicate a malformed/incomplete file
                    self.logger.log_message(
                        f"[GeoIP] Attempt {attempt + 1}/{max_retries}: GeoIP database format error: {e}. Retrying in 0.5 seconds...")
                    self.geoip_reader = None
                    time.sleep(0.5)
                except Exception as e:
                    self.logger.log_message(
                        f"[GeoIP] Attempt {attempt + 1}/{max_retries}: Error loading database: {e}. Retrying in 0.5 seconds...")
                    self.geoip_reader = None  # Ensure reader is None on failure
                    time.sleep(0.5)
            else:
                self.logger.log_message(
                    f"[GeoIP] Failed to load GeoIP database after {max_retries} attempts. GeoIP lookups disabled.")
                self._decompressed_db_path = None  # Clear the path reference if loading failed


        except Exception as e:
            self.logger.log_message(
                f"[GeoIP] An unexpected error occurred during GeoIP initialization: {e}. GeoIP lookups disabled.")
            self.geoip_reader = None
            # Clear the path reference if loading failed
            self._decompressed_db_path = None

    def _get_geoip_location(self, ip_address: str) -> str:
        """Looks up an IP address and returns a formatted location string."""
        if not self.geoip_reader or not ip_address:
            return ""

        try:
            # First, check if it's a private IP using ipaddress module
            # This is robust for standard private IP ranges (RFC1918)
            try:
                ip_obj = ipaddress.ip_address(ip_address)
                if ip_obj.is_private:
                    return "Private IP"
            except ValueError:
                return "Invalid IP Format"

            # Attempt to look up the IP in the GeoIP database.
            # The geoip2.database.Reader.city() method will raise AddressNotFoundError
            # for IPs not found in the database, including non-public IPs not covered
            # by ipaddress.is_private.
            response = self.geoip_reader.city(ip_address)
            city = response.city.name or "Unknown City"
            country = response.country.iso_code or "N/A"
            return f"{city}, {country}"

        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception as e:
            self.logger.log_message(f"[GeoIP] Lookup Error for IP: {ip_address} - Details: {e}")
            return "Lookup Error"

    def _get_tshark_path(self) -> str | None:
        """Resolve tshark in development, PyInstaller and normal installs."""
        candidates = []

        def add(value):
            if not value:
                return
            try:
                candidates.append(Path(value).expanduser())
            except Exception:
                pass

        if getattr(sys, "frozen", False):
            meipass = Path(getattr(sys, "_MEIPASS", Path(sys.executable).resolve().parent))
            exe_dir = Path(sys.executable).resolve().parent
            add(meipass / "tools" / "Wireshark" / "tshark.exe")
            add(meipass / "Wireshark" / "tshark.exe")
            add(exe_dir / "tools" / "Wireshark" / "tshark.exe")
            add(exe_dir / "Wireshark" / "tshark.exe")

        p2pool_dir = Path(str(getattr(self.p2pool_data, "P2POOL_DIR", "") or "."))
        add(p2pool_dir / "tools" / "Wireshark" / "tshark.exe")
        add(p2pool_dir / "Wireshark" / "tshark.exe")

        server_dir = Path(__file__).resolve().parent
        project_root = server_dir.parent
        add(project_root / "client" / "tools" / "Wireshark" / "tshark.exe")
        add(server_dir / "tools" / "Wireshark" / "tshark.exe")

        for env_name in ("ProgramFiles", "ProgramFiles(x86)"):
            root = os.environ.get(env_name)
            if root:
                add(Path(root) / "Wireshark" / "tshark.exe")
        local_app_data = os.environ.get("LOCALAPPDATA")
        if local_app_data:
            add(Path(local_app_data) / "Programs" / "Wireshark" / "tshark.exe")

        system_tshark = shutil.which("tshark") or shutil.which("tshark.exe")
        if system_tshark:
            add(system_tshark)

        seen = set()
        for candidate in candidates:
            try:
                resolved = candidate.resolve(strict=False)
            except Exception:
                resolved = candidate
            key = os.path.normcase(str(resolved))
            if key in seen:
                continue
            seen.add(key)
            if candidate.is_file():
                self.logger.log_message(f"[Wireshark] Using tshark: {candidate}")
                return str(candidate)

        searched = ", ".join(str(p) for p in candidates[:8])
        self.logger.log_message(
            "[Wireshark] Error: tshark.exe was not found. "
            f"Checked PATH and: {searched or '(no candidate paths)'}."
        )
        return None

    def _list_interfaces(self, tshark_path: str) -> list[dict]:
        """Return the current tshark capture inventory with stable metadata."""
        self.logger.log_message("[Wireshark] Discovering capture interfaces with tshark -D...")
        creationflags = int(getattr(subprocess, "CREATE_NO_WINDOW", 0) or 0)
        try:
            proc = subprocess.run(
                [tshark_path, "-D"],
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
                timeout=20,
                creationflags=creationflags,
            )
        except Exception as exc:
            self.logger.log_message(f"[Wireshark] Interface discovery failed: {type(exc).__name__}: {exc}")
            return []

        output = str(proc.stdout or "")
        stderr = str(proc.stderr or "").strip()
        if proc.returncode != 0:
            self.logger.log_message(
                f"[Wireshark] tshark -D exited {proc.returncode}: {stderr or output.strip() or 'no details'}"
            )
            return []

        pattern = re.compile(r"^\s*(\d+)\.\s+(.+?)\s*$")
        guid_re = re.compile(r"\{[0-9A-Fa-f-]{36}\}")
        interfaces = []
        for raw_line in output.splitlines():
            match = pattern.match(raw_line)
            if not match:
                continue
            iface_id, iface_name = match.group(1), match.group(2).strip()
            lowered = iface_name.casefold()
            guid_match = guid_re.search(iface_name)
            row = {
                "id": iface_id,
                "name": iface_name,
                "guid": guid_match.group(0) if guid_match else "",
                "is_npf": "npf_" in lowered and "device" in lowered,
                "is_loopback": "loopback" in lowered or "npf_loopback" in lowered,
                "is_extcap": any(token in lowered for token in (
                    "sshdump", "randpkt", "udpdump", "wifidump", "ciscodump",
                    "androiddump", "sdjournal", "etwdump", "bluetooth",
                )),
            }
            interfaces.append(row)

        if not interfaces:
            self.logger.log_message(
                "[Wireshark] tshark returned no parseable interfaces. "
                f"stderr={stderr or '-'} stdout={output[:500]!r}"
            )
            return []

        self.logger.log_message(f"[Wireshark] Found {len(interfaces)} capture interfaces.")
        if self._capture_settings.get("log_interface_inventory", False):
            for row in interfaces:
                self.logger.log_message(f"[Wireshark]   {row['id']}: {row['name']}")
        return interfaces

    def configure_capture(self, **settings) -> dict:
        merged = dict(self._capture_settings)
        known = set(merged)
        unknown = set(settings) - known
        if unknown:
            raise ValueError("Unknown Wireshark capture setting(s): " + ", ".join(sorted(unknown)))
        merged.update(settings)
        for key in (
                "include_loopback", "include_vpn", "include_multicast",
                "include_discovery", "include_dhcp", "include_localhost",
                "promiscuous", "full_details", "feed_router",
                "log_packet_summaries", "log_payloads", "log_filtered_packets",
        ):
            merged[key] = bool(merged[key])
        merged["main_interface"] = str(merged.get("main_interface") or "Auto").strip()
        merged["custom_bpf"] = str(merged.get("custom_bpf") or "").strip()
        merged["min_packet_len"] = max(0, min(65535, int(merged["min_packet_len"])))
        merged["max_interfaces"] = max(1, min(32, int(merged["max_interfaces"])))
        self._capture_settings = merged
        self.min_packet_len = merged["min_packet_len"]
        return dict(merged)

    @staticmethod
    def _interface_name_matches(selector: str, iface_name: str) -> bool:
        selector = str(selector or "").strip().casefold()
        iface_name = str(iface_name or "").strip().casefold()
        if not selector or selector == "auto":
            return False
        raw = selector.removeprefix("guid:").strip("{}")
        return selector in iface_name or (raw and raw in iface_name)

    @staticmethod
    def _creation_flags() -> int:
        return int(getattr(subprocess, "CREATE_NO_WINDOW", 0) or 0)

    @staticmethod
    def _capture_interface_candidate(row: dict) -> bool:
        if not isinstance(row, dict):
            return False
        if row.get("is_extcap"):
            return False
        name = str(row.get("name") or "").casefold()
        return bool(row.get("is_npf") or "ethernet" in name or "wi-fi" in name or "wifi" in name)

    def _extract_layers_from_record(self, packet_data: dict) -> dict:
        """Accept normal tshark JSON and normalized line-oriented records."""
        if not isinstance(packet_data, dict):
            return {}
        source = packet_data.get("_source")
        if isinstance(source, dict) and isinstance(source.get("layers"), dict):
            return source.get("layers") or {}
        layers = packet_data.get("layers")
        if isinstance(layers, dict):
            return layers
        return {}

    def _build_capture_filter(self, capture: dict, *, include_custom: bool = True) -> str:
        # Keep the kernel filter deliberately conservative.  Detailed length and
        # application filtering occurs after decode so short DHCP, loopback and
        # control packets are still available to the manager/router.
        parts = ["(ip or ip6 or arp)"]
        if not capture.get("include_multicast", False):
            parts.append("not (ip multicast or ip6 multicast)")
        if not capture.get("include_discovery", False):
            parts.append(
                "not (udp port 5353 or udp port 1900 or udp port 3702 "
                "or udp port 5355 or tcp port 5357)"
            )
        if not capture.get("include_dhcp", True):
            parts.append("not (port 67 or port 68 or port 546 or port 547)")
        if not capture.get("include_localhost", True):
            parts.extend(("not host 127.0.0.1", "not host ::1"))
        parts.append("not (udp port 137 and net 169.254.0.0/16)")
        custom = str(capture.get("custom_bpf") or "").strip()
        if include_custom and custom:
            parts.append(f"({custom})")
        return "(" + " and ".join(parts) + ")"

    def _build_tshark_command(
            self,
            tshark_path: str,
            interface_id: str,
            capture_filter: str,
            capture: dict,
    ) -> list[str]:
        # -T json already emits the complete protocol tree.  Combining -V with
        # JSON is unnecessary and has caused immediate exits on some tshark
        # releases, so full_details is handled in Python rather than with -V.
        command = [
            tshark_path,
            "-l",                 # flush live output after each packet
            "-n",                 # avoid resolver latency in the capture path
            "-T", "json",
            "-i", str(interface_id),
            "-s", "0",          # preserve complete frames
            "-B", "16",         # bounded Npcap capture buffer (MiB)
            "-o", "tcp.desegment_tcp_streams:TRUE",
        ]
        if capture_filter:
            command.extend(("-f", capture_filter))
        if not capture.get("promiscuous", True):
            command.append("-p")
        return command

    @staticmethod
    def _looks_like_filter_error(lines) -> bool:
        text = " ".join(str(x) for x in (lines or ())).casefold()
        return any(token in text for token in (
            "invalid capture filter", "capture filter syntax", "syntax error",
            "can't parse filter", "cannot parse filter", "not a valid capture filter",
            "pcap_compile", "data link type",
        ))

    def _spawn_capture_process(self, row: dict, command: list[str]) -> subprocess.Popen | None:
        iface_id = str(row.get("id") or "")
        iface_name = str(row.get("name") or iface_id)
        try:
            proc = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
                errors="replace",
                bufsize=1,
                creationflags=self._creation_flags(),
            )
        except Exception as exc:
            self.logger.log_message(
                f"[Wireshark] Failed to launch {iface_name} ({iface_id}): {type(exc).__name__}: {exc}"
            )
            return None

        with self._capture_lock:
            self.tshark_procs[iface_id] = proc
            self._capture_iface_names[iface_id] = iface_name
            self._capture_commands[iface_id] = list(command)
            stats = self._capture_stats[iface_id]
            stats["started_at"] = time.monotonic()

        stdout_thread = threading.Thread(
            target=self._redirect_output,
            args=(proc, iface_id),
            daemon=True,
            name=f"TsharkStdout-{iface_id}",
        )
        stderr_thread = threading.Thread(
            target=self._redirect_stderr,
            args=(proc, iface_id),
            daemon=True,
            name=f"TsharkStderr-{iface_id}",
        )
        self.redirect_threads[iface_id] = stdout_thread
        self.stderr_threads[iface_id] = stderr_thread
        stdout_thread.start()
        stderr_thread.start()
        return proc

    def _remove_dead_capture(self, iface_id: str) -> None:
        with self._capture_lock:
            self.tshark_procs.pop(str(iface_id), None)
            self._capture_commands.pop(str(iface_id), None)

    def _capture_status_loop(self) -> None:
        while not self.stop_event.wait(self._status_interval):
            with self._capture_lock:
                process_snapshot = dict(self.tshark_procs)
                stats_snapshot = {key: dict(value) for key, value in self._capture_stats.items()}
            alive = sum(1 for proc in process_snapshot.values() if proc.poll() is None)
            total = sum(int(s.get("packets", 0)) for s in stats_snapshot.values())
            parse_errors = sum(int(s.get("parse_errors", 0)) for s in stats_snapshot.values())
            router_ok = sum(int(s.get("router_accepted", 0)) for s in stats_snapshot.values())
            router_no = sum(int(s.get("router_rejected", 0)) for s in stats_snapshot.values())
            now = time.monotonic()
            changed = total != self._last_status_total
            due = (now - self._last_status_log) >= 15.0
            if changed or due:
                self._last_status_total = total
                self._last_status_log = now
                self.logger.log_message(
                    f"[Wireshark] Capture status: alive={alive}/{len(process_snapshot)} "
                    f"packets={total} parse_errors={parse_errors} "
                    f"router={router_ok} accepted/{router_no} rejected."
                )
            if process_snapshot and alive == 0:
                self.logger.log_message("[Wireshark] All tshark capture processes have exited.")
                return

    def capture_status(self) -> dict:
        with self._capture_lock:
            processes = dict(self.tshark_procs)
            stats = {key: dict(value) for key, value in self._capture_stats.items()}
        return {
            "running": any(proc.poll() is None for proc in processes.values()),
            "interfaces": {
                iface_id: {
                    "name": self._capture_iface_names.get(iface_id, iface_id),
                    "alive": proc.poll() is None,
                    "returncode": proc.poll(),
                    "stats": stats.get(iface_id, {}),
                    "stderr_tail": list(self._stderr_tail.get(iface_id, ())),
                }
                for iface_id, proc in processes.items()
            },
        }
    def start_capture(
            self, main_interface_name: str = "Auto", router_manager=None,
            promiscuous=True, settings: Optional[Dict[str, Any]] = None,
    ):
        capture = self.configure_capture(**dict(settings or {}))
        capture["main_interface"] = str(main_interface_name or capture["main_interface"] or "Auto").strip()
        capture["promiscuous"] = bool(promiscuous)
        self._capture_settings = capture
        self.router_manager = router_manager

        # Do not allow stale exited children to make the manager appear active.
        with self._capture_lock:
            stale = [key for key, proc in self.tshark_procs.items() if proc.poll() is not None]
            for key in stale:
                self.tshark_procs.pop(key, None)
        if self.tshark_procs:
            self.logger.log_message("[Wireshark] Capture is already running.")
            return False

        self._initialize_geoip()
        tshark_path = self._get_tshark_path()
        if not tshark_path:
            return False
        available_interfaces = self._list_interfaces(tshark_path)
        if not available_interfaces:
            return False

        self.loopback_interface_id = None
        self.vpn_interface_id = None
        selector = capture["main_interface"]
        preferred_tokens = [selector]
        if selector.casefold() == "auto":
            preferred_tokens = []
            if router_manager is not None:
                preferred_tokens.extend((
                    getattr(router_manager, "interface_out_full_name", ""),
                    getattr(router_manager, "interface_out_friendly_name", ""),
                    getattr(router_manager, "interface_out_guid", ""),
                ))
            preferred_tokens.extend(("Wi-Fi", "Ethernet"))

        main = None
        for token in preferred_tokens:
            if not str(token or "").strip():
                continue
            main = next(
                (row for row in available_interfaces
                 if self._interface_name_matches(str(token), row.get("name", ""))),
                None,
            )
            if main:
                break

        if main is None:
            main = next(
                (row for row in available_interfaces
                 if self._capture_interface_candidate(row) and not row.get("is_loopback")),
                None,
            )
        if main is None:
            main = next(
                (row for row in available_interfaces if not row.get("is_loopback") and not row.get("is_extcap")),
                available_interfaces[0],
            )
            self.logger.log_message(
                f"[Wireshark] Main selector {selector!r} was not found; using {main['name']}."
            )
        else:
            self.logger.log_message(
                f"[Wireshark] Main interface {selector!r} resolved to {main['id']}: {main['name']}"
            )

        capture_rows = [main]
        for row in available_interfaces:
            name = str(row.get("name", ""))
            lowered = name.casefold()
            if capture.get("include_loopback", True) and row.get("is_loopback"):
                self.loopback_interface_id = str(row["id"])
                capture_rows.append(row)
            if capture.get("include_vpn", True) and any(token in lowered for token in (
                    "wireguard", "protonvpn", "openvpn", "wintun", "tap-windows", "vpn", "zerotier"
            )):
                if self.vpn_interface_id is None:
                    self.vpn_interface_id = str(row["id"])
                capture_rows.append(row)

        unique_rows = []
        seen_ids = set()
        for row in capture_rows:
            iface_id = str(row.get("id") or "")
            if not iface_id or iface_id in seen_ids or row.get("is_extcap"):
                continue
            seen_ids.add(iface_id)
            unique_rows.append(row)
            if len(unique_rows) >= int(capture["max_interfaces"]):
                break
        if not unique_rows:
            self.logger.log_message("[Wireshark] No usable live-capture interfaces were selected.")
            return False

        requested_filter = self._build_capture_filter(capture, include_custom=True)
        safe_filter = self._build_capture_filter(capture, include_custom=False)
        self.stop_event.clear()
        self._last_status_total = -1
        self._last_status_log = 0.0
        self._capture_stats.clear()
        self._stderr_tail.clear()

        launched = {}
        for row in unique_rows:
            command = self._build_tshark_command(
                tshark_path, str(row["id"]), requested_filter, capture
            )
            proc = self._spawn_capture_process(row, command)
            if proc is not None:
                launched[str(row["id"])] = row

        # tshark compiles the capture filter and opens Npcap immediately.  A
        # short health check prevents the GUI from reporting success when every
        # child exited with a filter/adapter error.
        time.sleep(1.0)
        failed = []
        for iface_id, row in list(launched.items()):
            proc = self.tshark_procs.get(iface_id)
            if proc is None or proc.poll() is not None:
                failed.append((iface_id, row, list(self._stderr_tail.get(iface_id, ()))))
                self._remove_dead_capture(iface_id)

        # Invalid custom BPF must not leave the entire capture dead. Retry only
        # filter-related failures with the known-safe generated filter.
        if requested_filter != safe_filter:
            for iface_id, row, tail in failed[:]:
                if not self._looks_like_filter_error(tail):
                    continue
                self.logger.log_message(
                    f"[Wireshark] Custom BPF failed on {row['name']}; retrying without the custom expression."
                )
                command = self._build_tshark_command(
                    tshark_path, str(row["id"]), safe_filter, capture
                )
                proc = self._spawn_capture_process(row, command)
                if proc is not None:
                    time.sleep(0.8)
                    if proc.poll() is None:
                        failed = [item for item in failed if item[0] != iface_id]
                    else:
                        self._remove_dead_capture(iface_id)

        alive = {
            iface_id: proc for iface_id, proc in self.tshark_procs.items()
            if proc.poll() is None
        }
        if not alive:
            details = []
            for iface_id, row, tail in failed:
                msg = " | ".join(tail[-4:]).strip()
                details.append(f"{row['name']}: {msg or 'tshark exited during startup'}")
            self.logger.log_message(
                "[Wireshark] Capture could not start on any selected interface. "
                + ("; ".join(details) if details else "Check Npcap permissions and adapter availability.")
            )
            self.stop_event.set()
            return False

        self._status_thread = threading.Thread(
            target=self._capture_status_loop,
            daemon=True,
            name="WiresharkCaptureStatus",
        )
        self._status_thread.start()
        names = [self._capture_iface_names.get(key, key) for key in alive]
        active_filters = {}
        for iface_id in alive:
            cmd = list(self._capture_commands.get(iface_id, ()))
            active_filter = ""
            if "-f" in cmd:
                try:
                    active_filter = cmd[cmd.index("-f") + 1]
                except Exception:
                    active_filter = ""
            active_filters[iface_id] = active_filter or "<none>"
        self.logger.log_message(
            f"[Wireshark] Capture active on {len(alive)} interface(s): {names}. "
            f"feed_router={capture['feed_router']} filters={active_filters}"
        )
        return True

    def stop_capture(self):
        with self._capture_lock:
            processes = dict(self.tshark_procs)
        if not processes:
            self.logger.log_message("[Wireshark] Capture is not running.")
            return

        self.logger.log_message("[Wireshark] Stopping capture...")
        self.stop_event.set()
        for proc in processes.values():
            if proc.poll() is None:
                try:
                    proc.terminate()
                except Exception:
                    pass
        for iface_id, proc in processes.items():
            try:
                proc.wait(timeout=4)
            except subprocess.TimeoutExpired:
                self.logger.log_message(f"[Wireshark] Killing unresponsive tshark interface {iface_id}.")
                try:
                    proc.kill()
                except Exception:
                    pass
            for stream in (proc.stdout, proc.stderr):
                try:
                    if stream:
                        stream.close()
                except Exception:
                    pass

        for thread in list(self.redirect_threads.values()) + list(self.stderr_threads.values()):
            if thread and thread.is_alive() and thread is not threading.current_thread():
                thread.join(timeout=1.0)
        if self._status_thread and self._status_thread.is_alive() and self._status_thread is not threading.current_thread():
            self._status_thread.join(timeout=1.0)

        if self.geoip_reader:
            try:
                self.geoip_reader.close()
            except Exception:
                pass
            self.geoip_reader = None
        self._decompressed_db_path = None

        status = self.capture_status()
        total = sum(
            int(item.get("stats", {}).get("packets", 0))
            for item in status.get("interfaces", {}).values()
        )
        self.logger.log_message(f"[Wireshark] Capture stopped after {total} decoded packet(s).")
        with self._capture_lock:
            self.tshark_procs.clear()
            self.redirect_threads.clear()
            self.stderr_threads.clear()
            self._capture_commands.clear()
            self._capture_iface_names.clear()
    def _as_int(self, x: Any, default: Optional[int] = None) -> Optional[int]:
        try:
            return int(str(x))
        except Exception:
            return default

    def _hexdump_to_bytes(self, hex_like: str) -> Optional[bytes]:
        """
        tshark often gives hex with colons 'xx:xx:...', or sometimes plain hex.
        This cleans and converts to bytes.
        """
        if not hex_like:
            return None
        try:
            s = "".join(ch for ch in hex_like if ch in "0123456789abcdefABCDEF")
            if len(s) % 2 != 0:
                # pad if odd
                s = s[:-1]
            return bytes.fromhex(s)
        except Exception:
            return None

    def _get_ip_pair(self, layers: Dict[str, Any]) -> tuple[str, str, str]:
        """
        Returns (version, src, dst) where version is 'ipv4', 'ipv6', or 'none'
        """
        if "ip" in layers:
            ip_l = layers["ip"]
            return "ipv4", ip_l.get("ip.src", "N/A"), ip_l.get("ip.dst", "N/A")
        if "ipv6" in layers:
            v6 = layers["ipv6"]
            return "ipv6", v6.get("ipv6.src", "N/A"), v6.get("ipv6.dst", "N/A")
        return "none", "N/A", "N/A"


    def _is_ipv4_broadcast(self, addr: str) -> bool:
        try:
            return ipaddress.ip_address(addr) == ipaddress.IPv4Address("255.255.255.255")
        except Exception:
            return False

    def _is_multicast_or_llm(self, addr: str) -> bool:
        try:
            ip = ipaddress.ip_address(addr)
            if ip.version == 4:
                # 224.0.0.0/24 and 239.255.255.0/24 are particularly noisy
                if ip in ipaddress.IPv4Network('224.0.0.0/24'):
                    return True
                if ip in ipaddress.IPv4Network('239.255.255.0/24'):
                    return True
                if str(ip) == "239.255.255.250":  # SSDP
                    return True
                return ip.is_multicast
            else:
                # IPv6 link-local multicast
                return ip.is_multicast and ip.is_link_local
        except Exception:
            return False

    def _process_packet(self, packet_data: dict | str, interface_id: str) -> None:
        """Parse tshark JSON, log/filter like before, THEN wrap into Scapy and pass to router_manager with iface='WireShark'."""
        settings = dict(self._capture_settings)
        log_filtered = bool(settings.get("log_filtered_packets", False))
        log_summaries = bool(settings.get("log_packet_summaries", True))
        log_payloads = bool(settings.get("log_payloads", False))
        feed_router = bool(settings.get("feed_router", False))
        if not isinstance(packet_data, dict):
            return

        try:
            layers = self._extract_layers_from_record(packet_data)
            if not layers:
                self._capture_stats[str(interface_id)]["empty_records"] += 1
                return

            def _nz(ip: str) -> str:
                return ip.split("%", 1)[0] if isinstance(ip, str) else ip

            def _safe_int(v, default=0):
                try:
                    return int(str(v or default).strip())
                except Exception:
                    return default

            def _is_loopback_addr(ip: str) -> bool:
                try:
                    return ipaddress.ip_address(_nz(ip)).is_loopback
                except Exception:
                    return False

            def _looks_like_directed_broadcast(ip: str) -> bool:
                try:
                    ip_s = str(_nz(ip) or "")
                    ip_obj = ipaddress.ip_address(ip_s)
                    if ip_obj.version != 4:
                        return False
                    if ip_obj.is_multicast or ip_obj.is_loopback:
                        return False
                    parts = ip_s.split(".")
                    return len(parts) == 4 and parts[-1] == "255"
                except Exception:
                    return False

            def _parse_json_loose(text: str):
                if not text:
                    return None
                s = str(text).lstrip("\ufeff\r\n\t \x00")
                if not s:
                    return None
                try:
                    obj = json.loads(s)
                    return obj if isinstance(obj, dict) else None
                except Exception:
                    pass
                try:
                    decoder = json.JSONDecoder()
                    obj, _ = decoder.raw_decode(s)
                    return obj if isinstance(obj, dict) else None
                except Exception:
                    return None

            def _is_hvrm_control_json_block(decoded_payload: str, payload_bytes: bytes, src_port_val, dst_port_val,
                                            src_ip_val: str, dst_ip_val: str) -> bool:
                text = ""
                if decoded_payload and decoded_payload.strip():
                    text = decoded_payload
                elif payload_bytes:
                    try:
                        text = payload_bytes.decode("utf-8", errors="ignore")
                    except Exception:
                        text = ""

                if not text:
                    return False

                preview = text[:8192]
                if '"magic":"HVRM' not in preview and '"magic": "HVRM' not in preview:
                    return False

                msg = _parse_json_loose(text)
                if not isinstance(msg, dict):
                    return False

                magic = str(msg.get("magic") or "").strip()
                mtype = str(msg.get("type") or "").strip().lower()

                if magic not in {"HVRM4", "HVRM5", "HVRM6"}:
                    return False
                if mtype not in {"hello", "hello_ack", "frame", "ack"}:
                    return False

                sp = _safe_int(src_port_val, 0)
                dp = _safe_int(dst_port_val, 0)

                if sp in {47771, 47772} or dp in {47771, 47772}:
                    return True

                if _looks_like_directed_broadcast(dst_ip_val):
                    return True

                try:
                    adv_ip = str(msg.get("listen_ip") or msg.get("reply_to_ip") or "")
                    if adv_ip and adv_ip == str(src_ip_val):
                        return True
                except Exception:
                    pass

                return True

            frame = layers.get("frame", {})
            timestamp = frame.get("frame.time", "N/A")
            packet_num = frame.get("frame.number", "N/A")
            packet_len = frame.get("frame.len", "N/A")

            try:
                if int(packet_len) < self.min_packet_len:
                    if log_filtered:
                        self.logger.log_message(
                            f"[Wireshark Filter] Filtering small packet (Len: {packet_len}) on interface {interface_id}."
                        )
                    return
            except ValueError:
                pass

            ip_layer = layers.get("ip") or layers.get("ipv6")
            src_ip = ip_layer.get("ip.src", ip_layer.get("ipv6.src", "N/A")) if ip_layer else "N/A"
            dst_ip = ip_layer.get("ip.dst", ip_layer.get("ipv6.dst", "N/A")) if ip_layer else "N/A"

            if not settings.get("include_multicast", False) and self._is_ipv4_broadcast(dst_ip):
                if log_filtered:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering IPv4 Broadcast packet to {dst_ip} on interface {interface_id}."
                    )
                return

            dst_is_mcast = self._is_multicast_or_llm(dst_ip)
            if not settings.get("include_multicast", False) and dst_is_mcast:
                if log_filtered:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering Multicast/Discovery packet to {dst_ip} on interface {interface_id}."
                    )
                return

            try:
                dst_obj = ipaddress.ip_address(_nz(dst_ip))
            except ValueError:
                dst_obj = None

            if (not settings.get("include_multicast", False)
                    and "icmpv6" in layers and dst_obj and dst_obj.is_multicast):
                if log_filtered:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering ICMPv6 multicast to {dst_ip} on interface {interface_id}."
                    )
                return

            if ((not settings.get("include_loopback", True)
                     or not settings.get("include_localhost", True))
                    and _is_loopback_addr(src_ip) and _is_loopback_addr(dst_ip)):
                if log_filtered:
                    self.logger.log_message(f"[Wireshark] Skipping local loopback packet {src_ip} -> {dst_ip}")
                return

            if (not settings.get("include_localhost", True)
                    and self.router_manager and self.router_manager.started and src_ip == dst_ip):
                is_legitimate_loopback = False
                try:
                    ip_obj = ipaddress.ip_address(src_ip)
                    if ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_loopback:
                        is_legitimate_loopback = True
                except ValueError:
                    is_legitimate_loopback = False

                if is_legitimate_loopback:
                    if log_filtered:
                        self.logger.log_message(
                            f"[Wireshark] Dropping self-addressed local packet: {src_ip} -> {dst_ip}"
                        )
                    return
                else:
                    if log_filtered:
                        self.logger.log_message(
                            f"[Wireshark] Dropping suspicious self-addressed public packet: {src_ip} -> {dst_ip}"
                        )
                    return

            if not settings.get("include_localhost", True) and self.router_manager and self.router_manager.started:
                try:
                    link_local_ip_bare = str(self.router_manager.router_ipv6_link_local_out or "").split('%')[0]
                    if link_local_ip_bare and (dst_ip == link_local_ip_bare or src_ip == link_local_ip_bare):
                        if log_filtered:
                            self.logger.log_message(
                                f"[Wireshark] Dropping packet to our own link-local address: {dst_ip}"
                            )
                        return
                except Exception:
                    pass

            has_ip4 = "ip" in layers
            has_ip6 = "ipv6" in layers
            if not (has_ip4 or has_ip6):
                return

            ip_layer = layers.get("ip") or layers.get("ipv6")
            src_ip = ip_layer.get("ip.src", ip_layer.get("ipv6.src", "N/A"))
            dst_ip = ip_layer.get("ip.dst", ip_layer.get("ipv6.dst", "N/A"))

            common_noisy_ports = set()
            if not settings.get("include_discovery", False):
                common_noisy_ports.update({
                    "5353", "1900", "137", "138", "3702", "5355", "5357", "22222"
                })
            if not settings.get("include_dhcp", True):
                common_noisy_ports.update({"67", "68", "546", "547"})

            if "udp" in layers:
                udp_layer = layers["udp"]
                dst_port = udp_layer.get("udp.dstport", "N/A")
                src_port = udp_layer.get("udp.srcport", "N/A")
                if dst_port in common_noisy_ports or src_port in common_noisy_ports:
                    if log_filtered:
                        self.logger.log_message(
                            f"[Wireshark Filter] Filtering Discovery/Idle UDP packet on port {dst_port} from {src_ip} to {dst_ip} on interface {interface_id}."
                        )
                    return

            if "tcp" in layers:
                tcp_layer = layers["tcp"]
                dst_port = tcp_layer.get("tcp.dstport", "N/A")
                src_port = tcp_layer.get("tcp.srcport", "N/A")
                if dst_port in common_noisy_ports or src_port in common_noisy_ports:
                    if log_filtered:
                        self.logger.log_message(
                            f"[Wireshark Filter] Filtering Discovery/Idle TCP packet on port {dst_port} from {src_ip} to {dst_ip} on interface {interface_id}."
                        )
                    return

            def _is_private(addr: str) -> bool:
                try:
                    return ipaddress.ip_address(addr.split("%")[0]).is_private
                except ValueError:
                    return True

            context_tags: list[str] = []

            if (
                    interface_id == self.loopback_interface_id and
                    self.vpn_interface_id is not None and
                    not _is_private(dst_ip)
            ):
                context_tags.append("via-VPN-out")

            if interface_id == self.vpn_interface_id:
                if _is_private(src_ip) and not _is_private(dst_ip):
                    context_tags.append("VPN→WAN")
                elif not _is_private(src_ip) and _is_private(dst_ip):
                    context_tags.append("WAN→VPN")
                else:
                    context_tags.append("VPN-internal")

            src_port = dst_port = "N/A"
            tcp_layer = layers.get("tcp")
            udp_layer = layers.get("udp")

            if tcp_layer:
                src_port = tcp_layer.get("tcp.srcport", "N/A")
                dst_port = tcp_layer.get("tcp.dstport", "N/A")
            elif udp_layer:
                src_port = udp_layer.get("udp.srcport", "N/A")
                dst_port = udp_layer.get("udp.dstport", "N/A")

            highest_proto = frame.get("frame.protocols", "N/A").split(":")[-1].upper()

            payload_bytes = b""
            decoded_payload = ""
            app_layer = "UNKNOWN"
            app_detail = ""

            try:
                payload_bytes = self._extract_best_payload_bytes(layers) or b""
            except Exception:
                payload_bytes = b""

            try:
                decoded_payload = self._decode_best_payload_text(payload_bytes) if payload_bytes else ""
            except Exception:
                decoded_payload = ""

            try:
                app_layer, app_detail = self._classify_application_layer(
                    layers,
                    payload_bytes,
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    src_port=src_port,
                    dst_port=dst_port,
                    interface_id=interface_id,
                )
            except Exception:
                app_layer, app_detail = "UNKNOWN", ""

            # HARD DROP BEFORE ANY LOGGING OF JSON / PAYLOAD / GEOIP
            if _is_hvrm_control_json_block(decoded_payload, payload_bytes, src_port, dst_port, src_ip, dst_ip):
                if log_filtered:
                    self.logger.log_message(
                        f"[Wireshark Filter] Blocking HVRM control JSON {src_ip}:{src_port} -> {dst_ip}:{dst_port} on interface {interface_id}."
                    )
                return

            src_location = ""
            dst_location = ""
            if log_summaries:
                try:
                    if hasattr(self, "_get_geoip_location"):
                        src_location = self._get_geoip_location(src_ip)
                        dst_location = self._get_geoip_location(dst_ip)
                except Exception:
                    src_location = ""
                    dst_location = ""

            if log_summaries:
                src_loc_str = f"({src_location})" if src_location else ""
                dst_loc_str = f"({dst_location})" if dst_location else ""
    
                tag_str = f" [{' | '.join(context_tags)}]" if context_tags else ""
                app_str = f" | App:{app_layer}" + (f" ({app_detail})" if app_detail else "")
                self.logger.log_message(
                    f"[NetTrace-{interface_id}] Pkt:{packet_num:<6} | {timestamp} | Len:{packet_len:<5} | "
                    f"{src_ip}:{src_port} {src_loc_str} -> {dst_ip}:{dst_port} {dst_loc_str} | "
                    f"Proto:{highest_proto}{app_str}{tag_str}"
                )
    
                if app_layer == "HTTP":
                    http = layers.get("http", {})
                    if "http.request.method" in http:
                        host = http.get("http.host", "")
                        uri = http.get("http.request.full_uri", "")
                        self.logger.log_message(
                            f"[HTTP-{interface_id}] {src_ip} → {host}{uri} ({http['http.request.method']}){tag_str}"
                        )
                    elif "http.response.code" in http:
                        code = http["http.response.code"]
                        self.logger.log_message(
                            f"[HTTP-{interface_id}] {dst_ip} ← {code}{tag_str}"
                        )
    
                elif app_layer == "TLS":
                    tls = layers.get("ssl", layers.get("tls", {}))
                    if "tls.handshake.extensions_server_name" in tls:
                        sni = tls["tls.handshake.extensions_server_name"]
                        self.logger.log_message(
                            f"[TLS-{interface_id}] SNI={sni} {src_ip}:{src_port} → {dst_ip}:{dst_port}{tag_str}"
                        )
    
                elif app_layer == "DNS":
                    dns = layers.get("dns", {})
                    qname = dns.get("dns.qry.name", "")
                    qtype = dns.get("dns.qry.type", "")
                    answer = dns.get("dns.a", dns.get("dns.aaaa", ""))
                    self.logger.log_message(
                        f"[DNS-{interface_id}] {qname} ({qtype}) → {answer or 'NO-ANSWER'}{tag_str}"
                    )
    
                elif app_layer in {"JSON", "JSON-RPC"}:
                    preview = decoded_payload[:400] if decoded_payload else ""
                    self.logger.log_message(
                        f"[JSON-{interface_id}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} {preview}"
                    )
    
                elif app_layer in {"XML", "SOAP"}:
                    preview = decoded_payload[:400] if decoded_payload else ""
                    self.logger.log_message(
                        f"[XML-{interface_id}] {src_ip}:{src_port} -> {dst_ip}:{dst_port} {preview}"
                    )
    
            if log_payloads:
                if payload_bytes:
                    raw_payload_hex_str = payload_bytes.hex()
                    truncated_hex_display = raw_payload_hex_str[:128] + ("..." if len(raw_payload_hex_str) > 128 else "")
                    self.logger.log_message(f"[Payload-Wireshark] 📦 Raw payload (hex): {truncated_hex_display}")
    
                    if decoded_payload and decoded_payload.strip():
                        self.logger.log_message(f"[Payload-Wireshark] 📝 Decoded payload: {decoded_payload[:1200]}")
                    else:
                        self.logger.log_message("[Payload-Wireshark] ⚠️ Decoded payload not considered human-readable.")
                else:
                    self.logger.log_message("[Payload-Wireshark] 📦 No reassembled payload data found.")
    
            try:
                if feed_router and self.router_manager and self.router_manager.started:
                    scapy_pkt = self._build_scapy_from_tshark(layers)
                    if scapy_pkt is None:
                        self.logger.log_message(
                            "[Wireshark-Process] ⚠️ Could not build Scapy packet from tshark JSON."
                        )
                        return

                    try:
                        scapy_raw = bytes(scapy_pkt)
                    except Exception as e:
                        self.logger.log_message(
                            f"[Wireshark-Process] ⚠️ Built Scapy packet but could not serialize it: {type(e).__name__}: {e}"
                        )
                        return

                    try:
                        setattr(scapy_pkt, "_ws_layers", layers)
                        setattr(scapy_pkt, "_ws_app_layer", app_layer)
                        setattr(scapy_pkt, "_ws_app_detail", app_detail)
                        setattr(scapy_pkt, "_ws_payload_text", decoded_payload)
                        setattr(scapy_pkt, "_ws_payload_bytes", payload_bytes)
                        setattr(scapy_pkt, "_ws_geoip_src", src_location)
                        setattr(scapy_pkt, "_ws_geoip_dst", dst_location)
                        setattr(scapy_pkt, "_ws_interface_id", interface_id)
                        setattr(scapy_pkt, "_ws_timestamp", timestamp)
                        setattr(scapy_pkt, "_ws_packet_num", packet_num)
                        setattr(scapy_pkt, "_ws_net_patch", True)
                    except Exception:
                        pass

                    accepted = self.router_manager.enqueue_ingress_packet(
                        scapy_pkt, "WireShark"
                    )
                    stats = self._capture_stats[str(interface_id)]
                    if accepted:
                        stats["router_accepted"] += 1
                    else:
                        stats["router_rejected"] += 1
                        if log_filtered:
                            self.logger.log_message(
                                "[Wireshark-Process] Router ingress queue did not accept reconstructed packet."
                            )

            except Exception as e:
                self.logger.log_message(f"[Wireshark-Process] ❌ Scapy build/dispatch error: {e}")

        except Exception as e:
            self.logger.log_message(
                f"[Wireshark-Process] Error processing packet on interface {interface_id}: {e}"
            )

    def _redirect_output(self, process: subprocess.Popen, interface_id: str):
        """Incrementally decode tshark's live JSON array without waiting for exit."""
        if not process.stdout:
            return
        decoder = json.JSONDecoder()
        buffer = ""
        max_buffer = 16 * 1024 * 1024

        def consume(current: str) -> str:
            while current:
                current = current.lstrip("\ufeff\r\n\t ,[]")
                if not current:
                    return ""
                if not current.startswith("{"):
                    start = current.find("{")
                    if start < 0:
                        return current[-4096:]
                    current = current[start:]
                try:
                    record, index = decoder.raw_decode(current)
                except json.JSONDecodeError:
                    return current
                current = current[index:]
                layers = self._extract_layers_from_record(record) if isinstance(record, dict) else {}
                if not layers:
                    self._capture_stats[interface_id]["empty_records"] += 1
                    continue
                try:
                    self._process_packet(record, interface_id)
                    stats = self._capture_stats[interface_id]
                    stats["packets"] += 1
                    stats["last_packet_at"] = time.monotonic()
                except Exception as exc:
                    self._capture_stats[interface_id]["parse_errors"] += 1
                    if self._capture_stats[interface_id]["parse_errors"] <= 3:
                        self.logger.log_message(
                            f"[Wireshark] Packet decode error on {interface_id}: {type(exc).__name__}: {exc}"
                        )
            return current

        try:
            for line in iter(process.stdout.readline, ""):
                if self.stop_event.is_set():
                    break
                stats = self._capture_stats[interface_id]
                stats["stdout_lines"] += 1
                stats["stdout_bytes"] += len(line.encode("utf-8", "replace"))
                buffer += line
                buffer = consume(buffer)
                if len(buffer) > max_buffer:
                    stats["parse_errors"] += 1
                    self.logger.log_message(
                        f"[Wireshark] Resetting oversized JSON buffer on interface {interface_id}."
                    )
                    start = buffer.rfind("{")
                    buffer = buffer[start:] if start >= 0 else ""
            if buffer:
                consume(buffer)
        except Exception as exc:
            if not self.stop_event.is_set():
                self.logger.log_message(
                    f"[Wireshark] stdout reader failed on {interface_id}: {type(exc).__name__}: {exc}"
                )
        finally:
            rc = process.poll()
            if not self.stop_event.is_set():
                self.logger.log_message(
                    f"[Wireshark] Capture stream ended on {interface_id} (exit={rc})."
                )

    def _redirect_stderr(self, process: subprocess.Popen, interface_id: str):
        if not process.stderr:
            return
        emitted = 0
        try:
            for raw_line in iter(process.stderr.readline, ""):
                line = str(raw_line or "").strip()
                if not line:
                    continue
                self._capture_stats[interface_id]["stderr_lines"] += 1
                self._stderr_tail[interface_id].append(line)
                lowered = line.casefold()
                important = any(token in lowered for token in (
                    "error", "failed", "invalid", "permission", "denied", "npcap",
                    "couldn't", "cannot", "not found", "no such device",
                ))
                if important and emitted < 8:
                    self.logger.log_message(f"[Wireshark/tshark {interface_id}] {line}")
                    emitted += 1
        except Exception:
            pass

class AsyncNmapManager:
    """An asynchronous manager for running Nmap through WSL."""

    def __init__(self, logger, async_loop):
        self.i_stdout_thread = None
        self.i_stderr_thread = None
        self.logger = logger
        self.wsl_path = self._find_wsl_executable()
        self.is_ready = False
        self.setup_message = "Ready to initialize."
        self.status = "idle"
        if getattr(sys, "frozen", False):


            self.tools_dir = Path(sys._MEIPASS) / "tools" / "Linux"
        else:
            self.tools_dir = Path(__file__).resolve().parent  / "tools" / "Linux"

        self.nmap_wsl_path = None
        self._scan_task = None
        self._scan_process = None
        self.async_loop = async_loop
        # --- ADDED: Attributes for the interactive session ---
        self._interactive_session_process = None
        self._interactive_session_tasks = []

        self.stdout_capture = []
    # --- ADDED: Methods for managing the interactive session ---
    async def initialize(self, on_complete_callback):
        """
        Asynchronously ensures WSL is functional and Nmap is properly installed.
        """
        self.logger.log_message("🚀 Starting asynchronous WSL & Nmap setup...")
        self.is_ready = False
        try:
            # Step 1: Verify WSL is working
            if not self.wsl_path or not await self._check_wsl_functionality():
                self.setup_message = "⚠️ WSL not found or non-functional. Attempting install/repair..."
                self.logger.log_message(self.setup_message)
                if not await self._install_wsl():
                    self.setup_message = "❌ WSL installation failed."
                else:
                    self.setup_message = "-> WSL setup started. Please restart your PC."
                return

            # Step 2: Check if Nmap is installed inside WSL
            self.logger.log_message("✅ WSL is functional. Checking for Nmap installation...")
            if not await self._check_nmap_installed():
                self.logger.log_message("   - Nmap not found. Attempting installation via apt...")
                if not await self._install_nmap_in_wsl():
                    # Error message is set within the install method
                    return

            self.logger.log_message("   - ✅ Nmap is installed in WSL.")
            self.is_ready = True
            self.setup_message = "✅ WSL & Nmap are ready."
        finally:
            self.logger.log_message(f"[Nmap] Setup finished. Status: {self.setup_message}")
            on_complete_callback()

    async def _check_nmap_installed(self) -> bool:
        """
        Checks if Nmap is installed in the default WSL path OR in the custom tools directory.
        """
        try:
            # Check 1: Is 'nmap' in the default WSL PATH?
            self.logger.log_message("   - Checking for Nmap in default WSL PATH...")
            proc_path = await asyncio.create_subprocess_exec(
                self.wsl_path, "command", "-v", "nmap",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc_path.wait()
            if proc_path.returncode == 0:
                self.logger.log_message("   - ✅ Found Nmap in default PATH.")
                return True

            # Check 2: If not found, check the custom tools directory.
            self.logger.log_message("   - ℹ️ Nmap not found in default PATH. Checking tools directory...")
            nmap_in_tools_win_path = self.tools_dir / "usr" / "bin" / "nmap"

            # Convert the Windows path to its WSL equivalent for the check
            nmap_in_tools_wsl_path = await self._get_wsl_path_for_windows_path(nmap_in_tools_win_path)

            if not nmap_in_tools_wsl_path:
                self.logger.log_message(
                    f"   - ❌ Could not resolve tools directory path '{nmap_in_tools_win_path}' in WSL.")
                return False

            # Use 'test -f' to see if the file exists at that specific WSL path
            proc_tools = await asyncio.create_subprocess_exec(
                self.wsl_path, "test", "-f", nmap_in_tools_wsl_path,
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL
            )
            await proc_tools.wait()

            if proc_tools.returncode == 0:
                self.logger.log_message(f"   - ✅ Found Nmap in tools directory.")
                return True

            self.logger.log_message("   - ❌ Nmap not found.")
            return False

        except Exception as e:
            self.logger.log_message(f"   - ❌ An error occurred while checking for Nmap: {e}")
            return False
    # --- ADDED: Methods for managing the interactive session ---
    async def start_interactive_session(self):
        if self._interactive_session_process:
            self.logger.log_message("[WSL-Shell] An interactive session is already running."); return
        self.logger.log_message("[WSL-Shell] Starting interactive bash session...")
        try:
            self._interactive_session_process = await asyncio.create_subprocess_exec(
                self.wsl_path, "bash", "-i", stdin=asyncio.subprocess.PIPE,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            self.i_stdout_thread = threading.Thread(target=self.stream_output, args=(self._interactive_session_process.stdout, "Nmap"))
            self.i_stderr_thread = threading.Thread(target=self.stream_output, args=(self._interactive_session_process.stderr, "Nmap-ERR"))
            self.i_stdout_thread.start()
            self.i_stderr_thread.start()

            self.logger.log_message("[WSL-Shell] ✅ Session started.")
        except Exception as e:
            self.logger.log_message(f"[WSL-Shell] 💥 Failed to start session: {e}"); self._interactive_session_process = None
    async def stop_interactive_session(self):
        if not self._interactive_session_process: return
        self.logger.log_message("[WSL-Shell] Stopping interactive session...")
        for task in self._interactive_session_tasks: task.cancel()
        if self._interactive_session_process:
            self._interactive_session_process.terminate()
            self.i_stdout_thread.join()
            self.i_stderr_thread.join()
            await self._interactive_session_process.wait()
        self._interactive_session_process = None
        self.logger.log_message("[WSL-Shell] ⏹️ Session stopped.")

    async def send_command_to_session(self, command: str):
        """Sends a command string to the running interactive shell's stdin."""
        if not self._interactive_session_process or not self._interactive_session_process.stdin:
            self.logger.log_message("[WSL-Shell] ❌ Cannot send command: No active session.")
            return

        stdin = self._interactive_session_process.stdin
        # Add a newline to execute the command
        stdin.write(f"{command}\n".encode())
        await stdin.drain()

    async def _install_nmap_in_wsl(self) -> bool:
        """
        Installs Nmap in WSL using Snap and copies the binary to the tools directory.
        This opens a new terminal window to allow user input for the sudo password.
        """
        self.setup_message = "Installing Nmap in WSL via external terminal..."
        self.logger.log_message(self.setup_message)

        try:
            wsl_tools_path_str = await self._get_wsl_path_for_windows_path(self.tools_dir)
            if not wsl_tools_path_str:
                self.setup_message = "❌ ERROR: Could not resolve WSL path for tools directory."
                self.logger.log_message(self.setup_message)
                return False

            nmap_dest_dir = f"{wsl_tools_path_str}/usr/bin"

            shell_command = (
                f"echo '--- Installing Nmap using Snap (requires sudo) ---' && "
                f"sudo snap install nmap && "
                f"echo '--- Copying Nmap to tools directory: {nmap_dest_dir} ---' && "
                f"mkdir -p {nmap_dest_dir} && "
                f"sudo cp /snap/bin/nmap {nmap_dest_dir}/ && "
                f"sudo chmod +x {nmap_dest_dir}/nmap && "
                f"echo; echo '✅ Nmap installation complete. You can close this window now.' && "
                f"read -p 'Press [Enter] to close...'"  # Wait for user input
            )

            # This is the corrected, more robust way to launch the process.
            # It calls wsl.exe directly and forces a new console window.
            self.logger.log_message("   - Launching in new console window...")
            subprocess.Popen(
                ["wsl.exe", "-e", "bash", "-c", shell_command],
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )

            self.logger.log_message(
                "   - 🕔 Installation running in new terminal. Please complete the sudo prompt there.")
            return True

        except FileNotFoundError:
            self.setup_message = "❌ ERROR: wsl.exe not found. Please ensure WSL is installed and in your system's PATH."
            self.logger.log_message(self.setup_message)
            return False
        except Exception as e:
            self.setup_message = f"❌ ERROR: An unexpected error occurred during installation: {e}"
            self.logger.log_message(self.setup_message)
            return False

        except FileNotFoundError:
            self.setup_message = "❌ ERROR: wsl.exe not found. Please ensure WSL is installed and in your system's PATH."
            self.logger.log_message(self.setup_message)
            return False
        except Exception as e:
            self.setup_message = f"❌ ERROR: An unexpected error occurred during installation: {e}"
            self.logger.log_message(self.setup_message)
            return False

    # (The rest of the class, including _run_scan, _check_wsl_functionality, etc., is correct and remains unchanged)
    async def start_scan(self, targets, arguments, on_complete_callback):
        """
        This is now a coroutine, ensuring it runs on the event loop
        and can safely create other tasks.
        """

        if self.status == "running":
            self.logger.log_message("[Nmap] ⚠️ Scan already running.")
            return
        if not self.is_ready:
            self.logger.log_message("[Nmap] ❌ Cannot start scan: Nmap is not ready.")
            return

        async def run_and_callback():
            try:
                xml_output = await self._run_scan(targets, arguments)
                if callable(on_complete_callback):
                    on_complete_callback(xml_output)
            except Exception as e:
                self.logger.log_message(f"[Nmap] 💥 Exception during scan task: {e}")
            finally:
                self.status = "idle"
                self._scan_task = None

        self.status = "running"
        self._scan_task = asyncio.create_task(run_and_callback())
        self.logger.log_message("[Nmap] ▶️ Nmap scan task started.")
    def stop_scan(self):
        if self.status != "running": return
        self.logger.log_message("[Nmap] ⏹️ Stop request received...")
        self.status = "stopping"
        if self._scan_task: self._scan_task.cancel()
        if self._scan_process: self._scan_process.terminate()
    def stream_output(self, stream, label):
        for line in iter(stream.readline, ''):
            self.logger.log_message(f"[{label}] {line.strip()}")
            self.stdout_capture.append(line)
        stream.close()

    async def _run_scan(self, targets: List[str], arguments: List[str]) -> str:
        """
        Runs an Nmap scan asynchronously within WSL, allowing for interactive sudo password entry.

        Args:
            targets: A list of target IP addresses or hostnames.
            arguments: A list of Nmap command-line arguments.

        Returns:
            A string containing the Nmap XML output or an <error> tag on failure.
        """
        self.logger.log_message("[Nmap] 🚀 Preparing interactive scan...")
        # 1. Resolve Nmap path.
        if not self.nmap_wsl_path:
            nmap_windows_path = self.tools_dir / "usr" / "bin" / "nmap"
            self.nmap_wsl_path = await self._get_wsl_path_for_windows_path(nmap_windows_path)
            if not self.nmap_wsl_path:
                error_msg = "Could not resolve Nmap path inside WSL."
                self.logger.log_message(f"[Nmap] ❌ {error_msg}")
                return f"<error>{error_msg}</error>"

        # 2. Prepare commands for interactive session.
        # First, resolve the tools directory path for use inside WSL.
        wsl_tools_dir = await self._get_wsl_path_for_windows_path(self.tools_dir)
        if not wsl_tools_dir:
            error_msg = f"Could not resolve tools directory path '{self.tools_dir}' inside WSL."
            self.logger.log_message(f"[Nmap] ❌ {error_msg}")
            return f"<error>{error_msg}</error>"

        # Use a unique filename and construct the full WSL path for the output file.
        # Note the use of single quotes to handle potential spaces in paths.
        output_filename = f"nmap_output_{uuid.uuid4()}.xml"
        output_path = f"'{wsl_tools_dir}/{output_filename}'"
        all_targets = " ".join(targets)

        # The Nmap command saves output to the temp file.
        nmap_cmd = f"sudo {self.nmap_wsl_path} {' '.join(arguments)} -oX {output_path} {all_targets}"

        # 'script' is used to force TTY allocation, which sudo requires for password prompts.
        # The output of 'script' itself is sent to /dev/null.
        script_cmd = f"script -q -c '{nmap_cmd}; echo Press Enter to continue...; read' /dev/null"

        # The final command to be run in a new console window.
        interactive_command = [self.wsl_path, "bash", "-c", script_cmd]
        self.logger.log_message(f"[Nmap] 🚀 Launching interactive console for command: {script_cmd}")

        try:
            # 3. Launch the interactive scan in a new console window.
            # We don't pipe stdio, allowing direct user interaction.
            self._scan_process = await asyncio.create_subprocess_exec(
                *interactive_command,
                creationflags=subprocess.CREATE_NEW_CONSOLE
            )
            return_code = await self._scan_process.wait()

            if return_code != 0:
                error_msg = f"Scan process exited with code {return_code}. Check the console window for details."
                self.logger.log_message(f"[Nmap] ❌ {error_msg}")
                return f"<error>{error_msg}</error>"

            self.logger.log_message("[Nmap] ✅ Interactive scan completed. Fetching results...")

            # 4. Read the XML output from the temporary file in WSL.
            read_command = [self.wsl_path, "cat", output_path]
            read_proc = await asyncio.create_subprocess_exec(
                *read_command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await read_proc.communicate()

            if read_proc.returncode != 0:
                error_msg = stderr.decode(errors='ignore').strip()
                self.logger.log_message(f"[Nmap] ❌ Failed to read output file: {error_msg}")
                return f"<error>Failed to read Nmap output file: {error_msg}</error>"

            xml_output = stdout.decode()
            self.logger.log_message(f"[Nmap-DBG] XML output size: {len(xml_output)} bytes.")

            # 5. Validate XML.
            try:
                ET.fromstring(xml_output)
                self.logger.log_message("[Nmap] ✅ XML output successfully validated.")
            except ET.ParseError as e:
                self.logger.log_message(f"[Nmap] ⚠️ XML parse error: {e}")
                return f"<error>Malformed XML output received from Nmap: {e}</error>"

            return xml_output

        except FileNotFoundError:
            self.logger.log_message("[Nmap] 💥 Critical Error: wsl.exe not found.")
            return "<error>wsl.exe not found. Please ensure WSL is installed and in your PATH.</error>"
        except Exception as e:
            self.logger.log_message(f"[Nmap] 💥 An unexpected exception occurred: {e}")
            return f"<error>Scan failed with an unexpected exception: {e}</error>"
        finally:
            # 6. Clean up the temporary file from WSL.
            self.logger.log_message(f"[Nmap] 🧹 Cleaning up temporary file: {output_path}")
            cleanup_command = [self.wsl_path, "rm", "-f", output_path]
            await asyncio.create_subprocess_exec(*cleanup_command)

            self._scan_process = None
            self.logger.log_message("[Nmap] ✅ Scan complete.")
    def _find_wsl_executable(self):
        path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe")
        return path if os.path.exists(path) else None

    def _is_admin(self):
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False

    async def _check_wsl_functionality(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(self.wsl_path, "-l", "-v", stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False

    async def _install_wsl(self) -> bool:
        if not self._is_admin(): self.logger.log_message(
            "❌ ERROR: WSL install requires admin privileges."); return False
        try:
            subprocess.Popen('start cmd.exe /k "wsl --install"', shell=True); return True
        except Exception as e:
            self.logger.log_message(f"❌ Failed to launch installer: {e}"); return False


    async def _get_wsl_path_for_windows_path(self, windows_path: Path) -> str | None:
        """
        Converts a Windows path to its WSL equivalent. It first tries the reliable
        'wslpath' command and falls back to manual path construction and
        verification if that fails.
        """
        # --- Attempt 1: Use the standard wslpath tool ---
        try:
            proc = await asyncio.create_subprocess_exec(
                self.wsl_path, "wslpath", "-a", str(windows_path),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                wsl_path = stdout.decode().strip()
                self.logger.log_message(f"   - Successfully converted path using wslpath: {wsl_path}")
                return wsl_path
            else:
                raise RuntimeError(f"wslpath failed: {stderr.decode().strip()}")
        except Exception as e:
            self.logger.log_message(f"   - wslpath command failed: {e}. Attempting manual fallback...")

        # --- Attempt 2: Manual fallback for non-standard drives ---
        try:
            win_path_str = str(windows_path.resolve())
            drive, path_no_drive = os.path.splitdrive(win_path_str)

            if not drive:
                self.logger.log_message("   - Manual fallback failed: Path has no drive letter.")
                return None

            drive_letter = drive.replace(":", "").lower()
            manual_path = f"/mnt/{drive_letter}{path_no_drive.replace(os.sep, '/')}"
            self.logger.log_message(f"   - Manually constructed path: {manual_path}. Verifying access...")

            # --- THE FIX IS HERE ---
            # Use 'test -e' to check if the path EXISTS (file or directory).
            # The old code used 'test -d' which only checks for directories.
            verify_proc = await asyncio.create_subprocess_exec(
                self.wsl_path, "test", "-e", manual_path,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            await verify_proc.wait()
            # ---------------------

            if verify_proc.returncode == 0:
                self.logger.log_message("   - ✅ Manual path verification successful.")
                return manual_path
            else:
                self.logger.log_message("   - ❌ Manual path verification failed. WSL cannot access this path.")
                return None
        except Exception as e:
            self.logger.log_message(f"   - ❌ Manual path fallback failed with an exception: {e}")
            return None

class AsyncGobusterManager(QObject):
    """An asynchronous manager for running Gobuster through WSL."""
    # Signals for GUI updates
    gobuster_process_started_signal = pyqtSignal()
    gobuster_new_result_signal = pyqtSignal(str)  # Emits each found URL or relevant line
    gobuster_scan_finished_signal = pyqtSignal(str) # Emits final status/error message
    def __init__(self, logger, async_loop, manual_gobuster_path: str = None):
        super().__init__()
        self._current_target_url = None
        self.logger = logger
        self.async_loop = async_loop
        self.wsl_path = self._find_wsl_executable()
        self.is_ready = False
        self.setup_message = "Ready to initialize."
        self.status = "idle"  # idle, initializing, ready, running, stopping, completed, error, cancelled
        if getattr(sys, "frozen", False):
            self.tools_dir = Path(sys._MEIPASS) / "tools" / "Linux"
        else:
            self.tools_dir = Path(__file__).resolve().parent / "tools" / "Linux"
        self.gobuster_wsl_path = self.tools_dir / "gobuster" # Will be set to the validated WSL path of the manual binary
        self.default_wsl_wordlist_path = self.tools_dir / "SecLists/Discovery/Web-Content/common.txt"  # Common SecLists path
        # Determine the base path for the application (handles PyInstaller bundling)
        if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
            # Running in a PyInstaller bundle
            self.base_path = Path(sys._MEIPASS)
        else:
            # Running in a normal Python environment
            self.base_path = Path(__file__).resolve().parent
        # Construct the manual Gobuster path relative to the base_path
        if manual_gobuster_path:
            self._manual_gobuster_path_windows = (self.base_path / manual_gobuster_path).resolve()
            self.logger.log_message(f"Manual Gobuster path provided (Windows): {self._manual_gobuster_path_windows}")
        else:
            self._manual_gobuster_path_windows = None
            self.logger.log_message(
                "No manual Gobuster path provided. Manager will rely on default WSL 'gobuster' or not be ready.")
        self._manual_gobuster_path_wsl = None  # To store the converted WSL path
        self._scan_task = None
        self._scan_process = None
    async def initialize(self, on_complete_callback):
        """
        Asynchronously ensures WSL is functional and Gobuster is installed
        at the provided manual path. Also ensures wordlists are present.
        """
        self.logger.log_message("🚀 Starting asynchronous WSL & Gobuster setup (manual path only)...")
        self.is_ready = False
        self.status = "initializing"
        try:
            # Step 1: Verify WSL is working
            if not self.wsl_path or not await self._check_wsl_functionality():
                self.setup_message = "⚠️ WSL not found or non-functional. Please ensure WSL is installed and working."
                self.logger.log_message(self.setup_message)
                if not self.wsl_path and self._is_admin():
                    self.setup_message += " Attempting WSL install..."
                    self.logger.log_message(self.setup_message)
                    if await self._install_wsl():
                        self.setup_message = "-> WSL setup initiated. Please restart your PC."
                    else:
                        self.setup_message = "❌ WSL installation failed. Please install manually."
                self.status = "error"
                return
            self.logger.log_message("✅ WSL is functional.")
            # Step 2: Handle manual Gobuster path
            if self._manual_gobuster_path_windows:
                if not self._manual_gobuster_path_windows.exists():
                    self.setup_message = f"❌ ERROR: Manual Gobuster binary not found at specified path: {self._manual_gobuster_path_windows}. Please ensure the file exists."
                    self.logger.log_message(self.setup_message)
                    self.status = "error"
                    return
                self.logger.log_message(f"✅ Manual Gobuster binary detected at: {self._manual_gobuster_path_windows}")
                self._manual_gobuster_path_wsl = await self._get_wsl_path_for_windows_path(
                    self._manual_gobuster_path_windows)
                if not self._manual_gobuster_path_wsl:
                    self.setup_message = f"❌ ERROR: Failed to convert/verify manual Gobuster path in WSL: {self._manual_gobuster_path_windows}. Please check path validity or permissions."
                    self.logger.log_message(self.setup_message)
                    self.status = "error"
                    return
                self.logger.log_message(
                    f"   - Checking/setting execute permissions for {self._manual_gobuster_path_wsl} in WSL...")
                chmod_proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "chmod", "+x", self._manual_gobuster_path_wsl,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                stdout, stderr = await chmod_proc.communicate()
                if chmod_proc.returncode != 0:
                    self.logger.log_message(
                        f"   - ⚠️ Failed to set execute permissions via chmod: {stderr.decode().strip()}. This might cause issues.")
                else:
                    self.logger.log_message("   - ✅ Execute permissions set (or already present) for Gobuster binary.")
                exec_check_proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "test", "-x", self._manual_gobuster_path_wsl,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await exec_check_proc.wait()
                if exec_check_proc.returncode == 0:
                    self.gobuster_wsl_path = self._manual_gobuster_path_wsl
                    self.logger.log_message(
                        f"   - ✅ Manual Gobuster binary is executable in WSL: {self.gobuster_wsl_path}")
                else:
                    self.setup_message = f"❌ ERROR: Manual Gobuster binary not executable in WSL: {self._manual_gobuster_path_wsl}. Please ensure it's a valid Linux binary."
                    self.logger.log_message(self.setup_message)
                    self.is_ready = False
                    self.status = "error"
                    return
            else:
                # If no manual path provided, fall back to checking if 'gobuster' is in WSL's PATH
                self.logger.log_message("No manual Gobuster path provided. Checking for 'gobuster' in WSL's PATH.")
                if not await self._check_gobuster_installed():  # This checks 'gobuster' in WSL PATH
                    self.setup_message = "❌ ERROR: No manual Gobuster path provided and 'gobuster' not found in WSL's PATH. Cannot proceed."
                    self.logger.log_message(self.setup_message)
                    self.is_ready = False
                    self.status = "error"
                    return
                else:
                    self.gobuster_wsl_path = "gobuster"  # Set to default 'gobuster'
                    self.logger.log_message("✅ 'gobuster' found in WSL's PATH.")
            # Step 3: Ensure Wordlists are installed in WSL
            if not await self._check_wordlist_installed(self.default_wsl_wordlist_path):
                self.logger.log_message(
                    f"   - Required wordlist '{self.default_wsl_wordlist_path}' not found. Attempting automatic installation of SecLists...")
                if not await self._install_wordlists_in_wsl():
                    self.setup_message = f"❌ ERROR: Failed to install wordlists in WSL. {self.setup_message}"
                    self.is_ready = False
                    self.status = "error"
                    return
            self.logger.log_message("   - ✅ Wordlists are installed in WSL.")
            self.is_ready = True
            self.setup_message = "✅ WSL, Gobuster, and Wordlists are ready."
            self.status = "ready"
        except Exception as e:
            self.logger.log_message(f"💥 An unexpected error occurred during setup: {e}")
            self.setup_message = f"❌ An unexpected error occurred: {e}"
            self.is_ready = False
            self.status = "error"
        finally:
            self.logger.log_message(f"[Gobuster] Setup finished. Status: {self.setup_message}")
            if on_complete_callback:
                self.async_loop.call_soon_threadsafe(on_complete_callback)
    async def _check_gobuster_installed(self) -> bool:
        """
        Checks if the 'gobuster' command is available in the WSL path (if not using a manual path)
        or if the manually provided path is executable.
        """
        if self.gobuster_wsl_path:
            # If a manual path was set, check it directly
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "test", "-x", self.gobuster_wsl_path,
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()
                return proc.returncode == 0
            except Exception:
                return False
        else:
            # Otherwise, check if 'gobuster' is in WSL's PATH
            try:
                proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "command", "-v", "gobuster",
                    stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
                )
                await proc.wait()
                return proc.returncode == 0
            except Exception:
                return False
    async def _check_wordlist_installed(self, wsl_wordlist_path: str) -> bool:
        """Checks if a specific wordlist file exists in WSL."""
        try:
            proc = await asyncio.create_subprocess_exec(
                self.wsl_path, "test", "-f", wsl_wordlist_path,  # -f tests if it's a regular file
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL
            )
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            return False
    def _check_wordlist_exists_in_wsl(self, wsl_file_path: str) -> bool:
        """
        Checks if a given file exists in WSL using the 'test -f' command.
        This method now expects a WSL-formatted path.
        """
        try:
            # Use 'test -f' in bash to check for file existence
            # This is more reliable than trying to parse 'ls' output
            command = f"test -f \"{wsl_file_path}\""
            result = subprocess.run(
                [self.wsl_path, 'bash', '-c', command],
                capture_output=True,
                check=False,  # Don't raise an exception for non-zero exit code (file not found)
            )
            return result.returncode == 0  # returncode 0 means success (file exists)
        except Exception as e:
            self.logger.log_message(f"ERROR checking wordlist existence in WSL for {wsl_file_path}: {e}")
            return False
    async def _install_wordlists_in_wsl(self) -> bool:
        """
        Installs SecLists wordlists in WSL by launching a single command in a new console,
        ensuring TTY allocation for sudo prompts. This method is now asynchronous.
        """
        self.setup_message = "Installing wordlists in WSL..."
        self.logger.log_message(self.setup_message)
        try:
            SECLISTS_REPO = "https://github.com/danielmiessler/SecLists.git"
            windows_seclists_target_dir = self.tools_dir / "SecLists"
            windows_parent_dir = windows_seclists_target_dir.parent
            # *** CRITICAL CHANGE: Get WSL paths in Python BEFORE constructing the bash string ***
            # This leverages your existing _get_wsl_path_for_windows_path which has fallback logic.
            actual_wsl_seclists_target_dir = await self._get_wsl_path_for_windows_path(windows_seclists_target_dir)
            actual_wsl_parent_dir = await self._get_wsl_path_for_windows_path(windows_parent_dir)
            if not actual_wsl_seclists_target_dir or not actual_wsl_parent_dir:
                self.setup_message = "❌ ERROR: Failed to translate SecLists paths for WSL. Installation aborted."
                self.logger.log_message(self.setup_message)
                return False
            windows_check_file = windows_seclists_target_dir / "Discovery" / "Web-Content" / "common.txt"
            # Use the already translated wsl_check_file_path for initial existence check
            wsl_check_file_path = await self._get_wsl_path_for_windows_path(windows_check_file)
            if wsl_check_file_path and await self._check_wordlist_installed(wsl_check_file_path):
                self.logger.log_message("   - ✅ Required wordlist already detected in WSL. Skipping installation.")
                return True
            # Construct a single, comprehensive command string for bash
            # Now, directly use the *translated WSL paths* obtained from Python
            # This bypasses the need for `wslpath -u` inside the bash script itself for these variables.
            wsl_installation_commands_bash_string = (
                # Optional debug print of the translated paths
                f"echo 'Using Translated WSL Target Dir: {actual_wsl_seclists_target_dir}' && "
                f"echo 'Using Translated WSL Parent Dir: {actual_wsl_parent_dir}' && "
                "echo '---' && "
                "sudo apt-get update && "  # Update package lists
                "sudo apt-get install -y git && "  # Install git
                f"sudo mkdir -p \"{actual_wsl_parent_dir}\" && "  # Create parent directory (if not exists)
                f"sudo git clone --depth 1 {SECLISTS_REPO} \"{actual_wsl_seclists_target_dir}\" && "  # Shallow clone SecLists
                "echo 'SecLists installation attempt finished. You can close this window now.' && "
                "read -p 'Press Enter to close this window...'"  # Always keep for debugging until stable
            )
            self.logger.log_message("   - Launching wordlist installation in a new console window...")
            self.logger.log_message("     👉 Please monitor the new window for progress and any sudo password prompts.")
            self.logger.log_message("     👉 You MUST type your WSL password if prompted in that window.")
            self.logger.log_message("     👉 Installation might take some time (cloning SecLists).")
            subprocess.Popen(
                [self.wsl_path, 'bash', '-c', '-i', wsl_installation_commands_bash_string],
                creationflags=subprocess.CREATE_NEW_CONSOLE,
            )
            self.logger.log_message("   - ✅ Wordlist installation command launched. Waiting for completion...")
            max_wait = 1800
            interval = 10
            waited = 0
            while waited < max_wait:
                if wsl_check_file_path and await self._check_wordlist_installed(wsl_check_file_path):
                    self.logger.log_message("   - ✅ SecLists detected in WSL.")
                    return True
                await asyncio.sleep(interval)
                waited += interval
                self.logger.log_message(f"     ...still waiting ({waited}/{max_wait}s)...")
            self.logger.log_message("   - ❌ Timeout: SecLists installation not completed within expected time.")
            return False
        except Exception as e:
            self.setup_message = f"❌ ERROR: Unexpected error during wordlist installation: {e}"
            self.logger.log_message(self.setup_message)
            return False

    async def start_scan(self, target_url: str, wordlist_path: str = None, arguments: list = None,
                         on_complete_callback=None):
        try:
            if self.status == "running":
                self.logger.log_message("[Gobuster] ⚠️ Scan already running.")
                return
            if not self.is_ready:
                self.logger.log_message(f"[Gobuster] ❌ Cannot start scan: {self.setup_message}")
                return
            if not self.gobuster_wsl_path:
                self.logger.log_message("[Gobuster] ❌ Gobuster WSL path is not configured.")
                return

            final_wsl_wordlist_path = None
            if wordlist_path:
                try:
                    windows_wordlist_path = Path(wordlist_path)
                    if not windows_wordlist_path.exists():
                        self.logger.log_message(
                            f"⚠️ Provided wordlist not found on Windows: {wordlist_path}. Trying fallback."
                        )
                    else:
                        wsl_converted_path = await self._get_wsl_path_for_windows_path(windows_wordlist_path)
                        if wsl_converted_path and await self._check_wordlist_installed(wsl_converted_path):
                            final_wsl_wordlist_path = wsl_converted_path
                            self.logger.log_message(f"✅ Using converted WSL path: {final_wsl_wordlist_path}")
                        else:
                            self.logger.log_message(f"⚠️ Converted WSL wordlist invalid. Falling back.")
                except Exception as e:
                    self.logger.log_message(f"⚠️ Error converting wordlist: {e}. Will fall back to default.")

            if not final_wsl_wordlist_path:
                converted_default = await self._get_wsl_path_for_windows_path(self.default_wsl_wordlist_path)
                if converted_default and await self._check_wordlist_installed(converted_default):
                    final_wsl_wordlist_path = converted_default
                    self.logger.log_message(f"✅ Using fallback default wordlist: {final_wsl_wordlist_path}")
                else:
                    error_msg = f"❌ ERROR: Default wordlist missing or inaccessible: {converted_default}"
                    self.logger.log_message(error_msg)
                    self.status = "error"
                    if on_complete_callback:
                        self.async_loop.call_soon_threadsafe(
                            lambda: on_complete_callback(f"<error>{error_msg}</error>")
                        )
                    return

            # --- CRITICAL CHANGE HERE ---
            # Manually quote the gobuster_wsl_path and final_wsl_wordlist_path
            # This ensures Bash treats paths with spaces as single arguments.
            # Use shlex.quote for robust quoting if paths can contain complex characters
            import shlex
            quoted_gobuster_path = shlex.quote(str(self.gobuster_wsl_path))
            quoted_wordlist_path = shlex.quote(final_wsl_wordlist_path)

            # Construct the command string to be executed by bash -c
            # The gobuster arguments themselves (target_url, arguments) should NOT be quoted here,
            # as they are distinct arguments for gobuster.
            # Bash will handle splitting the string and executing it.
            gobuster_base_cmd = f"{quoted_gobuster_path} dir -u {shlex.quote(target_url)} -w {quoted_wordlist_path}"

            # Append additional arguments, ensuring they are also quoted for robustness
            if arguments:
                gobuster_base_cmd += " " + " ".join([shlex.quote(arg) for arg in arguments])

            # The full command to pass to wsl.exe bash -c
            # We are providing a single string to bash -c, so it needs to be syntactically correct Bash.
            full_wsl_command = [self.wsl_path, "bash", "-c", gobuster_base_cmd]

            full_command_str_for_logging = ' '.join(full_wsl_command)  # for logging only
            self.logger.log_message(f"[Gobuster] 🚀 Running: {full_command_str_for_logging}")

            self.status = "running"
            self._current_target_url = target_url.strip().rstrip('/')
            self._scan_task = asyncio.create_task(self._run_and_callback(full_wsl_command, on_complete_callback))
            self.logger.log_message("[Gobuster] ▶️ Gobuster scan task started.")

        except Exception:
            self.status = "error"
            error_msg = f"[Gobuster] 💥 Exception during start_scan:\n{traceback.format_exc()}"
            self.logger.log_message(error_msg)
            if on_complete_callback:
                self.async_loop.call_soon_threadsafe(
                    lambda: on_complete_callback(f"<error>{error_msg}</error>")
                )
    async def _run_and_callback(self, command, on_complete_callback):
        final_message = ""
        try:
            self._scan_process = await asyncio.create_subprocess_exec(
                *command,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            self.async_loop.call_soon_threadsafe(self.gobuster_process_started_signal.emit)
            self.logger.log_message(f"[Gobuster-DBG] Subprocess created. PID: {self._scan_process.pid}")
            self.logger.log_message(f"[Gobuster-DBG] Starting concurrent streaming...")

            await asyncio.gather(
                self._stream_gobuster_stdout_for_results(self._scan_process.stdout, "Gobuster-out"),
                self._stream_gobuster_stderr(self._scan_process.stderr, "Gobuster-err")
            )

            await self._scan_process.wait()
            return_code = self._scan_process.returncode

            if return_code == 0:
                self.status = "completed"
                final_message = "Gobuster scan completed successfully."
            else:
                self.status = "error"
                # Read any remaining stderr for error messages if process exited with non-zero
                stderr_output = (await self._scan_process.stderr.read()).decode(errors='ignore').strip()
                final_message = f"<error>Gobuster scan failed with exit code {return_code}. Stderr: {stderr_output}</error>"

        except asyncio.CancelledError:
            self.status = "cancelled"
            final_message = "<error>Gobuster scan was cancelled.</error>"
        except Exception as e:
            self.logger.log_message(f"[Gobuster] 💥 Scan exception: {e}\n{traceback.format_exc()}")
            self.status = "error"
            final_message = f"<error>Exception occurred: {e}</error>"
        finally:
            self.logger.log_message(f"[Gobuster] ✅ Scan finished with status: {self.status}.")
            self._scan_process = None
            if on_complete_callback:
                self.gobuster_scan_finished_signal.emit(final_message)
                self.async_loop.call_soon_threadsafe(lambda: on_complete_callback(final_message))


    def stop_scan(self):
        if self.status != "running" and self.status != "stopping":
            self.logger.log_message("[Gobuster] Not running or stopping.")
            return

        self.logger.log_message("[Gobuster] ⏹️ Stop request received...")
        self.status = "stopping"

        if self._scan_task:
            self.logger.log_message("[Gobuster-DBG] Cancelling scan task.")
            self._scan_task.cancel()
            # No need to await here, it will be handled in _run_and_callback's finally block
        if self._scan_process and self._scan_process.returncode is None:
            self.logger.log_message("[Gobuster-DBG] Terminating Gobuster process.")
            try:
                self._scan_process.terminate()
            except ProcessLookupError:
                self.logger.log_message("[Gobuster-DBG] Process already terminated or not found.")

    async def _stream_gobuster_stdout_for_results(self, stream, prefix):
        """
        Reads from Gobuster's stdout line-by-line, logs each line, and emits
        found URLs/relevant output via signal.
        """
        while True:
            try:
                line_bytes = await stream.readline()
                if not line_bytes:
                    break
                line_str = line_bytes.decode(errors='ignore').strip()
                self.logger.log_message(f"[{prefix}] {line_str}")

                # Simple parsing for Gobuster output (lines starting with / or other indicators)
                # This logic is adapted from _parse_and_display_results in GobusterTab
                if line_str.startswith('/'):
                    full_url = f"{self._current_target_url}{line_str}"
                    self.logger.log_message(f"[{prefix}] Found: {full_url}")
                    self.async_loop.call_soon_threadsafe(lambda s=full_url: self.gobuster_new_result_signal.emit(s))
                elif line_str.startswith("http://") or line_str.startswith("https://"):
                    self.logger.log_message(f"[{prefix}] Found: {line_str}")
                    self.async_loop.call_soon_threadsafe(lambda s=line_str: self.gobuster_new_result_signal.emit(s))
                elif "Status:" in line_str or "Found:" in line_str:
                    self.logger.log_message(f"[{prefix}] Found line: {line_str}")
                    self.async_loop.call_soon_threadsafe(lambda s=line_str: self.gobuster_new_result_signal.emit(s))
                elif "Status:" in line_str or "Found:" in line_str:
                    # Catch lines that might be results not starting with /
                    self.async_loop.call_soon_threadsafe(lambda s=line_str: self.gobuster_new_result_signal.emit(s))

            except asyncio.CancelledError:
                self.logger.log_message(f"[{prefix}] Stream cancelled.")
                break
            except Exception as e:
                self.logger.log_message(f"[{prefix}] Error reading stream: {e}")
                break
        self.logger.log_message(f"[{prefix}] Stream finished.")


    async def _stream_gobuster_stderr(self, stream, prefix):
        """
        Streams Gobuster's stderr to the logger.
        """
        while True:
            try:
                line = await stream.readline()
                if not line:
                    break
                decoded_line = line.decode(errors='ignore').strip()
                self.logger.log_message(f"[{prefix}] {decoded_line}")
            except asyncio.CancelledError:
                self.logger.log_message(f"[{prefix}] Stream cancelled.")
                break
            except Exception as e:
                self.logger.log_message(f"[{prefix}] Error reading stream: {e}")
                break
        self.logger.log_message(f"[{prefix}] Stream finished.")

    def _find_wsl_executable(self):
        path = os.path.join(os.environ.get("SystemRoot", "C:\\Windows"), "System32", "wsl.exe")
        return path if os.path.exists(path) else None
    def _is_admin(self):
        """Checks if the current Python process is running with administrator privileges."""
        try:
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        except:
            return False
    async def _check_wsl_functionality(self) -> bool:
        try:
            proc = await asyncio.create_subprocess_exec(self.wsl_path, "-l", "-v", stdout=asyncio.subprocess.PIPE,
                                                        stderr=asyncio.subprocess.PIPE)
            await proc.wait()
            return proc.returncode == 0
        except Exception:
            self.logger.log_message("Error checking WSL functionality. Is WSL installed?")
            return False
    async def _install_wsl(self) -> bool:
        if not self._is_admin():
            self.logger.log_message("❌ ERROR: WSL install requires administrator privileges. Please run as admin.")
            return False
        try:
            self.logger.log_message("Attempting to initiate WSL installation. A new command prompt window will open.")
            subprocess.Popen('start cmd.exe /k "wsl --install"', shell=True)
            self.logger.log_message(
                "WSL installation command launched. Please follow the instructions in the new window and restart your PC if prompted.")
            return True
        except Exception as e:
            self.logger.log_message(f"❌ Failed to launch WSL installer: {e}")
            return False
    async def _stream_output(self, stream, prefix):
        while True:
            try:
                line = await stream.readline()
                if not line: break
                decoded_line = line.decode(errors='ignore').strip()
                self.logger.log_message(f"[{prefix}] {decoded_line}")
            except asyncio.CancelledError:
                self.logger.log_message(f"[{prefix}] Stream cancelled.")
                break
            except Exception as e:
                self.logger.log_message(f"[{prefix}] Error reading stream: {e}")
                break
        self.logger.log_message(f"[{prefix}] Stream finished.")
    async def _get_wsl_path_for_windows_path(self, windows_path: Path) -> str | None:
        """
        Converts a Windows path to its WSL equivalent. It first tries the reliable
        'wslpath' command and falls back to manual path construction and
        verification if that fails.
        """
        windows_path_str = str(windows_path.resolve())  # Ensure absolute path and string for wslpath
        # Attempt wslpath -a first
        try:
            # Use -a to ensure absolute path, even if it's not strictly needed for existing files
            # It seems your issue is the input string to wslpath. Let's ensure it's quoted.
            proc = await asyncio.create_subprocess_exec(
                self.wsl_path, "wslpath", "-a", windows_path_str,
                # Removed quotes around windows_path_str, wslpath handles arguments directly
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
            )
            stdout, stderr = await proc.communicate()
            if proc.returncode == 0:
                wsl_path = stdout.decode().strip()
                self.logger.log_message(f"   - Successfully converted path using wslpath: {wsl_path}")
                return wsl_path
            else:
                # Log the full stderr from wslpath to diagnose malformed input issue
                wslpath_stderr = stderr.decode().strip()
                self.logger.log_message(
                    f"   - wslpath command failed (return code {proc.returncode}): {wslpath_stderr}. Input was: '{windows_path_str}'")
                raise RuntimeError(f"wslpath failed: {wslpath_stderr}")
        except Exception as e:
            self.logger.log_message(f"   - wslpath command failed: {e}. Attempting manual fallback...")
        # Manual Fallback
        try:
            drive, path_no_drive = os.path.splitdrive(windows_path_str)
            if not drive:
                self.logger.log_message("   - Manual fallback failed: Path has no drive letter.")
                return None
            drive_letter = drive.replace(":", "").lower()
            # Important: Ensure path_no_drive starts with '/', otherwise it will be relative in WSL
            path_no_drive = path_no_drive.replace(os.sep, '/').lstrip('/')
            manual_path = f"/mnt/{drive_letter}/{path_no_drive}"
            self.logger.log_message(f"   - Manually constructed path: {manual_path}.")
            # --- CRITICAL CHANGE HERE ---
            # Only verify existence if the Windows path *actually exists*.
            # For target directories that will be created, we just need the translation.
            if windows_path.exists():
                self.logger.log_message(f"   - Verifying access for existing path in WSL...")
                verify_proc = await asyncio.create_subprocess_exec(
                    self.wsl_path, "test", "-e", manual_path,
                    stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE
                )
                await verify_proc.wait()
                if verify_proc.returncode == 0:
                    self.logger.log_message("   - ✅ Manual path verification successful.")
                    return manual_path
                else:
                    stderr_output = (await verify_proc.stderr.read()).decode().strip()
                    self.logger.log_message(
                        f"   - ❌ Manual path verification failed (return code {verify_proc.returncode}). WSL cannot access this path. Stderr: {stderr_output}")
                    return None
            else:
                # If the Windows path doesn't exist, we assume it's a target path to be created.
                # We return the translated path without verifying existence.
                self.logger.log_message(
                    "   - Windows path does not exist; returning translated path for future creation.")
                return manual_path
        except Exception as e:
            self.logger.log_message(f"   - ❌ Manual path fallback failed with an exception: {e}")
            return None

class AsyncScrapingManager(QObject):
    """
    An asynchronous manager for performing web scraping operations.
    Uses Playwright for JavaScript rendering and BeautifulSoup for parsing.
    Designed to integrate with PyQt5 signals and asyncio.

    PyInstaller / missing-browser support:
      - If Playwright launch fails due to missing browsers, this class will
        run `python -m playwright install chromium` once and retry.
      - In frozen (PyInstaller) builds, it installs into the normal user cache,
        NOT _MEIPASS, so it persists across runs.
    """

    scraping_started_signal = pyqtSignal()
    scraping_finished_signal = pyqtSignal(dict)
    scraping_progress_signal = pyqtSignal(str)

    def __init__(self, logger, async_loop):
        super().__init__()
        self.logger = logger
        self.async_loop = async_loop
        self.status = "idle"
        self._scrape_task = None
        self._current_url = None

    async def initialize(self, on_complete_callback=None):
        self.logger.log_message("[Scraper] Initializing scraping manager...")
        self.status = "ready"
        self.logger.log_message("[Scraper] Manager is ready.")
        if on_complete_callback:
            self.async_loop.call_soon_threadsafe(on_complete_callback)

    async def start_scrape(self, url: str, delay_seconds: int, on_complete_callback=None):
        if self.status == "running":
            self.logger.log_message("[Scraper] ⚠️ Scraping already in progress.")
            return

        self._current_url = url.strip()
        if not self._current_url:
            error_msg = "URL cannot be empty."
            self.logger.log_message(f"[Scraper] ❌ {error_msg}")
            self.status = "error"
            if on_complete_callback:
                self.async_loop.call_soon_threadsafe(lambda: on_complete_callback({"error": error_msg}))
            return

        self.logger.log_message(
            f"[Scraper] ▶️ Starting scrape for: {self._current_url} with a {delay_seconds}s delay."
        )
        self.status = "running"
        self.scraping_started_signal.emit()

        async def run_and_callback():
            scraped_data = {"error": "Unknown error during scrape."}
            try:
                scraped_data = await self._perform_scrape(self._current_url, delay_seconds)
            except asyncio.CancelledError:
                self.logger.log_message("[Scraper] ⏹️ Scrape task cancelled.")
                scraped_data = {"error": "Scrape cancelled."}
                self.status = "cancelled"
            except Exception as e:
                self.logger.log_message(
                    f"[Scraper] 💥 Exception during scrape task: {e}\n{traceback.format_exc()}"
                )
                scraped_data = {"error": f"Scrape failed: {str(e)}"}
                self.status = "error"
            finally:
                self.logger.log_message(f"[Scraper] ✅ Scrape finished with status: {self.status}.")
                self._scrape_task = None
                if on_complete_callback:
                    self.async_loop.call_soon_threadsafe(lambda: on_complete_callback(scraped_data))
                self.scraping_finished_signal.emit(scraped_data)

        self._scrape_task = self.async_loop.create_task(run_and_callback())

    def stop_scrape(self):
        if self.status != "running":
            self.logger.log_message("[Scraper] Not running or stopping.")
            return

        self.logger.log_message("[Scraper] ⏹️ Stop request received...")
        self.status = "stopping"
        if self._scrape_task:
            self._scrape_task.cancel()

    # ------------------------------------------------------------------
    # Playwright self-contained helpers
    # ------------------------------------------------------------------

    def _is_missing_playwright_browser_error(self, err: Exception) -> bool:
        """
        Detect the "please run playwright install" / missing executable errors.
        """
        s = str(err)
        needles = [
            "Executable doesn't exist",
            "playwright install",
            ".local-browsers",
            "BrowserType.launch",
            "chromium-",
        ]
        return any(n in s for n in needles)

    def _persistent_browsers_path(self) -> str:
        """
        Where BOTH the frozen app and global-python installs will put browsers.
        Use user-writable persistent location.
        """
        # Prefer Playwright default cache location:
        # %LOCALAPPDATA%\ms-playwright  (Windows)
        local_appdata = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        p = Path(local_appdata) / "ms-playwright"
        p.mkdir(parents=True, exist_ok=True)
        return str(p)

    def _bundled_playwright_version(self) -> str | None:
        """
        Read playwright version from the environment the app is running in.
        """
        try:
            import playwright
            return getattr(playwright, "__version__", None)
        except Exception:
            return None

    def _candidate_pythons(self) -> list[str]:
        cands = []
        env_exe = os.environ.get("PYTHON_EXE")
        if env_exe and Path(env_exe).exists():
            cands.append(env_exe)

        py_launcher = shutil.which("py")
        if py_launcher:
            cands.append(py_launcher)

        for name in ("python3", "python"):
            p = shutil.which(name)
            if p:
                cands.append(p)

        out, seen = [], set()
        for c in cands:
            if c not in seen:
                out.append(c);
                seen.add(c)
        return out

    def _python_has_playwright(self, py: str) -> bool:
        try:
            if Path(py).name.lower() in ("py.exe", "py"):
                cmd = [py, "-3", "-c", "import playwright; print(playwright.__version__)"]
            else:
                cmd = [py, "-c", "import playwright; print(playwright.__version__)"]
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                  text=True, timeout=15)
            return proc.returncode == 0
        except Exception:
            return False

    def _pip_install_playwright(self, py: str, version: str | None) -> bool:
        """
        Install playwright into global python, pinned to bundled version if known.
        """
        try:
            pkg = f"playwright=={version}" if version else "playwright"
            if Path(py).name.lower() in ("py.exe", "py"):
                cmd = [py, "-3", "-m", "pip", "install", "--upgrade", pkg]
            else:
                cmd = [py, "-m", "pip", "install", "--upgrade", pkg]

            self.logger.log_message(f"[Scraper] 🔧 Installing playwright package: {' '.join(cmd)}")
            proc = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                  text=True, timeout=60 * 5)
            self.logger.log_message("[Scraper] pip install playwright output:\n" + proc.stdout)
            return proc.returncode == 0
        except Exception as e:
            self.logger.log_message(f"[Scraper] ❌ pip install playwright failed: {e}")
            return False

    def _run_playwright_install(self, browser: str = "chromium") -> bool:
        """
        Ensure global python has SAME playwright version as bundled app,
        then install browsers into a persistent path that the frozen app uses too.
        """
        try:
            bundled_ver = self._bundled_playwright_version()
            browsers_path = self._persistent_browsers_path()

            # find / choose a python
            cands = self._candidate_pythons()
            if not cands:
                self.logger.log_message("[Scraper] ❌ No global Python found; cannot auto-install Playwright.")
                return False

            py = None
            for c in cands:
                if self._python_has_playwright(c):
                    py = c
                    break
            if not py:
                py = cands[0]
                self.logger.log_message(
                    f"[Scraper] ⚠️ No python with Playwright found. Will install into: {py}"
                )
                if not self._pip_install_playwright(py, bundled_ver):
                    self.logger.log_message("[Scraper] ❌ Could not install playwright package.")
                    return False

            env = os.environ.copy()
            env.pop("PLAYWRIGHT_SKIP_BROWSER_DOWNLOAD", None)

            # CRITICAL: force install into the SAME persistent place your app will read from
            env["PLAYWRIGHT_BROWSERS_PATH"] = browsers_path

            if Path(py).name.lower() in ("py.exe", "py"):
                cmd = [py, "-3", "-m", "playwright", "install", browser]
            else:
                cmd = [py, "-m", "playwright", "install", browser]

            self.logger.log_message(f"[Scraper] 🔧 Running Playwright browser install: {' '.join(cmd)}")
            proc = subprocess.run(
                cmd, env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, timeout=60 * 8,
            )
            self.logger.log_message("[Scraper] Playwright install output:\n" + proc.stdout)

            if proc.returncode != 0:
                self.logger.log_message(
                    f"[Scraper] ❌ Playwright browser install failed with code {proc.returncode}"
                )
                return False

            self.logger.log_message(f"[Scraper] ✅ Playwright browsers installed into: {browsers_path}")
            return True

        except Exception as e:
            self.logger.log_message(f"[Scraper] ❌ Exception while installing Playwright browsers: {e}")
            return False

    async def _start_playwright_and_browser(self):
        playwright = None
        browser = None
        try:
            # CRITICAL: make bundled Playwright look in persistent cache, not _MEI local-browsers
            os.environ["PLAYWRIGHT_BROWSERS_PATH"] = self._persistent_browsers_path()

            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(
                headless=False,
                args=[
                    "--disable-blink-features=AutomationControlled",
                    "--no-sandbox",
                    "--disable-dev-shm-usage",
                    "--disable-gpu",
                ],
            )
            return playwright, browser

        except Exception as e:
            # Cleanup partial Playwright start if needed
            try:
                if browser and browser.is_connected():
                    await browser.close()
            except Exception:
                pass
            try:
                if playwright:
                    await playwright.stop()
            except Exception:
                pass

            if self._is_missing_playwright_browser_error(e):
                self.logger.log_message(
                    "[Scraper] ⚠️ Playwright browsers missing. Attempting automatic install..."
                )
                ok = self._run_playwright_install(browser="chromium")
                if not ok:
                    raise ValueError(f"Playwright error (auto-install failed): {e}")

                # Retry once after install
                playwright = await async_playwright().start()
                browser = await playwright.chromium.launch(
                    headless=False,
                    args=[
                        "--disable-blink-features=AutomationControlled",
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                    ],
                )
                return playwright, browser

            raise  # Not a missing-browser case; rethrow

    # ------------------------------------------------------------------

    async def _perform_scrape(self, url: str, delay_seconds: int) -> dict:
        self.scraping_progress_signal.emit("Launching browser for interaction...")
        self.logger.log_message(f"[Scraper-DBG] Launching visible Playwright for {url}")

        playwright = None
        browser = None
        headless_browser = None

        try:
            playwright, browser = await self._start_playwright_and_browser()

            context = await browser.new_context(accept_downloads=False)
            page = await context.new_page()

            await page.goto(url, timeout=60000)

            if delay_seconds > 0:
                self.scraping_progress_signal.emit(f"Waiting for {delay_seconds}s (load/login time)...")
                await page.wait_for_timeout(delay_seconds * 1000)

            self.scraping_progress_signal.emit("Extracting HTML and session data...")
            content = await page.content()
            storage_state = await context.storage_state()
            await browser.close()

            self.logger.log_message("[Scraper-DBG] Page content loaded. Parsing...")

            scraped_data = await self.async_loop.run_in_executor(
                None,
                lambda: self._parse_content(content, url)
            )
            scraped_data["html_content"] = content

            hardcoded_headers = {
                "User-Agent": (
                    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 (KHTML, like Gecko) "
                    "Chrome/91.0.4472.124 Safari/537.36"
                ),
                "Accept": "image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.9",
                "Accept-Encoding": "gzip, deflate, br",
            }

            self.scraping_progress_signal.emit("Downloading images...")
            failed_images = []
            for image_info in scraped_data.get("extracted_images", []):
                img_url = image_info["src"]
                try:
                    if img_url.startswith("data:image"):
                        _, encoded = img_url.split(",", 1)
                        image_info["data"] = base64.b64decode(encoded)
                    else:
                        if img_url.startswith("//"):
                            img_url = "https:" + img_url

                        headers_for_request = hardcoded_headers.copy()
                        headers_for_request["Referer"] = url

                        response = requests.get(img_url, headers=headers_for_request, timeout=10)
                        response.raise_for_status()
                        image_info["data"] = response.content

                except Exception:
                    self.logger.log_message(
                        f"[ImageDownloader] ⚠️ Request failed for {img_url[:100]}... "
                        f"Falling back to browser screenshot."
                    )
                    failed_images.append(image_info)

            if failed_images:
                self.scraping_progress_signal.emit("Retrying failed images with headless browser...")
                headless_browser = await playwright.chromium.launch(headless=True)
                headless_context = await headless_browser.new_context(
                    storage_state=storage_state,
                    extra_http_headers=hardcoded_headers,
                )

                for image_info in failed_images:
                    img_url = image_info["src"]
                    try:
                        if img_url.startswith("//"):
                            img_url = "https:" + img_url

                        img_page = await headless_context.new_page()
                        await img_page.goto(img_url, timeout=15000)

                        dimensions = await img_page.evaluate(
                            """() => {
                                const img = document.querySelector('img');
                                if (!img) return { width: 800, height: 600 };
                                return { width: img.naturalWidth, height: img.naturalHeight };
                            }"""
                        )

                        await img_page.set_viewport_size(dimensions)
                        image_info["data"] = await img_page.screenshot()
                        await img_page.close()

                    except Exception as e:
                        self.logger.log_message(
                            f"[ImageDownloader] ❌ Failed to process image {img_url[:100]}... with browser: {e}"
                        )
                        image_info["data"] = None

            self.status = "completed"
            return scraped_data

        except Exception as e:
            self.logger.log_message(f"[Scraper] 🚨 Playwright scrape failed: {e}")
            raise ValueError(f"Playwright error: {e}")

        finally:
            try:
                if browser and browser.is_connected():
                    await browser.close()
            except Exception:
                pass
            try:
                if headless_browser and headless_browser.is_connected():
                    await headless_browser.close()
            except Exception:
                pass
            try:
                if playwright:
                    await playwright.stop()
            except Exception:
                pass

    def _parse_content(self, html_content: str, base_url: str) -> dict:
        soup = BeautifulSoup(html_content, "html.parser")

        for script in soup(["script", "style"]):
            script.extract()

        extracted_text = soup.get_text(separator="\n", strip=True)

        extracted_links = []
        for a_tag in soup.find_all("a", href=True):
            link_text = a_tag.get_text(strip=True)
            href = a_tag["href"]
            if not href.startswith("http") and not href.startswith("//"):
                try:
                    from requests.compat import urljoin
                    href = urljoin(base_url, href)
                except Exception:
                    pass
            extracted_links.append({"text": link_text, "href": href})

        extracted_images = []
        for img_tag in soup.find_all("img", src=True):
            src = img_tag["src"]
            if not src.startswith("http") and not src.startswith("//"):
                try:
                    from requests.compat import urljoin
                    src = urljoin(base_url, src)
                except Exception:
                    pass
            extracted_images.append({"src": src, "alt": img_tag.get("alt", "")})

        return {
            "extracted_text": extracted_text,
            "extracted_links": extracted_links,
            "extracted_images": extracted_images,
        }
