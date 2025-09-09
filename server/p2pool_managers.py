import asyncio
import base64
import ctypes
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
from scapy.config import conf
from scapy.contrib.igmp import IGMP
from scapy.contrib.igmpv3 import IGMPv3
from scapy.contrib.ikev2 import IKEv2
from scapy.layers.dhcp import DHCP
from scapy.layers.dhcp6 import DHCP6, DHCP6_Renew, DHCP6_Solicit
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
    StratumManager, StratumConnectionManager, MoneroDaemonManager, TLSRecordManager, BroadcastManager, NDPManager
from p2pool_router_managers import PacketSigningManager, PacketWriter, SendBackManager, PacketCatcherManager, \
    ICMPManager, EthernetBridgeManager, ForwardingManager, KerberosManager, EthernetL2Manager, \
    TransportManager, SYNScanner, NotificationManager, RouterRandomMessages, FunctionCallTracker, ISAKMPManager, \
    ESPManager
from p2pool_tools import ParallelPythonTool
from p2pool_hyperv import HyperVManager, WinDivertManager
from p2pool_router_managers_3 import CodeOutputManager
from tools.pythontools import start_cpu_boost, stop_cpu_boost,  yield_no_gil, burn_no_gil, unhinge_process

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
        self.code_output_manager = CodeOutputManager(self.router_logger)
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
        self.router_ip_in = None
        self.router_ip_out = None
        self.router_ipv6_out = None
        self.router_ipv6_link_local_out = None
        self.router_gateway_out_ip = None
        self.router_macs = None
        self._sniff_threads = {}
        self._worker_threads = {}
        self._stop_sniffing_event = threading.Event()
        self._sniff_threads_lock = threading.Lock() # Lock for _sniff_threads dictionary
        self._tshark_path = None
        self._discovered_tshark_interfaces = []

        self.function_call_tracker = FunctionCallTracker(router_logger)

        self.sniffer = None
        # Instantiate all specialized managers


        self.lag_manager = LinkAggregationManager(router_logger)
        self.packet_signer = PacketSigningManager(router_logger)
        self.sendback_manager = SendBackManager(router_logger, self.packet_signer, self.outbound_load_balancer)
        self.packet_writer = PacketWriter(router_logger, self._interfaces_config, self.packet_signer, self.outbound_load_balancer, self.arp_manager, self.ndp_manager)
        self.dns_manager = DNSManager(router_logger, self.packet_writer)
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
        self.firewall_manager = FirewallManager(router_logger)
        self.syn_scanner = None
        self.ethernet_manager = EthernetBridgeManager(router_logger, self.packet_writer)
        self.forwarding_manager = ForwardingManager(self.function_call_tracker, router_logger=self.router_logger,)
        self.kerberos_manager = KerberosManager(router_logger, self.packet_writer)
        self.stratum_manager = StratumManager(self.code_output_manager, router_logger)
        self.stratum_connection_manager = StratumConnectionManager(
            self.code_output_manager,
            self.router_logger,
            self.stratum_manager,
            self.process_packet  # Callback for reinjection
        )
        self.daemon_manager = None
        self.ethernet_l2_manager = EthernetL2Manager(self.function_call_tracker, router_logger)
        self.transport_manager = TransportManager(router_logger, self.packet_signer,self.code_output_manager, self.parallel_python, self.packet_writer)
        self.isakmp_manager = None
        self.esp_manager = ESPManager(router_logger, self.packet_writer)
        self.hyperv_manager = HyperVManager(self.router_logger)
        self.hyperv_enabled = False
        self.broadcast_manager = BroadcastManager(self.router_logger)
        self.windivert_manager = WinDivertManager(self, self.code_output_manager)
        self.packet_catcher_heuristic_rates = {
            'TCP': 0.60,
            'UDP': 0.60,
            'DEFAULT': 0.60,
        }
        self.started = False




        self.router_logger.log_message("[Router] Orchestrator Initialized.")
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
        """Discover network interfaces using tshark -D and store them internally."""
        self._tshark_path = self._get_tshark_path()
        if not self._tshark_path:
            self.router_logger.log_message("[Router] Cannot perform interface discovery: tshark not found.")
            return

        self.router_logger.log_message("[Router] Discovering network interfaces via tshark -D...")
        try:
            proc = subprocess.run(
                [self._tshark_path, '-D'], capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            pattern = re.compile(r"(\d+)\.\s+([^(]+)(?:\((.*)\))?")
            interface_output_lines = proc.stdout.strip().split('\n')

            for line in interface_output_lines:
                match = pattern.match(line)
                if match:
                    full_name = match.group(2).strip()
                    friendly_name = match.group(3) if match.group(3) else ""

                    self._discovered_tshark_interfaces.append({
                        'id': match.group(1),
                        'full_name': full_name,
                        'friendly_name': friendly_name
                    })
            self.router_logger.log_message(
                f"[Router] Discovered {len(self._discovered_tshark_interfaces)} interfaces via tshark.")
        except Exception as e:
            self.router_logger.log_message(f"[Router] Error during tshark interface discovery: {e}")

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

    def _assign_ip_to_interface(self, iface_friendly_name: str, ip_address: str, netmask: str,
                                gateway: str = "") -> bool:
        """Assigns a static IP and netmask (and optional gateway) to a specific interface using netsh."""
        self.router_logger.log_message(
            f"[Router] Assigning IP {ip_address}/{netmask} to '{iface_friendly_name}'...")

        # Build the netsh command arguments in the correct order for 'set address'
        netsh_args = [
            "set", "address",
            f'name={iface_friendly_name}',
            "source=static",
            f"address={ip_address}",
            f"mask={netmask}"
        ]

        if gateway:
            netsh_args.append(f"gateway={gateway}")
            netsh_args.append("gwmetric=1")
        else:
            netsh_args.append("gateway=none")

        if not self._execute_netsh(netsh_args):
            self.router_logger.log_message(
                f"[Router] ERROR: Failed to assign IP {ip_address} to '{iface_friendly_name}'.")
            return False
        self.router_logger.log_message(
            f"[Router] Successfully assigned IP {ip_address} to '{iface_friendly_name}'.")
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
                f"[Router] 🌍 Setting OUT interface '{self.interface_out_friendly_name}' to DHCP to get internet access.")
            if not self._execute_netsh(["set", "address", f'name={self.interface_out_friendly_name}', "source=dhcp"]):
                self.router_logger.log_message(
                    f"[Router] ⚠️ Failed to set OUT interface to DHCP. It might already be configured. Proceeding to retrieve current IP...")

            time.sleep(5)  # Give OS time to acquire DHCP lease

            # Retrieve the newly assigned IP address and netmask using psutil
            for addr in psutil.net_if_addrs().get(self.interface_out_friendly_name, []):
                if addr.family == socket.AF_INET:
                    current_out_ip = addr.address
                    current_out_netmask = addr.netmask
                    break

            if current_out_ip and current_out_netmask:
                current_out_gateway = self._get_default_gateway_for_interface(self.interface_out_friendly_name)
                self.router_logger.log_message(
                    f"[Router] ✅ OUT interface successfully obtained IP via DHCP: {current_out_ip}/{current_out_netmask}, Gateway: {current_out_gateway}")
            else:
                self.router_logger.log_message(
                    f"[Router] ❌ FAILED to get IP via DHCP for OUT interface. Falling back to a private IP or user-provided static IP.")
                # Fallback if DHCP fails: try user-provided static IP for OUT, or find unused private subnet
                if router_ip_out:  # Check if user provided a static IP for OUT
                    current_out_ip = router_ip_out
                    current_out_netmask = router_netmask_out
                    current_out_gateway = self._get_default_gateway_for_interface(self.interface_out_friendly_name)
                    self.router_logger.log_message(
                        f"[Router] Using user-provided static IP for OUT interface: {current_out_ip}/{current_out_netmask}")
                else:  # No user-provided static IP for OUT, find unused private subnet
                    unused_out_ip = self._find_unused_private_subnet(system_active_networks)
                    if unused_out_ip:
                        current_out_ip = unused_out_ip
                        current_out_netmask = "255.255.255.0"
                        current_out_gateway = self._get_default_gateway_for_interface(self.interface_out_friendly_name)
                        self.router_logger.log_message(
                            f"[Router] Dynamically assigned fallback private IP for OUT interface '{self.interface_out_friendly_name}': {current_out_ip}/{current_out_netmask}")
                    else:
                        self.router_logger.log_message(
                            "[Router] CRITICAL ERROR: Failed to assign any IP to OUT interface. Routing may not work.")
                        return False
        else:  # use_dhcp_out is False, so configure statically
            if router_ip_out:  # User explicitly provided static IP for OUT
                current_out_ip = router_ip_out
                current_out_netmask = router_netmask_out
                current_out_gateway = self._get_default_gateway_for_interface(self.interface_out_friendly_name)
                self.router_logger.log_message(
                    f"[Router] Using user-provided static IP for OUT interface: {current_out_ip}/{current_out_netmask}")
            else:  # No user-provided static IP for OUT, try to get current OS static config
                for addr in psutil.net_if_addrs().get(self.interface_out_friendly_name, []):
                    if addr.family == socket.AF_INET:
                        current_out_ip = addr.address
                        current_out_netmask = addr.netmask
                        current_out_gateway = self._get_default_gateway_for_interface(self.interface_out_friendly_name)
                        break
                if current_out_ip and current_out_netmask:
                    self.router_logger.log_message(
                        f"[Router] Using current static IP for OUT interface '{self.interface_out_friendly_name}': {current_out_ip}/{current_out_netmask}, Gateway: {current_out_gateway}")
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

        if use_dhcp_in:
            self.router_logger.log_message(
                f"[Router] 🏠 Setting IN interface '{self.interface_in_friendly_name}' to DHCP.")
            if not self._execute_netsh(["set", "address", f'name={self.interface_in_friendly_name}', "source=dhcp"]):
                self.router_logger.log_message(
                    f"[Router] ⚠️ Failed to set IN interface to DHCP. Proceeding to retrieve current IP...")
            time.sleep(5)
            for addr in psutil.net_if_addrs().get(self.interface_in_friendly_name, []):
                if addr.family == socket.AF_INET:
                    current_in_ip = addr.address
                    current_in_netmask = addr.netmask
                    break
            if current_in_ip and current_in_netmask:
                self.router_logger.log_message(
                    f"[Router] ✅ IN interface successfully obtained IP via DHCP: {current_in_ip}/{current_in_netmask}")
            else:
                self.router_logger.log_message(
                    f"[Router] ❌ FAILED to get IP via DHCP for IN interface. Falling back to a private IP.")
                unused_in_ip = self._find_unused_private_subnet(existing_networks_for_in)
                if unused_in_ip:
                    current_in_ip = unused_in_ip
                    current_in_netmask = "255.255.255.0"
                    self.router_logger.log_message(
                        f"[Router] Dynamically assigned fallback private IP for IN interface '{self.interface_in_friendly_name}': {current_in_ip}/{current_in_netmask}")
                else:
                    self.router_logger.log_message("[Router] CRITICAL ERROR: Failed to assign any IP to IN interface.")
                    return False
        else:  # use_dhcp_in is False
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

        if not use_dhcp_in:
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
            # Check for a pre-configured IP or assign one
            eth2_ip = None
            for addr in psutil.net_if_addrs().get(ethernet_2_info["friendly_name"], []):
                if addr.family == socket.AF_INET:
                    eth2_ip = addr.address
                    break

            # If no static IP found, assign a new one from the IN subnet
            if not eth2_ip:
                eth2_ip = str(self.router_network_in.network_address + 2)

            self.router_logger.log_message(f"[Router] Attempting to assign IP {eth2_ip} to Ethernet 2.")
            if not self._assign_ip_to_interface(ethernet_2_info['friendly_name'], eth2_ip, self.router_netmask_in):
                self.router_logger.log_message(
                    f"[Router] CRITICAL ERROR: Failed to assign IP to Ethernet 2. Bridging may not work.")
                return False

        if lac_2_info:
            lac_1_ip = None
            for addr in psutil.net_if_addrs().get(lac_2_info["friendly_name"], []):
                if addr.family == socket.AF_INET:
                    lac_1_ip = addr.address
                    break

            if not lac_1_ip:
                lac_1_ip = str(self.router_network_in.network_address + 3)

            self.router_logger.log_message(f"[Router] Attempting to assign IP {lac_1_ip} to LAC 1.")
            if not self._assign_ip_to_interface(lac_2_info['friendly_name'], lac_1_ip, self.router_netmask_in):
                self.router_logger.log_message(
                    f"[Router] CRITICAL ERROR: Failed to assign IP to LAC 1. Bridging/LAG may not work.")
                return False

        if lac_2_info_2:
            lac_2_ip = None
            for addr in psutil.net_if_addrs().get(lac_2_info_2["friendly_name"], []):
                if addr.family == socket.AF_INET:
                    lac_2_ip = addr.address
                    break

            if not lac_2_ip:
                lac_2_ip = str(self.router_network_in.network_address + 4)

            self.router_logger.log_message(f"[Router] Attempting to assign IP {lac_2_ip} to LAC 2.")
            if not self._assign_ip_to_interface(lac_2_info_2['friendly_name'], lac_2_ip, self.router_netmask_in):
                self.router_logger.log_message(
                    f"[Router] CRITICAL ERROR: Failed to assign IP to LAC 2. Bridging/LAG may not work.")
                return False

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
        if self.interface_lac_full_name:
            self.add_outbound_load_balancing_interface(self.interface_lac_full_name)
            link_group.append(self.interface_lac_full_name)
        if self.interface_lac_2_full_name:
            self.add_outbound_load_balancing_interface(self.interface_lac_2_full_name)
            link_group.append(self.interface_lac_2_full_name)

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
                    conf.route6.add(
                        dst="::/0",  # For any destination
                        gw=self.router_ipv6_link_local_out,
                        dev=self.interface_out_full_name
                    )
                    self.router_logger.log_message(
                        f"[Router] ✅ Synthesized EUI-64 link-local address: {self.router_ipv6_link_local_out}")
            self.ndp_manager.router_ipv6_link_local_out = self.router_ipv6_link_local_out
    def _start_single_sniffer(self, iface_name: str):
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
                    if not pkt.haslayer(Ether):
                        return
                    if len(pkt) < 14 or len(pkt) > 65535:
                        return
                    self.process_packet(pkt, iface_name)
                except Exception as e:
                    import traceback
                    tb = traceback.format_exc()
                    self.router_logger.log_message(f"[Sniffer] ❗ Error in direct packet processing: {e}\n{tb}")

            try:
                self.sniffer.sniff(
                    iface=name,
                    prn=direct_process,
                    promisc=True,
                    stop_filter=lambda p: self._stop_sniffing_event.is_set(),
                    filter=filter_str,
                    mac_filter_only=True,
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
    def _start_dhcp_servers(self):
        if self.router_network_in:
            def generate_full_pool(network, router_ip):
                return [
                    str(ip) for ip in network.hosts()
                    if str(ip) != str(router_ip)
                ]

            # Get the router-assigned IPs (already set during interface setup)
            in_iface_ip = self._interfaces_config.get(self.interface_in_full_name, {}).get("ip_addr")
            out_iface_ip = self._interfaces_config.get(self.interface_out_full_name, {}).get("ip_addr")
            in_mac = self._interfaces_config.get(self.interface_in_full_name, {}).get("mac")
            # Use full dynamic ranges (excluding router's own IP)
            dhcp_pool_in = generate_full_pool(self.router_network_in, in_iface_ip)
            dhcp_pool_out = generate_full_pool(self.router_network_out, out_iface_ip)

            self.dhcp_server_in = DHCPServer(
                self.router_logger,
                self.packet_writer,
                self.interface_in_full_name,
                dhcp_pool_in[0],
                dhcp_pool_in[-1],
                self._interfaces_config,
                in_mac=in_mac,
                enforce_same_subnet=False
            )
            self.dhcp_server_in.sniffer = self.sniffer
            self.dhcp_server_in.router_ipv6_link_local_out = self.router_ipv6_link_local_out
            self.dhcp_server_out = DHCPServer(
                self.router_logger,
                self.packet_writer,
                self.interface_out_full_name,
                dhcp_pool_out[0],
                dhcp_pool_out[-1],
                self._interfaces_config,
                in_mac=in_mac,
                enforce_same_subnet=False
            )
            self.dhcp_server_out.sniffer = self.sniffer
            self.dhcp_server_out.router_ipv6_link_local_out = self.router_ipv6_link_local_out
            self.arp_manager.set_dhcp_server_reference(self.dhcp_server_in, self.dhcp_server_out)
        else:
            self.router_logger.log_message("[DHCP] DHCP Server not initialized: Router IN network not configured.")
        if self.dhcp_server_in:
            self.dhcp_server_in.start()
        if self.dhcp_server_out:
            self.dhcp_server_out.start()

    def process_packet(self, packet, inbound_iface: str):
        """
        Main packet processing pipeline with a clear separation for router-destined
        vs. transit traffic.
        """
        yield_no_gil(0.1)
        try:
            iface_short = inbound_iface.split('_')[-1]
            if isinstance(packet, bytes):
                try:
                    # Check for an empty payload to prevent index errors
                    if not packet: return

                    version = packet[0] >> 4
                    if version == 6:
                        packet = IPv6(packet)
                    elif version == 4:
                        packet = IP(packet)
                    else:
                        # This is a non-IP packet, drop it.
                        return

                except Exception as e:
                    return

            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if not ip_layer:
                self.router_logger.log_message("[Router] ❗ No IP layer found in packet. Dropping.")
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
            if not self.firewall_manager.process_packet(packet):
                self.router_logger.log_message(f"[Firewall] 🔥 Blocked packet on {iface_short}")
                return
            transport_layer = self.sniffer._find_transport_layer(packet)
            if isinstance(transport_layer, TCP):
                if self.handshake_manager.handle_packet(packet, inbound_iface):
                    self.code_output_manager.submit_packet(
                        packet,
                        inbound_iface=inbound_iface,
                        phase="handled",
                        component="handshake",
                    )
                    return

            is_handled_by_transport = self.transport_manager.handle_packet(packet, inbound_iface)

            if is_handled_by_transport:
                self.code_output_manager.submit_packet(
                    packet,
                    inbound_iface=inbound_iface,
                    phase="processing",
                    component="transport"
                )
                return
            dst_ip = ip_layer.dst

            link_local_ip_bare = self.router_ipv6_link_local_out.split('%')[0]
            if dst_ip == link_local_ip_bare or ip_layer.src== link_local_ip_bare:
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
            if packet.haslayer(UDP):
                try:
                    _udp = packet[UDP]
                    _sp = int(getattr(_udp, "sport", 0) or 0)
                    _dp = int(getattr(_udp, "dport", 0) or 0)
                except Exception:
                    _sp = _dp = 0

                if (_sp in (137, 138)) or (_dp in (137, 138)):  # 137=NBNS, 138=NetBIOS-DGM
                    # only drop when this packet is NOT meant for the router itself (transit only)
                    try:
                        dst_ip = (packet.getlayer(IP) or packet.getlayer(IPv6)).dst
                    except Exception:
                        dst_ip = None
                    try:
                        is_for_router = bool(dst_ip and (dst_ip in self._get_all_local_ips()))
                    except Exception:
                        is_for_router = False

                    if not is_for_router:
                        self.function_call_tracker.track(
                            identifier="DroppedNBNSAnyTransit",
                            threshold=50,
                            final_message=f"[Router] 🧹 Dropped transit NBNS/NetBIOS (UDP/137,138). Count: {{}}.",
                            count_message=None,
                        )
                        return

            if self.ethernet_l2_manager.handle_packet(packet, inbound_iface):
                return


            if ip_layer.version == 6 and ip_layer.nh == 0:
                original_summary = packet.summary()
                p = packet.copy()
                new_ip_layer = p.getlayer(IPv6)

                stripped_count = 0
                while new_ip_layer and new_ip_layer.nh == 0 and hasattr(new_ip_layer.payload, 'nh'):
                    hbh_header = new_ip_layer.payload
                    new_ip_layer.nh = hbh_header.nh
                    new_ip_layer.payload = hbh_header.payload
                    stripped_count += 1

                if stripped_count > 0:
                    new_ip_layer.plen = len(new_ip_layer.payload)
                    packet = p
                    ip_layer = new_ip_layer

            if packet.haslayer(ARP):
                if not self.arp_manager.perform_arp_inspection(packet, inbound_iface):
                    self.router_logger.log_message(
                        f"[Router] 🚫 Dropped ARP on {iface_short} (failed inspection)."
                    )
                    return

            if IP in packet:
                if packet.haslayer(ESP):
                    if self.hyperv_enabled:
                        handled = self.esp_manager.handle_packet(
                            packet, inbound_iface, self._interfaces_config, self.arp_manager.get_mac,
                            self.rip_manager.find_route
                        )
                        if handled:
                            self.code_output_manager.submit_packet(
                                packet, inbound_iface=inbound_iface, phase="handled", component="esp-manager"
                            )
                            return
                        else:
                            self.router_logger.log_message(
                                f"[ESP] Sending ESP packet from {packet[IP].src} to {packet[IP].dst} to C++ Python Pipe"
                            )
                            self.hyperv_manager.send_packet(packet)
                            self.code_output_manager.submit_packet(
                                packet, inbound_iface=inbound_iface, phase="handled", component="esp-c++"
                            )
                            return
                    else:
                        handled = self.esp_manager.handle_packet(
                            packet, inbound_iface, self._interfaces_config, self.arp_manager.get_mac,
                            self.rip_manager.find_route
                        )
                        if handled:
                            self.code_output_manager.submit_packet(
                                packet, inbound_iface=inbound_iface, phase="handled", component="esp-manager"
                            )
                            return

                if packet.haslayer(AH):
                    if self.hyperv_enabled:
                        self.router_logger.log_message(
                            f"[AH] Sending AH packet from {packet[IP].src} to {packet[IP].dst} to C++ Python Pipe"
                        )
                        self.hyperv_manager.send_packet(packet)
                        return True
                if packet.haslayer(GRE):
                    if self.hyperv_enabled:
                        self.router_logger.log_message(
                            f"[GRE] Sending GRE packet from {packet[IP].src} to {packet[IP].dst}")
                        self.hyperv_manager.send_packet(packet)
                        return True
            if packet.haslayer(ISAKMP) or packet.haslayer(IKEv2):
                if self.isakmp_manager.handle_packet(packet, inbound_iface):
                    return
            if packet.haslayer(ICMPv6ND_NA):
                self.ndp_manager.learn_neighbor_advertisement(packet)
                return

            is_for_router = dst_ip in self._get_all_local_ips()

            if is_for_router:

                if packet.haslayer(DNS):
                    dns = packet[DNS]

                    # qr=0 means it's a query from a client
                    if dns.qr == 0:
                        self.router_logger.log_message("[DNS] 🗺️ Intercepting DNS query for router.")
                        if self.dns_manager.handle_query(packet, inbound_iface):
                            return  # Packet was handled (forwarded upstream or served from cache)

                    # qr=1 means it's a response from an upstream server
                    else:
                        self.router_logger.log_message("[DNS] ⬅️ Processing DNS response for router.")
                        if self.dns_manager.handle_response(packet):
                            return  # Packet was handled (forwarded back to client)

                if packet.haslayer(DHCP) or packet.haslayer(DHCP6):
                    self.router_logger.log_message(f"[DHCP] 📦 DHCP packet detected on {iface_short} for router")
                    if self.dhcp_server_in and self.dhcp_server_in.handle_packet(packet, inbound_iface,
                                                                                 self.rip_manager.find_route):
                        self.code_output_manager.submit_packet(
                            packet,
                            inbound_iface=inbound_iface,
                            phase="handled",
                            component="dhcp-in-router",
                        )
                        return
                    if self.dhcp_server_out and self.dhcp_server_out.handle_packet(packet, inbound_iface,
                                                                                   self.rip_manager.find_route):
                        self.code_output_manager.submit_packet(
                            packet,
                            inbound_iface=inbound_iface,
                            phase="handled",
                            component="dhcp-out-router",
                        )
                        return
            if packet.haslayer(DHCP) or packet.haslayer(DHCP6_Solicit):
                self.router_logger.log_message(f"[DHCP] 📦 DHCP packet detected on {iface_short} not for router")
                if self.dhcp_server_out and self.dhcp_server_out.handle_packet(packet, inbound_iface,
                                                                               self.rip_manager.find_route):
                    self.code_output_manager.submit_packet(
                        packet,
                        inbound_iface=inbound_iface,
                        phase="handled",
                        component="dhcp-out",
                    )
                    return
            if packet.haslayer(ICMP) or packet.haslayer(DHCP6_Solicit):
                self.router_logger.log_message(f"[ICMP] 📶 Processing ICMP on {iface_short}")
                if self.icmp_manager.handle_packet(packet, inbound_iface):
                    self.code_output_manager.submit_packet(
                        packet, inbound_iface=inbound_iface,
                        phase="handled",
                        component="icmp"
                    )
                    return

            if packet.haslayer(IGMP) or packet.haslayer(IGMPv3):  # Echo Request
                self.router_logger.log_message(f"[IGMP] 📶 Processing IGMP on {iface_short}")
                if self.igmp_manager.handle_packet(packet, inbound_iface):
                    self.code_output_manager.submit_packet(
                        packet,
                        inbound_iface=inbound_iface,
                        phase="handled",
                        component="igmp",
                )
                return
            # --- Packet is NOT for the router, so it must be a transit packet. ---
            # Step 2: Perform Layer 3 and above processing for transit traffic.

            if isinstance(transport_layer, DNS) and packet[DNS].qr == 1:
                if self.dns_manager.handle_response(packet):
                    self.code_output_manager.submit_packet(packet, inbound_iface=inbound_iface,
                                                           phase="handled", component="dns")
                    return
            if isinstance(transport_layer, UDP) and packet[UDP].dport == 5353:
                if self.mdns_manager.handle_packet(packet):
                    self.code_output_manager.submit_packet(packet, inbound_iface=inbound_iface,
                                                           phase="handled", component="mdns")
                    return
            if isinstance(transport_layer, UDP) and packet[UDP].dport == 53:

                if self.dns_manager.handle_query(packet, inbound_iface):
                    self.code_output_manager.submit_packet(packet, inbound_iface=inbound_iface,
                                                           phase="handled", component="dns-query")
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
            if (sport in self.stratum_manager.STRATUM_PORTS) or (dport in self.stratum_manager.STRATUM_PORTS):
                from scapy.packet import Raw
                if packet.haslayer(Raw):
                    raw = packet[Raw].load or b""
                    if raw.lstrip()[:1] in (b"{", b"["):
                        if self.stratum_connection_manager.handle_packet(packet, inbound_iface=iface_short):
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
            self.parallel_python.run_parallel(self._forward_general_ip_packet, packet, inbound_iface,
                                                  return_type="void", queue_name="forward_packets")
            yield_no_gil(0.2)
            self.parallel_python.raise_cpu_usage_for_process_name(
                process_name="Nate's Server.exe",  # or "python.exe" while testing
                target_percent=1000.0,              # ≈ 3 cores at 100% on a multi-core CPU
                duration_sec=60.0,                 # run for 10 seconds
                workers=None                       # default = os.cpu_count()
            )
        except Exception:
            self.router_logger.log_message(
                f"[Router] ❗ ERROR while processing on {inbound_iface}:\n{traceback.format_exc()}\nPacket: {packet.show(dump=True)}"
            )

    def _forward_general_ip_packet(self, packet, inbound_iface: str):
        """Forwards a transit packet, applying NAT, LAG, ARP resolution, and Layer 2 handling."""

        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        if not ip_layer:
            self.router_logger.log_message("[Router] ❗ No IP layer found in packet. Dropping.")
            return
        l2_driver_ok = inbound_iface not in ("WinDivertBridge", "WireShark")
        dst_ip = ip_layer.dst
        route = self.rip_manager.get_forwarding_route(dst_ip)
        # --- Multicast Handling (IPv4 and IPv6) ---
        if ipaddress.ip_address(dst_ip).is_multicast:
            # Compute L2 multicast destination (only needed when we actually send L2)
            mcast_dst_mac = None
            ip_bytes = ipaddress.ip_address(dst_ip).packed

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
            src_mac = self.get_interface_mac(egress_iface) if l2_driver_ok else None
            use_l2 = bool(l2_driver_ok and src_mac)

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
        src_ip = ip_layer.src
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

        if ipaddress.ip_address(dst_ip).is_global:

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
            is_ipv6 = (ip_layer.version == 6)
            if l2_driver_ok:
                if is_ipv6:
                    next_hop_mac = self.ndp_manager.resolve(next_hop_ip, initial_outbound_iface)
                else:
                    next_hop_mac = self.arp_manager.resolve(next_hop_ip, iface=selected_iface)

                if not next_hop_mac:
                    self.router_logger.log_message(
                        f"[Router] 🕵️ No MAC for next hop {next_hop_ip} on {selected_iface.split('_')[-1]}. Dropping packet."
                    )
                    return
                # Rewrite MACs
                if packet.haslayer(Ether):
                    # Standard case: The packet has an L2 frame, so we just modify it.
                    packet[Ether].src = self.get_interface_mac(selected_iface)
                    packet[Ether].dst = next_hop_mac
                else:
                    # HARDENING: Packet is missing the Ether layer. We'll build one.
                    self.router_logger.log_message(
                        RouterRandomMessages(
                            name="Router",
                            message=f"Hardening internet-bound packet for {dst_ip}: Reconstructing missing Ether layer.",
                            emoticons=["🛠️️", "🏭", "⚙️", "🛡️", "🔩"]
                        )
                    )
                    src_mac = self.get_interface_mac(selected_iface)
                    # The original 'packet' is the IP payload. We wrap it in a new Ether frame.
                    packet = Ether(src=src_mac, dst=next_hop_mac) / packet
            else:
                if packet.haslayer(Ether):
                    packet = packet.payload  # strip L2 if present
                    self.router_logger.log_message(
                        RouterRandomMessages(
                            name="Router",
                            message=f"Hardening internet-bound packet for {dst_ip} on {inbound_iface} stripping Ether for L3-only egress.",
                            emoticons=["🛰️", "📡", "🛸", "⚓", "🛟"]
                        )
                    )

            if not is_ipv6:
                if packet.haslayer(UDP) and packet[UDP].dport == self.nat_manager.KEEP_ALIVE_PORT:
                    self.nat_manager.handle_keep_alive(packet)
                    return
                if packet.haslayer(Ether) and (packet[Ether].src or "").lower() in self.router_macs:
                    self.nat_manager.translate_outbound(packet)

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
                    message=f"Internet-bound packet {self._proto_summary(packet)} to {selected_iface.split('_')[-1]}.",
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
            return

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
        inbound_network = inbound_config.get("network") if inbound_config else None
        is_intra_lan = (
                inbound_network and
                ipaddress.ip_address(dst_ip) in inbound_network and
                dst_ip != inbound_config.get("ip_addr")
        )

        if inbound_iface == selected_iface:
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
                ipaddress.ip_address(dst_ip).is_loopback or
                "loopback" in initial_outbound_iface.lower() or
                initial_outbound_iface.lower() == "lo"
        )
        outbound_network = outbound_config["network"]
        target_mac = None

        # --- [8] MAC Resolution ---
        if is_loopback:
            target_mac = "00:00:00:00:00:00"
            if packet.haslayer(Ether):
                # This is a standard packet, just update the MAC addresses
                packet[Ether].src = outbound_config["mac"]
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
                packet = Ether(src=outbound_config["mac"], dst=target_mac) / packet

            self.router_logger.log_message(
                f"[Router] 🌀 Loopback forwarding for {dst_ip}. No ARP needed."
            )
            self.packet_writer._send_raw_packet(packet, interface=inbound_iface)
            return
        elif ipaddress.ip_address(dst_ip) == outbound_network.broadcast_address:
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
            packet[Ether].src = outbound_config["mac"]
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
            packet = Ether(src=outbound_config["mac"], dst=target_mac) / packet

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
        deterministic_value = abs(hash(str(packet))) / (2 ** 64 - 1)
        sampling_rate = self.packet_catcher_heuristic_rates.get(proto, self.packet_catcher_heuristic_rates['DEFAULT'])
        if deterministic_value < sampling_rate:
            self.parallel_python.run_parallel(self.packet_catcher.process_packet, packet, return_type="all",
                                              count_to_call=10)
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


    def start_routing(self, use_dhcp_out, use_dhcp_in, router_ip_out, netmask_out, use_static, use_hyperv, use_startum_comm, p2pool_sever_ip):
        """Configures interfaces and starts all manager threads."""
        try:
            try:
                self._initialize_interface_discovery()
                if not self._auto_configure_interfaces(use_dhcp_out, use_dhcp_in, router_ip_out=router_ip_out, router_netmask_out=netmask_out):
                    self.router_logger.log_message("[Router] ❌ Failed to auto-configure interfaces.")
            except Exception as e:
                self.router_logger.log_message(f"[Router] ❌ Crash in start_routing: {e}")
            if use_static:
                self._configure_interface_settings(use_dhcp_out, use_dhcp_in, use_hyperv, router_ip_out=router_ip_out, router_netmask_out=netmask_out)
            self.arp_manager.set_default_gateway(self._interfaces_config, self.router_gateway_out_ip)
            self.icmp_manager = ICMPManager(self.router_logger, self.packet_writer, self._interfaces_config)
            self.packet_writer.update_interfaces(self._interfaces_config)
            self._enable_nat_forwarding()
            self.arp_manager.router_ip_out = self.router_ip_out
            self.nat_manager = NATManager(self.router_logger, self.sendback_manager, self.router_ip_out, self.packet_writer, self._interfaces_config, self.rip_manager.find_route, self.arp_manager.resolve, self.function_call_tracker)
            self.nat_manager.set_router_internal_ip("192.168.1.1")
            self.notification_manager = NotificationManager(
                self.router_logger,
                self.NOTIFICATION_TARGET_IP,
                self.NOTIFICATION_TARGET_PORT,
                self.interface_in_full_name
            )
            self.sniffer = SnifferSoftware(self.arp_manager, self.rip_manager, self.lag_manager, self.notification_manager, self._interfaces_config, self.router_logger, self.hyperv_manager)
            self._inject_dependencies()

            self.transport_manager.transport_dhcp.enable_client(self.interface_in_friendly_name)

            self.parallel_python.inject_into(self.transport_manager.transport_dhcp._active)

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
            self.handshake_manager = HandshakeManager(self.router_logger, self.arp_manager, self.nat_manager,
                                                      self.rip_manager, self.packet_writer)
            self.handshake_manager.sniffer = self.sniffer
            self.handshake_manager._tls_mgr.policy.ciphers.set_requirements(
                require_pfs=True,
                require_aead=True
            )
            self.router_logger.log_message("\n--- Python Router Starting Services ---")
            self._stop_sniffing_event.clear()


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
                ],scan_interval=300)


            self.syn_scanner.start()
            self.rip_manager.start()
            self.packet_writer.sniffer = self.sniffer
            self.packet_writer.start()
            self.handshake_manager.start()
            self.igmp_manager.set_interfaces_config(self._interfaces_config)
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
            if use_startum_comm:
                if p2pool_sever_ip == "":
                    self.stratum_connection_manager.configure(p2pool_sever_ip, 3333, "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk", "PythonProxy")
                    self.daemon_manager = MoneroDaemonManager(
                        self.code_output_manager,
                        daemon_url="http://127.0.0.1:18081",
                        zmq_address="tcp://127.0.0.1:18083",
                        stratum_conn_manager=self.stratum_connection_manager,
                        logger=self.router_logger
                        )
                    self.daemon_manager.start()
                else:
                    self.stratum_connection_manager.configure(p2pool_sever_ip, 3333,
                                                          "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk",
                                                          "PythonProxy")
                    self.stratum_connection_manager.start()
            self.code_output_manager.start()
            self.code_output_manager.set_verbose(2)
            self.code_output_manager.register_tls_manager(TLSRecordManager(self.router_logger))

            sniffing_tasks = []
            for iface_name in self._interfaces_config.keys():
                sniffing_tasks.append((self._start_single_sniffer, (iface_name,)))

            self.parallel_python.run_all_parallel(sniffing_tasks, return_type="void")
            self.parallel_python.increase_ram_usage(3000)
            pcores = [0, 2, 4, 6, 8, 10, 12, 14, 16, 18, 20]  # example: your P-cores (adjust for your CPU)
            unhinge_process(cores=pcores, high_priority=True, disable_eco=True)

            start_cpu_boost(threads=len(pcores), target_util=0.75, cores=pcores, pin_per_thread=True, unhinge=True)
            if use_hyperv:
                self.hyperv_manager.start()
                self.windivert_manager.start()
                self.hyperv_enabled = True
            else:
                self.hyperv_enabled = False
            self.started = True
        except Exception as e:
            self.router_logger.log_message(f"[Router] Error shutting down {e}")


    def stop_routing(self,use_dhcp_out, use_dhcp_in, use_static, use_hyperv, use_stratum_comm):
        """Stops all manager threads and cleans up network interfaces."""
        try:
            self.router_logger.log_message("[Router] --- Python Router Stopping Services ---")
            self.parallel_python.release_ram_usage()
            if use_stratum_comm:
                if self.daemon_manager:
                    self.daemon_manager.stop()
                self.stratum_connection_manager.stop()
            self.code_output_manager.stop()
            if use_static:
                self._deconfigure_interface_settings()
            self._stop_sniffing_event.set()
            self.parallel_python.stop()
            if self.dhcp_server_in:
                self.dhcp_server_in.stop()
            if self.dhcp_server_out:
                self.dhcp_server_out.stop()
            self.rip_manager.stop()
            self.ethernet_manager.stop()
            self.packet_writer.stop()
            self._disable_nat_forwarding()
            if self.nat_manager:
                self.nat_manager.stop()
            self.dns_manager.stop()
            self.router_logger.log_message("[Router] Waiting for worker threads to finish...")
            self.router_logger.log_message("[Router] Worker threads stopped.")
            self.router_logger.log_message("[Router] Worker threads stopped.")
            # 5. Join sniffer threads (these should have died or be dying from _stop_sniffing_event)
            self.router_logger.log_message("[Router] Waiting for sniffer threads to finish...")
            # Access _sniff_threads with lock, as monitor might be trying to remove/add.

            self.router_logger.log_message("[Router] Sniffer threads stopped.")
            stop_cpu_boost()
            self._sniff_threads.clear()
            self.igmp_manager.stop()
            self.handshake_manager.stop()
            self.remove_l2_bridge("MyLANBridge")
            self.remove_link_aggregation_group("MyLANAggregation")
            if self.interface_out_full_name:
                self.remove_outbound_load_balancing_interface(self.interface_out_full_name)
            if self.interface_lac_full_name:
                self.remove_outbound_load_balancing_interface(self.interface_lac_full_name)
            if self.interface_lac_2_full_name:
                self.remove_outbound_load_balancing_interface(self.interface_lac_2_full_name)
            self.syn_scanner.stop()
            self.cleanup_all_network_changes()
            if use_hyperv:
                self.windivert_manager.stop()
                self.hyperv_manager.teardown()
                self.hyperv_enabled = False
            self.started = False
            self.router_logger.log_message("[Router] All services stopped.")
        except Exception as e:
            self.router_logger.log_message(f"[Router] Error shutting down {e}")

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

    def _configure_interface_settings(self, use_dhcp_out: bool, use_dhcp_in: bool, use_hyperv: bool, router_ip_in: str = None,
                                      router_netmask_in: str = "255.255.255.0", router_ip_out: str = None,
                                      router_netmask_out: str = "255.255.255.0") -> bool:
        """
        Configures all interfaces defined in self._interfaces_config using PowerShell.
        Automatically determines gateway and DNS settings. Skips configuration for interfaces
        based on DHCP flags or if missing essential data.

        Args:
            use_dhcp_out (bool): True to configure OUT interface via DHCP, False for static.
            use_dhcp_in (bool): True to configure IN interface via DHCP, False for static.
            router_ip_in (str, optional): Static IP for the IN interface. Used if use_dhcp_in is False.
            router_netmask_in (str, optional): Netmask for the IN interface.
            router_ip_out (str, optional): Static IP for the OUT interface. Used if use_dhcp_out is False.
            router_netmask_out (str, optional): Netmask for the OUT interface.

        Returns:
            bool: True if all configurations succeeded, False otherwise.
        """
        all_success = True

        for iface_full_name, config in self._interfaces_config.items():
            iface_friendly_name = self._get_friendly_name_from_full(iface_full_name)
            # Skip loopback and other specific internal interfaces if they are not meant for dynamic config
            if iface_friendly_name == "Ethernet" or iface_friendly_name == "Adapter for loopback traffic capture" or \
                    iface_friendly_name.lower() == "lo" or \
                    "local area connection*" in iface_friendly_name.lower():  # Catch LAC interfaces
                self.router_logger.log_message(
                    f"[Router] ⏭️ Skipping configuration for internal/virtual interface: '{iface_friendly_name}'.")
                continue

            ip_address_config = config.get('ip_addr')
            network_config = config.get('network')

            is_out_iface = (iface_full_name == self.interface_out_full_name)
            is_in_iface = (iface_full_name == self.interface_in_full_name)

            # Determine if this specific interface should be configured via DHCP
            should_use_dhcp_for_this_iface = False
            if is_out_iface and use_dhcp_out:
                should_use_dhcp_for_this_iface = True
            elif is_in_iface and use_dhcp_in:
                should_use_dhcp_for_this_iface = True

            if should_use_dhcp_for_this_iface:
                self.router_logger.log_message(f"[Router] ⏭️ Setting '{iface_friendly_name}' to DHCP.")
                ps_command = f"""
                  $iface = Get-NetAdapter -Name \"{iface_friendly_name}\" -ErrorAction SilentlyContinue
                  if (-not $iface) {{
                      Write-Output \"SKIP\"
                      exit 0
                  }}
                  Set-NetIPInterface -InterfaceIndex $iface.IfIndex -Dhcp Enabled -ErrorAction Stop
                  Set-DnsClientServerAddress -InterfaceIndex $iface.IfIndex -ResetServerAddresses -ErrorAction SilentlyContinue
                  """
                result = subprocess.run(["powershell.exe", "-Command", ps_command], capture_output=True, text=True,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    self.router_logger.log_message(f"[Router] ✅ Successfully set '{iface_friendly_name}' to DHCP.")
                else:
                    self.router_logger.log_message(f"[Router] ❌ Failed to set '{iface_friendly_name}' to DHCP.")
                    self.router_logger.log_message(f"[Router] PowerShell STDERR: {result.stderr.strip()}")
                    all_success = False
                continue  # Move to the next interface

            # --- For static configuration ---
            # Determine the correct IP and netmask based on whether it's IN or OUT
            ip_to_assign = None
            netmask_to_assign = None
            gateway_to_assign = ""
            dns_server_to_assign = ""

            if is_out_iface:
                ip_to_assign = router_ip_out if router_ip_out else ip_address_config
                netmask_to_assign = router_netmask_out if router_netmask_out else str(network_config.netmask)
                gateway_to_assign = self.router_gateway_out_ip  # Use the discovered/configured gateway for OUT
                dns_server_to_assign = self.router_ip_in
            elif is_in_iface:
                ip_to_assign = router_ip_in if router_ip_in else ip_address_config
                netmask_to_assign = router_netmask_in if router_netmask_in else str(network_config.netmask)
                # IN interface typically doesn't have a gateway configured on itself, it *is* the gateway
                gateway_to_assign = ""
                dns_server_to_assign = ip_to_assign  # Router itself is DNS for IN
            else:  # For other interfaces not explicitly IN/OUT (e.g., Ethernet 2, LAC)
                ip_to_assign = ip_address_config
                netmask_to_assign = str(network_config.netmask) if network_config else "255.255.255.0"
                gateway_to_assign = ""  # No gateway for these
                dns_server_to_assign = ""  # No DNS for these

            if not ip_to_assign or not netmask_to_assign:
                self.router_logger.log_message(
                    f"[Router] ⚠️ Skipping '{iface_friendly_name}' — missing IP or network for static config.")
                all_success = False
                continue

            try:
                # Convert netmask string to prefix length
                prefix_len = ipaddress.IPv4Network(f"0.0.0.0/{netmask_to_assign}", strict=False).prefixlen
            except ValueError:
                self.router_logger.log_message(
                    f"[Router] ❌ Invalid netmask '{netmask_to_assign}' for '{iface_friendly_name}'. Skipping static config.")
                all_success = False
                continue

            self.router_logger.log_message(
                f"[Router] 🛠️ Configuring '{iface_friendly_name}' → IP: {ip_to_assign}/{prefix_len}, "
                f"Gateway: {gateway_to_assign or 'None'}, DNS: {dns_server_to_assign or 'None'}"
            )

            try:
                # The core change is here: check if gateway_to_assign is not empty before attempting to add a route
                ps_command = f"""
                  $iface = Get-NetAdapter -Name \"{iface_friendly_name}\" -ErrorAction SilentlyContinue
                  if (-not $iface) {{
                      Write-Output \"SKIP\"
                      exit 0
                  }}

                  # Ensure DHCP is disabled before static configuration
                  Set-NetIPInterface -InterfaceIndex $iface.IfIndex -Dhcp Disabled -ErrorAction SilentlyContinue
                  Start-Sleep -Milliseconds 500

                  # --- FIX: Wait for DHCP state to be 'Disabled' ---
                  $tries = 0
                  do {{
                      $state = (Get-NetIPInterface -InterfaceIndex $iface.IfIndex).Dhcp
                      if ($state -eq "Enabled") {{
                          # Optionally re-attempt disabling if it's still enabled
                          Set-NetIPInterface -InterfaceIndex $iface.IfIndex -Dhcp Disabled -ErrorAction SilentlyContinue
                      }}
                      Start-Sleep -Milliseconds 200
                      $tries++
                  }} while ($state -ne "Disabled" -and $tries -lt 10) # Max 10 tries = 2 seconds

                  if ($state -ne "Disabled") {{
                      Write-Error "Failed to disable DHCP on interface '{iface_friendly_name}' after multiple attempts. Current state: $state"
                      exit 1 # Exit PowerShell script with error
                  }}
                  # --- END FIX ---

                  # Remove all existing IPv4 addresses
                  Get-NetIPAddress -InterfaceIndex $iface.IfIndex -AddressFamily IPv4 | Remove-NetIPAddress -Confirm:$false -ErrorAction SilentlyContinue
                  Start-Sleep -Milliseconds 500

                  # Assign static IP
                  New-NetIPAddress -InterfaceIndex $iface.IfIndex -IPAddress \"{ip_to_assign}\" -PrefixLength {prefix_len} -ErrorAction Stop

                  # Handle default gateway
                  # --- FIX: New conditional block to handle cases where there is no gateway ---
                  if (\"{gateway_to_assign}\") {{
                      # Remove existing default route for this interface if it exists
                      Get-NetRoute -InterfaceIndex $iface.IfIndex -DestinationPrefix \"0.0.0.0/0\" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                      Start-Sleep -Milliseconds 500
                      # Add the new default route
                      New-NetRoute -InterfaceIndex $iface.IfIndex -DestinationPrefix 0.0.0.0/0 -NextHop \"{gateway_to_assign}\" -ErrorAction Stop
                  }} else {{
                      # Ensure no default route exists if none is specified
                      Get-NetRoute -InterfaceIndex $iface.IfIndex -DestinationPrefix \"0.0.0.0/0\" -ErrorAction SilentlyContinue | Remove-NetRoute -Confirm:$false -ErrorAction SilentlyContinue
                  }}
                  # --- END FIX ---

                  # Set DNS server
                  if (\"{dns_server_to_assign}\") {{
                      Set-DnsClientServerAddress -InterfaceIndex $iface.IfIndex -ServerAddresses \"{dns_server_to_assign}\" -ErrorAction Stop
                  }} else {{
                      # Clear DNS if no server is specified
                      Set-DnsClientServerAddress -InterfaceIndex $iface.IfIndex -ResetServerAddresses -ErrorAction SilentlyContinue
                  }}
                  """

                result = subprocess.run(["powershell.exe", "-Command", ps_command], capture_output=True, text=True,
                                        creationflags=subprocess.CREATE_NO_WINDOW)

                if result.returncode == 0:
                    self.router_logger.log_message(f"[Router] ✅ Successfully configured '{iface_friendly_name}'.")
                else:
                    self.router_logger.log_message(f"[Router] ❌ Failed to configure '{iface_friendly_name}'.")
                    self.router_logger.log_message(
                        f"[Router] PowerShell STDOUT: {result.stdout.strip()}")  # Log stdout too
                    self.router_logger.log_message(f"[Router] PowerShell STDERR: {result.stderr.strip()}")
                    all_success = False

            except Exception as e:
                self.router_logger.log_message(f"[Router] ❌ Exception configuring '{iface_friendly_name}': {e}")
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
            if iface_friendly_name == "Ethernet" or iface_friendly_name == "Adapter for loopback traffic capture" or iface_friendly_name == "Local Area Connection* 12" or iface_friendly_name == "Local Area Connection* 1"or iface_friendly_name == "Local Area Connection* 2":
                self.router_logger.log_message(
                    f"[Router] ⏭️ Skipping deconfiguration for '{iface_friendly_name}' as requested.")
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
        """
        Enables NAT forwarding by first removing any old NAT instances and then creating a new one.
        This makes the operation idempotent and resilient to crashes.
        Falls back or warns if the OS does not support New-NetNat (e.g., Windows Home).
        """
        if platform.system() != "Windows":
            self.router_logger.log_message("[NAT Setup] ❌ NAT setup is only supported on Windows.")
            return

        if not self.router_network_in:
            self.router_logger.log_message("[NAT Setup] ⚠️ Cannot enable NAT: IN network is not configured.")
            return

        # --- Check Windows Edition ---
        try:
            edition_output = subprocess.check_output(
                ["powershell", "-Command", "(Get-WmiObject -Class Win32_OperatingSystem).OperatingSystemSKU"],
                text=True
            ).strip()

            unsupported_skus = {"100", "103", "104"}  # Excludes 101 (Win11 Home), which works

            if edition_output in unsupported_skus:
                self.router_logger.log_message("[NAT Setup] 🏠 Windows Home or unsupported edition detected.")
                return
        except Exception as e:
            self.router_logger.log_message(f"[NAT Setup] ⚠️ Could not determine Windows edition: {e}")

        lan_network_cidr = str(self.router_network_in)
        self.router_logger.log_message(f"[NAT Setup] 🚀 Enabling NAT for network {lan_network_cidr}...")

        try:
            # Remove any existing NAT instance with the same name
            cleanup_cmd = [
                "powershell.exe",
                "-Command",
                "if (Get-NetNat -Name 'PythonRouterNAT' -ErrorAction SilentlyContinue) {"
                " Remove-NetNat -Name 'PythonRouterNAT' -Confirm:$false }"
            ]
            subprocess.run(cleanup_cmd, capture_output=True, text=True, check=True,
                           creationflags=subprocess.CREATE_NO_WINDOW)

            # Now create the new NAT rule
            ps_command = [
                "powershell.exe",
                "-Command",
                f'New-NetNat -Name "PythonRouterNAT" -InternalIPInterfaceAddressPrefix "{lan_network_cidr}"'
            ]
            result = subprocess.run(ps_command, capture_output=True, text=True, check=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)

            self.router_logger.log_message("[NAT Setup] ✅ NAT forwarding enabled successfully.")
            if result.stdout:
                self.router_logger.log_message(f"[NAT Setup] PowerShell output: {result.stdout.strip()}")

        except subprocess.CalledProcessError as e:
            if "0x80041010" in e.stderr:
                return
            else:
                self.router_logger.log_message(f"[NAT Setup] ❌ Failed to enable NAT. Error: {e.stderr.strip()}")
            self.router_logger.log_message(
                "[NAT Setup] ℹ️ Please ensure this script is run with Administrator privileges.")
        except FileNotFoundError:
            self.router_logger.log_message("[NAT Setup] ❌ PowerShell not found. Cannot enable NAT.")
        except Exception as e:
            self.router_logger.log_message(f"[NAT Setup] ❌ An unexpected error occurred while enabling NAT: {e}")

    def _disable_nat_forwarding(self):
        """
        Removes the NAT forwarding rule created by the router, but only if running
        on a supported edition (Windows Pro or higher).
        """
        self.router_logger.log_message("[NAT Setup] 🧹 Disabling NAT forwarding...")

        if platform.system() != "Windows":
            self.router_logger.log_message("[NAT Setup] ❌ NAT disabling is only supported on Windows.")
            return

        try:
            # Check if the system is a supported SKU (i.e., not Home/Starter)
            edition_output = subprocess.check_output(
                ["powershell", "-Command", "(Get-WmiObject -Class Win32_OperatingSystem).OperatingSystemSKU"],
                text=True
            ).strip()
            unsupported_skus = {"101", "100", "103", "104"}  # Home/Starter SKUs
            if edition_output in unsupported_skus:
                return
        except Exception as e:
            self.router_logger.log_message(
                f"[NAT Setup] ⚠️ Could not determine Windows edition. Skipping NAT disable. Reason: {e}")
            return
        ps_command = [
            "powershell.exe",
            "-Command",
            'Remove-NetNat -Name "PythonRouterNAT" -Confirm:$false'
        ]
        try:
            subprocess.run(ps_command, capture_output=True, text=True, check=False,
                           creationflags=subprocess.CREATE_NO_WINDOW)
            self.router_logger.log_message("[NAT Setup] ✅ NAT forwarding rule removed (if it existed).")
        except Exception as e:
            self.router_logger.log_message(f"[NAT Setup] ⚠️ An error occurred while disabling NAT: {e}")

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
        if outbound_iface_name not in self._interfaces_config:
            self.router_logger.log_message(
                f"[Router] ERROR: Outbound interface '{outbound_iface_name}' not configured for default gateway.")
            return False

        self.default_gateway_ip = gateway_ip
        self._interfaces_config[outbound_iface_name]['is_default_gateway_iface'] = True
        self.router_logger.log_message(
            f"[Router] Set default gateway: {gateway_ip} via {outbound_iface_name.split('_')[-1]}")
        return True
    def cleanup_all_network_changes(self):
        """
        Cleans up all network changes made by the router, reverting IPs and DNS
        to DHCP for the interfaces it managed.
        Note: Loopback interface configuration is typically OS-managed and
        does not need DHCP reset.
        """
        self.router_logger.log_message("\n--- Cleaning up all network changes made by Python Router ---")
        self._remove_firewall_rules()
        if self.interface_in_friendly_name and self.router_ip_in:
            self.router_logger.log_message(
                f"[Router] Cleaning up IN interface '{self.interface_in_friendly_name}'...")
            self._cleanup_interface_ip(self.interface_in_friendly_name)
        else:
            self.router_logger.log_message(
                "[Router] No IN interface IP to clean up (not assigned or auto-config failed).")

        if self.interface_out_friendly_name and self.router_ip_out:
            self.router_logger.log_message(
                f"[Router] Cleaning up OUT interface '{self.interface_out_friendly_name}'...")
            self._cleanup_interface_ip(self.interface_out_friendly_name)
        else:
            self.router_logger.log_message(
                "[Router] No OUT interface IP to clean up (not assigned or auto-config failed).")

        # No cleanup for loopback needed as it's typically managed by OS and static.
        self.router_logger.log_message("--- Network cleanup complete. ---")

    def _cleanup_interface_ip(self, iface_friendly_name: str):
        """
        Resets the IP configuration of an interface to DHCP.
        """
        self.router_logger.log_message(
            f"[Router] Cleaning up IP for '{iface_friendly_name}' (setting to DHCP)...")

        netsh_args = ["set", "address", f'name={iface_friendly_name}', "source=dhcp"]

        if self._execute_netsh(netsh_args):
            self.router_logger.log_message(f"[Router] Successfully set '{iface_friendly_name}' to DHCP.")
            return True
        else:
            self.router_logger.log_message(
                f"[Router] WARNING: Failed to set '{iface_friendly_name}' to DHCP. Manual reset may be required.")
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
        - Prefers Scapy's get_if_hwaddr()
        - Falls back to OS interface lists (Windows / netifaces)
        - Final fallback: generates a deterministic synthetic MAC
          (locally administered, unicast, stable per interface name)
        """
        mac = None

        # --- Try Scapy ---
        try:
            from scapy.all import get_if_hwaddr
            mac = get_if_hwaddr(iface_full_name)
            if mac and mac.lower() != "00:00:00:00:00:00":
                return mac.lower()
        except Exception:
            pass

        # --- Try Windows API ---
        try:
            from scapy.arch.windows import get_windows_if_list
            for iface in get_windows_if_list():
                if iface_full_name in (
                        iface.get("name"), iface.get("win_name"), iface.get("friendlyname"),
                        iface.get("description"), iface.get("guid")
                ):
                    mac = (iface.get("mac") or "").lower()
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
        except Exception:
            pass

        # --- Try netifaces ---
        try:
            import netifaces as ni
            if iface_full_name in ni.interfaces():
                addrs = ni.ifaddresses(iface_full_name).get(ni.AF_LINK, [{}])
                if addrs and "addr" in addrs[0]:
                    mac = addrs[0]["addr"].lower()
                    if mac and mac != "00:00:00:00:00:00":
                        return mac
        except Exception:
            pass

        # --- Last resort: generate a synthetic MAC ---
        h = abs(hash(iface_full_name)) & 0xFFFFFFFFFFFF
        fake_mac = "02:%02x:%02x:%02x:%02x:%02x" % (
            (h >> 32) & 0xFF,
            (h >> 24) & 0xFF,
            (h >> 16) & 0xFF,
            (h >> 8) & 0xFF,
            h & 0xFF,
        )
        self.router_logger.log_message(
            RouterRandomMessages(
                name="Router",
                message=f"Synthesized MAC {fake_mac} for iface '{iface_full_name}",
                emoticons=["️⚠️️️", "🧪", "🧨", "🧧", "🌡️", "⚗️"]
            )
        )
        return fake_mac
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
    A stateless utility class for discovering network interfaces and sending various
    types of packets. Each sending function is self-contained and requires
    the interface to be specified on each call.
    """

    def __init__(self, packet_logger):
        """
        Initializes the PacketManager.
        Args:
            packet_logger: A logger instance for logging messages.
        """
        self.packet_logger = packet_logger
        self._tshark_interfaces = []
        self._tshark_path = None
        self._initialize_interface_discovery()
        print("[PacketManager] Initialized and ready.")

    def get_interfaces(self) -> List[dict]:
        """Returns the list of discovered network interfaces."""
        return self._tshark_interfaces

    def _get_tshark_path(self) -> Optional[str]:
        """Discovers the path to tshark.exe."""
        if getattr(sys, "frozen", False):
            # Path for bundled executable
            tshark_exe = Path(sys._MEIPASS) / "tools" / "Wireshark" / "tshark.exe"
            if tshark_exe.exists():
                return str(tshark_exe)

        # Path for development environment
        server_dir = Path(__file__).resolve().parent
        project_root = server_dir.parent
        tools_dir = project_root / "client" / "tools" / "Wireshark"
        candidate = tools_dir / "tshark.exe"
        if candidate.exists():
            return str(candidate)

        # Fallback to system PATH
        system_tshark = shutil.which("tshark")
        if system_tshark:
            return system_tshark

        self.packet_logger.log_message("[PacketManager] Error: tshark.exe not found.")
        return None

    def _initialize_interface_discovery(self):
        """Discovers network interfaces using tshark -D and stores them."""
        self._tshark_path = self._get_tshark_path()
        if not self._tshark_path:
            return
        self.packet_logger.log_message("[PacketManager] Discovering network interfaces via tshark -D...")
        try:
            proc = subprocess.run(
                [self._tshark_path, '-D'], capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            pattern = re.compile(r"(\d+)\.\s+([^(]+)(?:\((.*)\))?")
            for line in proc.stdout.strip().split('\n'):
                match = pattern.match(line)
                if match:
                    self._tshark_interfaces.append({
                        'id': match.group(1),
                        'full_name': match.group(2).strip(),
                        'friendly_name': match.group(3).strip() if match.group(3) else match.group(2).strip()
                    })
            self.packet_logger.log_message(f"[PacketManager] Discovered {len(self._tshark_interfaces)} interfaces.")
        except Exception as e:
            self.packet_logger.log_message(f"[PacketManager] Error during interface discovery: {e}")

    def send_ping(self, target_ip: str, iface: str, src_ip: Optional[str] = None, timeout: int = 2) -> Tuple[
        str, Optional[Packet]]:
        """Sends an ICMP Echo Request from a specific interface."""
        self.packet_logger.log_message(f"[PacketManager] Sending Ping to {target_ip} via {iface}...")
        try:
            packet = IP(dst=target_ip)
            if src_ip: packet.src = src_ip
            packet /= ICMP()

            response = self.sniffer.sr1(packet, timeout=timeout, verbose=0)

            if response is None: return 'TIMEOUT', None
            if response.haslayer(ICMP) and response.getlayer(ICMP).type == 0: return 'REPLY', response
            return 'UNEXPECTED_RESPONSE', response
        except Exception as e:
            self.packet_logger.log_message(f"[Ping] Error sending on {iface}: {e}")
            return 'ERROR', None

    def send_tcp_syn(self, target_ip: str, target_port: int, iface: str, src_ip: Optional[str] = None,
                     timeout: int = 2) -> Tuple[str, Optional[Packet]]:
        """Performs a TCP SYN scan for a single port from a specific interface."""
        self.packet_logger.log_message(f"[PacketManager] Sending TCP SYN to {target_ip}:{target_port} via {iface}...")
        try:
            packet = IP(dst=target_ip)
            if src_ip: packet.src = src_ip
            packet /= TCP(dport=target_port, sport=54321, flags='S')

            response = sr1(packet, timeout=timeout, verbose=0)

            if response is None: return 'FILTERED', None

            if response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN/ACK
                    rst_src_ip = response[IP].dst
                    rst_packet = IP(dst=target_ip, src=rst_src_ip) / TCP(
                        dport=target_port, sport=packet[TCP].sport, flags='R', seq=tcp_layer.ack
                    )
                    send(rst_packet, verbose=0)
                    return 'OPEN', response
                elif tcp_layer.flags & 0x04:  # RST
                    return 'CLOSED', response

            return 'UNEXPECTED_RESPONSE', response
        except Exception as e:
            self.packet_logger.log_message(f"[TCP-SYN] Error sending on {iface}: {e}")
            return 'ERROR', None

    def send_udp_packet(self, target_ip: str, target_port: int, payload: bytes, iface: str,
                        src_ip: Optional[str] = None, timeout: int = 2) -> Tuple[str, Optional[Packet]]:
        """Sends a UDP packet from a specific interface."""
        self.packet_logger.log_message(f"[PacketManager] Sending UDP to {target_ip}:{target_port} via {iface}...")
        try:
            packet = IP(dst=target_ip)
            if src_ip: packet.src = src_ip
            packet /= UDP(dport=target_port, sport=54322) / payload

            response = sr1(packet, timeout=timeout, verbose=0)

            if response is None: return 'NO_RESPONSE', None
            if response.haslayer(ICMP): return 'ICMP_RESPONSE', response
            return 'REPLY', response
        except Exception as e:
            self.packet_logger.log_message(f"[UDP] Error sending on {iface}: {e}")
            return 'ERROR', None

    def send_dns_query(self, target_dns_server: str, domain: str, record_type: str, iface: str,
                       src_ip: Optional[str] = None, timeout: int = 2) -> Tuple[str, Optional[Packet]]:
        """Sends a DNS query from a specific interface."""
        self.packet_logger.log_message(
            f"[PacketManager] Sending DNS Query for {domain} to {target_dns_server} via {iface}...")
        try:
            packet = IP(dst=target_dns_server)
            if src_ip: packet.src = src_ip
            packet /= UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=record_type))

            response = sr1(packet, timeout=timeout, verbose=0)

            if response is None: return 'TIMEOUT', None
            if response.haslayer(DNS): return 'REPLY', response
            return 'UNEXPECTED_RESPONSE', response
        except Exception as e:
            self.packet_logger.log_message(f"[DNS] Error sending on {iface}: {e}")
            return 'ERROR', None

class WiresharkManager:


    def __init__(self, p2pool_data, logger):
        self.p2pool_data = p2pool_data
        self.logger = logger
        self.tshark_procs = {}
        self.redirect_threads = {}
        self.stop_event = threading.Event()
        self.geoip_reader = None
        self._decompressed_db_path = None  # To store the path to the decompressed database

        # Attributes for stateful correlation engine
        self.correlation_lock = threading.Lock()

        self.stream_map = {}  # Stores the final loopback <-> VPN mappings
        self.loopback_interface_id = None
        self.vpn_interface_id = None
        self.min_packet_len = 60
        self.router_manager = None


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
                    self.logger.log_message(f"[GeoIP Debug] IP: {ip_address} identified as Private IP (RFC1918).")
                    return "Private IP"
            except ValueError:
                # If ip_address is not a valid IP string, log and return
                self.logger.log_message(f"[GeoIP Debug] IP: {ip_address} identified as Invalid IP Format.")
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
            self.logger.log_message(
                f"[GeoIP] AddressNotFoundError for IP: {ip_address} - IP not found in database (might be non-public or unlisted).")
            return "Unknown"
        except Exception as e:
            self.logger.log_message(f"[GeoIP] Lookup Error for IP: {ip_address} - Details: {e}")
            return "Lookup Error"

    def _get_tshark_path(self) -> str | None:
        if getattr(sys, "frozen", False):
            self.logger.log_message("[Wireshark] Running in bundled mode.")
            exe = Path(self.p2pool_data.P2POOL_DIR) / "Wireshark" / "tshark.exe"
            return str(exe) if exe.exists() else None
        self.logger.log_message("[Wireshark] Running in development mode. Using relative path.")
        server_dir = Path(__file__).resolve().parent
        project_root = server_dir.parent
        tools_dir = project_root / "client" / "tools" / "Wireshark"
        candidate = tools_dir / "tshark.exe"
        if candidate.exists():
            self.logger.log_message(f"[Wireshark] Found tshark at: {candidate}")
            return str(candidate)
        system_tshark = shutil.which("tshark")
        if system_tshark:
            self.logger.log_message(f"[Wireshark] Falling back to system tshark at: {system_tshark}")
            return system_tshark
        self.logger.log_message(
            f"[Wireshark] Error: tshark.exe not found. Looked in {candidate} and on PATH."
        )
        return None

    def _list_interfaces(self, tshark_path: str) -> list[dict]:
        self.logger.log_message("[Wireshark] Discovering network interfaces...")
        interfaces = []
        try:
            proc = subprocess.run(
                [tshark_path, '-D'], capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            pattern = re.compile(r"(\d+)\.\s+(.*)")
            interface_output_lines = proc.stdout.strip().split('\n')

            self.logger.log_message("[Wireshark] Available Network Interfaces:")
            for line in interface_output_lines:
                match = pattern.match(line)
                if match:
                    iface_id = match.group(1)
                    iface_name = match.group(2).strip()
                    interfaces.append({'id': iface_id, 'name': iface_name})
                    self.logger.log_message(f"  ID: {iface_id}, Name: {iface_name}")

            self.logger.log_message(f"[Wireshark] Found {len(interfaces)} interfaces.")
        except Exception as e:
            self.logger.log_message(f"[Wireshark] An error occurred while listing interfaces: {e}")
        return interfaces

    def start_capture(self, main_interface_name: str = 'Wi-Fi', router_manager = None, promiscuous=True):
        self._initialize_geoip()
        self.router_manager = router_manager
        tshark_path = self._get_tshark_path()
        if not tshark_path: return False
        if self.tshark_procs:
            self.logger.log_message("[Wireshark] Capture is already running.")
            return False

        # Ensure GeoIP reader is initialized before starting capture
        if self.geoip_reader is None:
            self.logger.log_message("[GeoIP] GeoIP reader is not initialized. Attempting to initialize it now.")
            self._initialize_geoip()
            if self.geoip_reader is None:  # If initialization still failed
                self.logger.log_message("[GeoIP] Failed to initialize GeoIP reader. Proceeding without GeoIP lookups.")
                # You might want to return False here if GeoIP is critical for your application
                # For now, we'll allow capture to proceed without GeoIP if it fails.

        available_interfaces = self._list_interfaces(tshark_path)
        if not available_interfaces: return False

        # --- NEW LOGIC: Resolve main_interface_name to its ID ---
        main_interface_id = None
        for iface in available_interfaces:
            # We need to be careful with string matching for interface names
            # Use 'in' for partial matches, or '==' for exact matches
            # For "Wi-Fi", a simple "Wi-Fi" in iface['name'] should work.
            if main_interface_name.lower() in iface['name'].lower():
                main_interface_id = iface['id']
                self.logger.log_message(
                    f"[Wireshark] Resolved '{main_interface_name}' to ID: {main_interface_id}")
                break

        if not main_interface_id:
            self.logger.log_message(
                f"[Wireshark] Error: Main interface '{main_interface_name}' not found. Available interfaces: "
                f"{[iface['name'] for iface in available_interfaces]}")
            return False
        # --- END NEW LOGIC ---

        interfaces_to_capture = {main_interface_id}  # Start with the resolved main interface

        # Add VPN and Loopback interfaces dynamically
        for iface in available_interfaces:
            if "WireGuard Tunnel" in iface['name'] or "ProtonVPN" in iface['name']:
                self.logger.log_message(
                    f"[Wireshark] Detected active VPN interface: {iface['name']} (ID: {iface['id']}). Adding to capture.")
                interfaces_to_capture.add(iface['id'])
                # Set VPN interface ID for correlation engine if not already set
                if self.vpn_interface_id is None:
                    self.vpn_interface_id = iface['id']
            elif "Loopback" in iface['name']:
                self.logger.log_message(
                    f"[Wireshark] Detected Loopback interface: {iface['name']} (ID: {iface['id']}). Adding to capture.")
                interfaces_to_capture.add(iface['id'])
                # Set Loopback interface ID for correlation engine if not already set
                if self.loopback_interface_id is None:
                    self.loopback_interface_id = iface['id']

        self.logger.log_message(f"[Wireshark] Final capture list (IDs): {list(interfaces_to_capture)}")
        self.logger.log_message(
            f"[CorrelationEngine] Watching for 'cause' on Loopback ID: {self.loopback_interface_id}")
        self.logger.log_message(f"[CorrelationEngine] Watching for 'effect' on VPN ID: {self.vpn_interface_id}")

        self.stop_event.clear()

        def _bpf_addr(a: str | None) -> str | None:
            # strip IPv6 zone index, e.g. 'fe80::1%Ethernet'
            return a.split("%", 1)[0] if isinstance(a, str) else None

        def build_capture_filter() -> str:
            # A list of BPF parts that will be joined with 'and'
            STR_BCAST_PART1 = 0x5354525f  # Represents "STR_"
            STR_BCAST_PART2 = 0x42434153  # Represents "BCAS"4
            parts = [
                # 1. Basic IP traffic only
                "(ip or ip6)",
                "not arp",

                # 2. Filter Multicast and common Discovery/Chatter protocols
                "not (ip multicast or ip6 multicast)",
                "not (udp port 5353 or udp port 1900 or udp port 3702 or udp port 5355)",
                "not (port 67 or port 68 or port 546 or port 547)",

                # 3. Filter local loopback traffic (IPv4 and IPv6)
                "not host 127.0.0.1",
                "not host ::1",
                "not host 10.2.0.2",
                # 4. Filter NetBIOS Name Service noise on the APIPA/link-local network
                "not (udp port 137 and net 169.254.0.0/16)",

                "not port 5357",
                "not port 889",
                f"not (udp[8:4] = {STR_BCAST_PART1} and udp[12:4] = {STR_BCAST_PART2})",

                #Banned IPS
                "not host 89.222.103.1"
            ]
            parts.append(f"not (src host {self.router_manager.router_ip_out} and dst host {self.router_manager.router_ip_out})")
            parts.append("not (ip broadcast and udp and dst port 22222)")
            # Exclude very small frames
            min_len = int(getattr(self, "min_packet_len", 0) or 0)
            if min_len > 0:
                parts.append(f"greater {max(0, min_len - 1)}")

            return "(" + " and ".join(parts) + ")"
        if self.router_manager.started:
            capture_filter = build_capture_filter()
        else:
            capture_filter = ""
        base_command = [
            tshark_path, "-l", "-T", "json", "-V",
            "-o", "tcp.desegment_tcp_streams:TRUE",
            "-f", capture_filter
        ]
        if not promiscuous:
            base_command.append('-p')
        def start_capture():
            started_count = 0
            for iface_id in interfaces_to_capture:
                self.logger.log_message(f"[Wireshark] Starting capture on interface {iface_id}...")
                command = base_command + ['-i', str(iface_id)]
                try:
                    proc = subprocess.Popen(
                        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    self.tshark_procs[iface_id] = proc
                    thread = threading.Thread(target=self._redirect_output, args=(proc, iface_id), daemon=True)
                    self.redirect_threads[iface_id] = thread
                    thread.start()
                    self.logger.log_message(f"[Wireshark] Capture started on interface {iface_id} with PID: {proc.pid}")
                    started_count += 1
                except Exception as e:
                    self.logger.log_message(f"[Wireshark] Failed to start capture on interface {iface_id}: {e}")
            return started_count > 0

        if self.router_manager.started:
            self.logger.log_message(f"[Wireshark] Parallel Capture started")
            funcs = []
            def capture_helper(iface_id):
                self.logger.log_message(f"[Wireshark] Starting capture on interface {iface_id}...")
                command = base_command + ['-i', str(iface_id)]
                try:
                    proc = subprocess.Popen(
                        command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                        text=True, creationflags=subprocess.CREATE_NO_WINDOW
                    )
                    self.tshark_procs[iface_id] = proc
                    thread = threading.Thread(target=self._redirect_output, args=(proc, iface_id), daemon=True)
                    self.redirect_threads[iface_id] = thread
                    thread.start()
                    self.logger.log_message(
                        f"[Wireshark] Capture started on interface {iface_id} with PID: {proc.pid}")
                except Exception as e:
                    self.logger.log_message(f"[Wireshark] Failed to start capture on interface {iface_id}: {e}")
            started_count = 0
            for iface_id in interfaces_to_capture:
                funcs.append((capture_helper, (iface_id,)))
                started_count +=1
            self.router_manager.parallel_python.increase_ram_usage(5000)
            self.router_manager.parallel_python.run_all_parallel(funcs,
                                                             return_type="void")
            return started_count
        else:
            return start_capture()

    def stop_capture(self):
        if not self.tshark_procs:
            self.logger.log_message("[Wireshark] Capture is not running.")
            return

        self.logger.log_message("[Wireshark] Stopping all captures...")
        self.stop_event.set()
        for iface_id, proc in self.tshark_procs.items():
            if proc.poll() is None:
                proc.terminate()
        for iface_id, proc in self.tshark_procs.items():
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.logger.log_message(f"[Wireshark] Process for interface {iface_id} did not terminate, killing.")
                proc.kill()

        if self.geoip_reader:
            self.geoip_reader.close()
            self.logger.log_message("[GeoIP] Database closed.")

        # The decompressed file is now persistent, no need to delete it on stop.
        self._decompressed_db_path = None  # Clear the path reference

        self.logger.log_message("[Wireshark] All capture processes stopped.")
        self.tshark_procs.clear()
        self.redirect_threads.clear()

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

    def _build_scapy_from_tshark(self, layers: Dict[str, Any]) -> Optional[Packet]:
        """
        Best-effort Scapy reconstruction from tshark JSON.
        Supports: Ether (if present), IPv4/IPv6 + TCP/UDP, ICMPv6 echo, and Raw payloads.
        """
        eth = layers.get("eth", {})
        eth_src = eth.get("eth.src")
        eth_dst = eth.get("eth.dst")

        ipver, src_ip, dst_ip = self._get_ip_pair(layers)

        # Decide payload (Raw) source: prefer L4 payload keys, else generic data/data-text-lines
        raw_bytes = None
        # TCP payload as hex
        if "tcp" in layers and "tcp.payload" in layers["tcp"]:
            raw_bytes = self._hexdump_to_bytes(layers["tcp"]["tcp.payload"])
        # UDP payload as hex
        if raw_bytes is None and "udp" in layers and "udp.payload" in layers["udp"]:
            raw_bytes = self._hexdump_to_bytes(layers["udp"]["udp.payload"])
        # tshark generic data
        if raw_bytes is None and "data" in layers and isinstance(layers["data"].get("data.data"), str):
            raw_bytes = self._hexdump_to_bytes(layers["data"]["data.data"])
        # data-text-lines (strings → bytes)
        if raw_bytes is None and "data-text-lines" in layers:
            dtl = layers["data-text-lines"]
            if isinstance(dtl, list):
                dtl = "\n".join(dtl)
            if isinstance(dtl, str):
                try:
                    raw_bytes = dtl.encode("utf-8", errors="ignore")
                except Exception:
                    pass

        l4_layer = None

        # Transport build
        if "tcp" in layers:
            tcp = layers["tcp"]
            sport = self._as_int(tcp.get("tcp.srcport"), 0) or 0
            dport = self._as_int(tcp.get("tcp.dstport"), 0) or 0
            l4_layer = TCP(sport=sport, dport=dport)
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
            # Echo req/rep most common
            if t == 128:  # Echo Request
                ident = self._as_int(ic6.get("icmpv6.echo.identifier"), 0) or 0
                seq = self._as_int(ic6.get("icmpv6.echo.sequence_number"), 0) or 0
                l4_layer = ICMPv6EchoRequest(id=ident, seq=seq)
            elif t == 129:  # Echo Reply
                ident = self._as_int(ic6.get("icmpv6.echo.identifier"), 0) or 0
                seq = self._as_int(ic6.get("icmpv6.echo.sequence_number"), 0) or 0
                l4_layer = ICMPv6EchoReply(id=ident, seq=seq)
            else:
                if raw_bytes:
                    l4_layer = Raw(load=raw_bytes)

        else:
            # No recognizable L4; still attach any raw bytes
            if raw_bytes:
                l4_layer = Raw(load=raw_bytes)

        # Build IP/IPv6
        net = None
        if ipver == "ipv4":
            net = IP(src=src_ip, dst=dst_ip)
        elif ipver == "ipv6":
            net = IPv6(src=src_ip, dst=dst_ip)

        # Final assembly
        out = None
        if eth_src and eth_dst:
            out = Ether(src=str(eth_src), dst=str(eth_dst))
            if net is not None:
                out = out / net
        else:
            # No Ether, start from network layer if present
            out = net if net is not None else None

        if out is None:
            # Nothing we can confidently build
            return None

        if l4_layer is not None:
            out = out / l4_layer

        return out

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
        yield_no_gil(0.1)
        if not isinstance(packet_data, dict):
            return  # ignore non-JSON / malformed

        try:
            layers = packet_data.get("_source", {}).get("layers", {})
            if not layers:
                return

            # ----------------------------------------------------------
            #          Basic frame / IP / transport extraction
            # ----------------------------------------------------------
            frame = layers.get("frame", {})
            timestamp = frame.get("frame.time", "N/A")
            packet_num = frame.get("frame.number", "N/A")
            packet_len = frame.get("frame.len", "N/A")

            # Filter by minimum packet length
            try:
                if int(packet_len) < self.min_packet_len:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering small packet (Len: {packet_len}) on interface {interface_id}.")
                    return
            except ValueError:
                pass  # packet_len might be "N/A"

            ip_layer = layers.get("ip") or layers.get("ipv6")
            src_ip = ip_layer.get("ip.src", ip_layer.get("ipv6.src", "N/A")) if ip_layer else "N/A"
            dst_ip = ip_layer.get("ip.dst", ip_layer.get("ipv6.dst", "N/A")) if ip_layer else "N/A"

            # ----------------------------------------------------------
            #                  Filtering for idle/senseless traffic
            # ----------------------------------------------------------
            # IPv4 broadcast?
            if self._is_ipv4_broadcast(dst_ip):
                self.logger.log_message(
                    f"[Wireshark Filter] Filtering IPv4 Broadcast packet to {dst_ip} on interface {interface_id}.")
                return

            # Multicast/Link-local multicast/Discovery?
            dst_is_mcast = self._is_multicast_or_llm(dst_ip)
            if dst_is_mcast:
                self.logger.log_message(
                    f"[Wireshark Filter] Filtering Multicast/Discovery packet to {dst_ip} on interface {interface_id}.")
                return

            def _nz(ip: str) -> str:
                return ip.split("%", 1)[0] if isinstance(ip, str) else ip

            try:
                dst_obj = ipaddress.ip_address(_nz(dst_ip))
            except ValueError:
                dst_obj = None

            def _is_loopback_addr(ip: str) -> bool:
                import ipaddress
                try:
                    return ipaddress.ip_address(_nz(ip)).is_loopback
                except Exception:
                    return False
            # Drop MLD/ND noise: ff02::/16 multicast and solicited-node ff02::1:ff00:0/104
            if "icmpv6" in layers and dst_obj and dst_obj.is_multicast:
                # Common ICMPv6 types to suppress: 130-143 (MLD), 133-137 (ND/RA/RS/NS/NA)
                self.logger.log_message(
                    f"[Wireshark Filter] Filtering ICMPv6 multicast to {dst_ip} on interface {interface_id}."
                )
                return
            if _is_loopback_addr(src_ip) and _is_loopback_addr(dst_ip):
                # optional: lightweight log or counter
                self.logger.log_message(f"[Wireshark] Skipping local loopback packet {src_ip} -> {dst_ip}")
                return  # 🚫 do not forward or “send via Scapy”

            if self.router_manager.started and src_ip == dst_ip:
                # 💡 This packet is addressed to itself. We need to check if it's a case
                # that requires processing (like private/link-local traffic).
                is_legitimate_loopback = False
                try:
                    ip_obj = ipaddress.ip_address(src_ip)

                    # This is the check: is the address private, link-local, or standard loopback?
                    if ip_obj.is_private or ip_obj.is_link_local or ip_obj.is_loopback:
                        is_legitimate_loopback = True

                except ValueError:
                    # If it's not a valid IP address, we'll treat it as not legitimate.
                    is_legitimate_loopback = False

                if is_legitimate_loopback:
                    self.logger.log_message(
                        f"[Wireshark] 💧 Dropping loopback public IP packet: {src_ip} -> {dst_ip}"
                    )
                    return
                else:
                    # 🚫 This is a self-addressed packet using a public IP. Drop it.
                    self.logger.log_message(
                        f"[Wireshark] 💧 Dropping suspicious self-addressed public IP packet: {src_ip} -> {dst_ip}"
                    )
                    return  # Stop processing immediately
            if self.router_manager.started:
                link_local_ip_bare = self.router_manager.router_ipv6_link_local_out.split('%')[0]
                if dst_ip == link_local_ip_bare or src_ip == link_local_ip_bare:
                    self.logger.log_message(
                        f"[Wireshark] 💧 Dropping packet to our own link-local address: {dst_ip}"
                    )
                    return # Stop processing immediately
            # 0) Fast path: skip non-IP frames entirely (prevents N/A logs)
            has_ip4 = "ip" in layers
            has_ip6 = "ipv6" in layers
            if not (has_ip4 or has_ip6):
                return

            # from here on, it is safe to assume we have IPv4 or IPv6
            ip_layer = layers.get("ip") or layers.get("ipv6")
            src_ip = ip_layer.get("ip.src", ip_layer.get("ipv6.src", "N/A"))
            # Common noisy ports
            common_noisy_ports = {
                "5353", "1900", "137", "138", "139", "445", "520", "161", "162",
                "67", "68", "546", "547", "5678", "5679", "3702", "5355","22222"
            }

            if "udp" in layers:
                udp_layer = layers["udp"]
                dst_port = udp_layer.get("udp.dstport", "N/A")
                src_port = udp_layer.get("udp.srcport", "N/A")
                if dst_port in common_noisy_ports or src_port in common_noisy_ports:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering Discovery/Idle UDP packet on port {dst_port} from {src_ip} to {dst_ip} on interface {interface_id}.")
                    return

            if "tcp" in layers:
                tcp_layer = layers["tcp"]
                dst_port = tcp_layer.get("tcp.dstport", "N/A")
                src_port = tcp_layer.get("tcp.srcport", "N/A")
                if dst_port in common_noisy_ports or src_port in common_noisy_ports:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering Discovery/Idle TCP packet on port {dst_port} from {src_ip} to {dst_ip} on interface {interface_id}.")
                    return

            # ----------------------------------------------------------
            #                  Contextual / VPN tagging
            # ----------------------------------------------------------
            def _is_private(addr: str) -> bool:
                try:
                    return ipaddress.ip_address(addr.split("%")[0]).is_private  # strip zone index
                except ValueError:
                    return True  # treat invalid as private to avoid FP egress tags

            context_tags: list[str] = []

            # 1) Loopback packet that will be encrypted by VPN soon
            if (
                    interface_id == self.loopback_interface_id and
                    self.vpn_interface_id is not None and
                    not _is_private(dst_ip)
            ):
                context_tags.append("via-VPN-out")

            # 2) Traffic already on VPN adapter
            if interface_id == self.vpn_interface_id:
                if _is_private(src_ip) and not _is_private(dst_ip):
                    context_tags.append("VPN→WAN")  # egress after encryption
                elif not _is_private(src_ip) and _is_private(dst_ip):
                    context_tags.append("WAN→VPN")  # ingress before decryption
                else:
                    context_tags.append("VPN-internal")

            # ----------------------------------------------------------
            #               Transport & service lookup
            # ----------------------------------------------------------
            src_port = dst_port = "N/A"
            tcp_layer = layers.get("tcp")
            if tcp_layer:
                src_port = tcp_layer.get("tcp.srcport", "N/A")
                dst_port = tcp_layer.get("tcp.dstport", "N/A")
            elif "udp" in layers:
                udp_layer = layers["udp"]
                src_port = udp_layer.get("udp.srcport", "N/A")
                dst_port = udp_layer.get("udp.dstport", "N/A")

            highest_proto = frame.get("frame.protocols", "N/A").split(":")[-1].upper()

            # ----------------------------------------------------------
            #                     GeoIP (optional)
            # ----------------------------------------------------------
            dst_location = ""
            if hasattr(self, "_get_geoip_location"):
                dst_location = self._get_geoip_location(dst_ip)
            loc_str = f"({dst_location})" if dst_location else ""

            # ----------------------------------------------------------
            #                       Structured log
            # ----------------------------------------------------------
            tag_str = f" [{' | '.join(context_tags)}]" if context_tags else ""
            self.logger.log_message(
                f"[NetTrace-{interface_id}] Pkt:{packet_num:<6} | {timestamp} | Len:{packet_len:<5} | "
                f"{src_ip}:{src_port} -> {dst_ip}:{dst_port} {loc_str} | Proto:{highest_proto}{tag_str}"
            )

            # ----------------------------------------------------------
            #              Application-layer quick peeks
            # ----------------------------------------------------------
            if "http" in layers:
                http = layers["http"]
                if "http.request.method" in http:
                    host = http.get("http.host", "")
                    uri = http.get("http.request.full_uri", "")
                    self.logger.log_message(
                        f"[HTTP-{interface_id}] {src_ip} → {host}{uri} ({http['http.request.method']}){tag_str}")
                elif "http.response.code" in http:
                    code = http["http.response.code"]
                    self.logger.log_message(
                        f"[HTTP-{interface_id}] {dst_ip} ← {code}{tag_str}")

            elif "ssl" in layers or "tls" in layers:
                tls = layers.get("ssl", layers.get("tls", {}))
                if "tls.handshake.extensions_server_name" in tls:
                    sni = tls["tls.handshake.extensions_server_name"]
                    self.logger.log_message(
                        f"[TLS-{interface_id}] SNI={sni} {src_ip}:{src_port} → {dst_ip}:{dst_port}{tag_str}")

            if "dns" in layers and layers["dns"].get("dns.qry.name"):
                dns = layers["dns"]
                qname = dns["dns.qry.name"]
                qtype = dns["dns.qry.type"]
                answer = dns.get("dns.a", dns.get("dns.aaaa", ""))
                self.logger.log_message(
                    f"[DNS-{interface_id}] {qname} ({qtype}) → {answer or 'NO-ANSWER'}{tag_str}")

            # ----------------------------------------------------------
            #           Optional reassembled payload preview (TCP/UDP)
            # ----------------------------------------------------------
            raw_payload_hex_str = None
            if tcp_layer and tcp_layer.get("tcp.payload"):
                raw_payload_hex_str = tcp_layer["tcp.payload"].replace(":", "")
            elif "udp" in layers and layers["udp"].get("udp.payload"):
                raw_payload_hex_str = layers["udp"]["udp.payload"].replace(":", "")
            elif "data-text-lines" in layers:
                reassembled = layers["data-text-lines"]
                if isinstance(reassembled, list):
                    reassembled = "\n".join(reassembled)
                try:
                    raw_payload_hex_str = reassembled.encode('utf-8', errors='ignore').hex()
                except Exception:
                    raw_payload_hex_str = None

            if raw_payload_hex_str:
                truncated_hex_display = raw_payload_hex_str[:128] + ("..." if len(raw_payload_hex_str) > 128 else "")
                self.logger.log_message(f"[Payload-Wireshark] 📦 Raw payload (hex): {truncated_hex_display}...")

                try:
                    payload_bytes = bytes.fromhex(raw_payload_hex_str)
                    decoded_payload = payload_bytes.decode('utf-8', errors='replace')

                    replacement_char_count = decoded_payload.count('\ufffd')
                    printable_char_count = sum(1 for ch in decoded_payload if ch in string.printable)

                    is_human_readable = True
                    if len(decoded_payload) > 0:
                        if replacement_char_count / len(decoded_payload) > 0.10:
                            is_human_readable = False
                        elif printable_char_count / len(decoded_payload) < 0.50:
                            is_human_readable = False
                    elif len(payload_bytes) > 0:
                        is_human_readable = False

                    if is_human_readable and len(decoded_payload.strip()) > 0:
                        self.logger.log_message(f"[Payload-Wireshark] 📝 Decoded payload: {decoded_payload}")
                    else:
                        self.logger.log_message("[Payload-Wireshark] ⚠️ Decoded payload not considered human-readable.")
                except UnicodeDecodeError:
                    self.logger.log_message("[Payload-Wireshark] ⚠️ Could not decode payload as UTF-8.")
                except Exception as e:
                    self.logger.log_message(f"[Payload-Wireshark] ❌ Error processing/decoding payload: {e}")
            else:
                self.logger.log_message(f"[Payload-Wireshark] 📦 No reassembled payload data found.")

            # ----------------------------------------------------------
            #                 NEW: build Scapy & dispatch
            # ----------------------------------------------------------
            try:
                if self.router_manager.started:
                    scapy_pkt = self._build_scapy_from_tshark(layers)
                    if scapy_pkt is None:
                        # Nothing we could reconstruct; still bail gracefully
                        self.logger.log_message("[Wireshark-Process] ⚠️ Could not build Scapy packet from tshark JSON.")
                        return

                    # Hand off to your router with inbound iface set to "WireShark"
                    try:
                        if self.router_manager.started and (
                                (self.router_manager.router_ip_out and self.router_manager.router_ip_out in str(
                                    src_ip)) or
                                (self.router_manager.router_ip_out and self.router_manager.router_ip_out in str(dst_ip))
                        ):
                            if self.router_manager.router_ip_out in str(
                                    src_ip) and self.router_manager.router_ip_out in str(dst_ip):
                                self.logger.log_message(
                                    "[Wireshark-Process] Skipping Routers self forward")
                                return
                            try:
                                if self.router_manager.router_ip_out in str(dst_ip):
                                    self.logger.log_message(
                                        "[Wireshark-Process] 🪈 Sending Routers own packet via Scapy through PYPIPE")
                                    # Prefer (pkt, iface) signature if your router supports it
                                    self.router_manager.hyperv_manager.send_packet(bytes(scapy_pkt))
                                else:
                                    self.logger.log_message(
                                        "[Wireshark-Process] 🪈 Sending packet via Scapy through router as WireShark.")
                                    # Prefer (pkt, iface) signature if your router supports it
                                    self.router_manager.process_packet(scapy_pkt, "WireShark")
                            except TypeError:
                                # Fallback to single-arg call if that’s your router’s API
                                self.router_manager.hyperv_manager.send_packet(bytes(scapy_pkt))
                            return
                        self.logger.log_message(
                            "[Wireshark-Process] 🪈 Sending packet via Scapy through router as WireShark.")
                        # Prefer (pkt, iface) signature if your router supports it
                        self.router_manager.process_packet(scapy_pkt, "WireShark")
                    except TypeError:
                        # Fallback to single-arg call if that’s your router’s API
                        self.router_manager.process_packet(scapy_pkt)
            except Exception as e:
                self.logger.log_message(f"[Wireshark-Process] ❌ Scapy build/dispatch error: {e}")

        except Exception as e:
            self.logger.log_message(
                f"[Wireshark-Process] Error processing packet on interface {interface_id}: {e}")

    def _redirect_output(self, process: subprocess.Popen, interface_id: str):
        if not process.stdout: return
        json_buffer = ""
        decoder = json.JSONDecoder()
        for line in iter(process.stdout.readline, ''):
            if self.stop_event.is_set(): break
            json_buffer += line
            while True:
                start_index = json_buffer.find('{')
                if start_index == -1:
                    json_buffer = ""
                    break
                json_buffer = json_buffer[start_index:]
                try:
                    packet_data, index = decoder.raw_decode(json_buffer)
                    self._process_packet(packet_data, interface_id)
                    json_buffer = json_buffer[index:]
                except json.JSONDecodeError:
                    break
        self.logger.log_message(f"[Wireshark] Output stream ended for interface {interface_id}.")

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

        self.logger.log_message(f"[Scraper] ▶️ Starting scrape for: {self._current_url} with a {delay_seconds}s delay.")
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
                self.logger.log_message(f"[Scraper] 💥 Exception during scrape task: {e}\n{traceback.format_exc()}")
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

    async def _perform_scrape(self, url: str, delay_seconds: int) -> dict:
        self.scraping_progress_signal.emit("Launching browser for interaction...")
        self.logger.log_message(f"[Scraper-DBG] Launching visible Playwright for {url}")

        playwright = None
        browser = None
        headless_browser = None

        try:
            playwright = await async_playwright().start()
            browser = await playwright.chromium.launch(headless=False,
                                                       args=[
                                                           "--disable-blink-features=AutomationControlled",
                                                           "--no-sandbox",
                                                           "--disable-dev-shm-usage",
                                                           "--disable-gpu",
                                                       ])
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
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
                'Accept': 'image/avif,image/webp,image/apng,image/svg+xml,image/*,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Accept-Encoding': 'gzip, deflate, br',
            }

            self.scraping_progress_signal.emit("Downloading images...")
            failed_images = []
            for image_info in scraped_data.get("extracted_images", []):
                img_url = image_info['src']
                try:
                    if img_url.startswith('data:image'):
                        header, encoded = img_url.split(',', 1)
                        image_data = base64.b64decode(encoded)
                        image_info['data'] = image_data
                    else:
                        if img_url.startswith('//'):
                            img_url = 'https:' + img_url

                        headers_for_request = hardcoded_headers.copy()
                        headers_for_request['Referer'] = url

                        response = requests.get(img_url, headers=headers_for_request, timeout=10)
                        response.raise_for_status()
                        image_info['data'] = response.content
                except Exception:
                    self.logger.log_message(
                        f"[ImageDownloader] ⚠️ Request failed for {img_url[:100]}... Falling back to browser screenshot.")
                    failed_images.append(image_info)

            if failed_images:
                self.scraping_progress_signal.emit("Retrying failed images with headless browser...")
                headless_browser = await playwright.chromium.launch(headless=True)
                headless_context = await headless_browser.new_context(
                    storage_state=storage_state,
                    extra_http_headers=hardcoded_headers
                )
                for image_info in failed_images:
                    img_url = image_info['src']
                    try:
                        if img_url.startswith('//'):
                            img_url = 'https:' + img_url
                        img_page = await headless_context.new_page()
                        await img_page.goto(img_url, timeout=15000)

                        dimensions = await img_page.evaluate('''() => {
                            const img = document.querySelector('img');
                            if (!img) return { width: 800, height: 600 }; // Default size
                            return {
                                width: img.naturalWidth,
                                height: img.naturalHeight
                            };
                        }''')

                        await img_page.set_viewport_size(dimensions)

                        image_info['data'] = await img_page.screenshot()
                        await img_page.close()
                    except Exception as e:
                        self.logger.log_message(
                            f"[ImageDownloader] ❌ Failed to process image {img_url[:100]}... with browser: {e}")
                        image_info['data'] = None

            self.status = "completed"
            return scraped_data

        except Exception as e:
            self.logger.log_message(f"[Scraper] 🚨 Playwright scrape failed: {e}")
            raise ValueError(f"Playwright error: {e}")

        finally:
            if browser and browser.is_connected(): await browser.close()
            if headless_browser and headless_browser.is_connected(): await headless_browser.close()
            if playwright: await playwright.stop()

    def _parse_content(self, html_content: str, base_url: str) -> dict:
        soup = BeautifulSoup(html_content, 'html.parser')

        for script in soup(["script", "style"]):
            script.extract()

        extracted_text = soup.get_text(separator='\n', strip=True)

        extracted_links = []
        for a_tag in soup.find_all('a', href=True):
            link_text = a_tag.get_text(strip=True)
            href = a_tag['href']
            if not href.startswith('http') and not href.startswith('//'):
                try:
                    from requests.compat import urljoin
                    href = urljoin(base_url, href)
                except Exception:
                    pass
            extracted_links.append({"text": link_text, "href": href})

        extracted_images = []
        for img_tag in soup.find_all('img', src=True):
            src = img_tag['src']
            if not src.startswith('http') and not src.startswith('//'):
                try:
                    from requests.compat import urljoin
                    src = urljoin(base_url, src)
                except Exception:
                    pass
            extracted_images.append({"src": src, "alt": img_tag.get('alt', '')})

        return {
            "extracted_text": extracted_text,
            "extracted_links": extracted_links,
            "extracted_images": extracted_images
        }
