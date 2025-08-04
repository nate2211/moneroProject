import asyncio
import base64
import ctypes
import os
import queue
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
import scapy
from PyQt5.QtCore import QObject, pyqtSignal
from bs4 import BeautifulSoup
from playwright.async_api import async_playwright
from scapy.all import send, sr1, conf
from scapy.arch import get_if_hwaddr
from scapy.layers.dhcp import DHCP
from scapy.layers.dhcp6 import DHCP6
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import TCP, ICMP
from scapy.layers.inet6 import IPv6
from scapy.layers.l2 import Ether, ARP
from scapy.layers.tls.record import TLS
from scapy.packet import Packet
from scapy.layers.inet import IP, UDP
from typing import Tuple, Dict
import xml.etree.ElementTree as ET
from scapy.layers.kerberos import (Kerberos)
from scapy.sessions import TCPSession
from p2pool_sniffer import SnifferSoftware
from p2pool_router_managers_2 import ARPManager, OutboundLoadBalancer, DNSManager, RIPManager, IGMPManager, \
    LinkAggregationManager, FirewallManager, DHCPServer, HandshakeManager, NATManager, MLDReport, MLDDone, RIP, \
    RIPEntry, mDNSManager, StratumManager
from p2pool_router_managers import PacketSigningManager, PacketWriter, SendBackManager, PacketCatcherManager, \
    ICMPManager, EthernetBridgeManager, ForwardingManager, KerberosManager, HTTPSManager, EthernetL2Manager, \
    TransportManager, SYNScanner, NotificationManager, RouterRandomMessages, FunctionCallTracker, ISAKMPManager
from p2pool_tools import ParallelPythonTool

packet_queue = queue.Queue(maxsize=5)

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


        self.arp_manager = ARPManager(router_logger)
        self.outbound_load_balancer = OutboundLoadBalancer(router_logger)  # New: Outbound Load Balancer
        self.packet_signer = PacketSigningManager(router_logger)
        self.sendback_manager = SendBackManager(router_logger, self.packet_signer, self.outbound_load_balancer)
        self.packet_writer = PacketWriter(router_logger, self._interfaces_config, self.packet_signer, self.outbound_load_balancer)
        self.dns_manager = DNSManager(router_logger, self.packet_writer)
        self.mdns_manager = mDNSManager(router_logger, self.packet_writer, self._interfaces_config)
        self.rip_manager = RIPManager(router_logger)
        self.nat_manager = None  # Initialized after public IP is known
        self.notification_manager = None
        self.packet_catcher = PacketCatcherManager(router_logger, self._interfaces_config)
        self.handshake_manager = None
        self.igmp_manager = IGMPManager(router_logger, self.packet_writer)
        self.icmp_manager = ICMPManager(router_logger, self.packet_writer, self.sendback_manager, self._interfaces_config)
        self.dhcp_server_in = None
        self.dhcp_server_out = None
        self.lag_manager = LinkAggregationManager(router_logger)  # New: Link Aggregation Manager
        self.firewall_manager = FirewallManager(router_logger)  # New: Firewall Manager
        self.syn_scanner = None
        self.ethernet_manager = EthernetBridgeManager(router_logger, self.packet_writer)
        self.forwarding_manager = ForwardingManager(self.function_call_tracker, router_logger=self.router_logger,)
        self.kerberos_manager = KerberosManager(router_logger, self.packet_writer)
        self.https_manager = HTTPSManager(router_logger)
        self.ethernet_l2_manager = EthernetL2Manager(self.function_call_tracker, router_logger)
        self.transport_manager = TransportManager(router_logger, self.packet_signer)
        self.isakmp_manager = None
        self.stratum_manager = StratumManager(router_logger)
        self.parallel_python = ParallelPythonTool(router_logger)
        self.parallel_python.inject_into(self.transport_manager)
        self.parallel_python.inject_into(self.packet_catcher)
        self.packet_catcher_heuristic_rates = {
            'TCP': 0.60,
            'UDP': 0.60,
            'DEFAULT': 0.60,
        }



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
        self.firewall_manager.add_rule(action='permit', protocol='udp', src_ip='0.0.0.0', dst_ip='255.255.255.255', src_port=68,
         dst_port=67)
        self.firewall_manager.add_rule(action='permit', protocol='udp', src_ip='any', dst_ip='255.255.255.255', src_port=67,
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

    def _get_system_networks(self) -> list[ipaddress.IPv4Network]:
        """Gets all currently active IPv4 networks on the system using psutil."""
        active_networks = []
        try:
            for iface_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == socket.AF_INET and addr.address and addr.netmask:  # Use socket.AF_INET
                        try:
                            network_obj = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                            active_networks.append(network_obj)
                        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                            self.router_logger.log_message(
                                f"[Router] Warning: Could not parse network {addr.address}/{addr.netmask}: {e}")
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

    def _get_default_gateway_for_interface(self, iface_friendly_name: str) -> str | None:
        """
        Attempts to get the default gateway IP for a specific interface using PowerShell.
        (Windows specific: uses Get-NetRoute and Get-NetAdapter)
        """
        self.router_logger.log_message(f"[Router] Discovering default gateway for '{iface_friendly_name}'...")
        try:
            ps_command = f"""
            $iface = Get-NetAdapter -Name "{iface_friendly_name}" -ErrorAction SilentlyContinue
            if ($iface) {{
                (Get-NetRoute -DestinationPrefix "0.0.0.0/0" -ErrorAction SilentlyContinue | Where-Object {{ $_.InterfaceIndex -eq $iface.IfIndex }}).NextHop | Select-Object -First 1
            }}
            """

            result = subprocess.run(
                ["powershell.exe", "-Command", ps_command],
                capture_output=True, text=True, check=False,
                creationflags=subprocess.CREATE_NO_WINDOW
            )

            if result.returncode == 0 and result.stdout.strip():
                gateway_ip = result.stdout.strip()
                self.router_logger.log_message(
                    f"[Router] Discovered gateway for '{iface_friendly_name}': {gateway_ip}")
                return gateway_ip
            else:
                self.router_logger.log_message(
                    f"[Router] Could not discover gateway for '{iface_friendly_name}'. STDOUT: {result.stdout.strip()}, STDERR: {result.stderr.strip()}")
                return None
        except Exception as e:
            self.router_logger.log_message(
                f"[Router] Error discovering gateway for '{iface_friendly_name}': {e}")
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

    def _auto_configure_interfaces(self, use_dhcp_out, use_dhcp_in):
        """
        Automatically finds and configures IN, OUT, and Loopback interfaces.
        Sets their IP addresses dynamically (for IN/OUT) and determines default gateway.
        """
        in_iface_info = None
        out_iface_info = None
        loopback_iface_info = None  # NEW: For loopback interface
        ethernet_2_info = None
        lac_2_info = None
        lac_2_info_2 = None
        self.router_logger.log_message(
            "[Router] Attempting to auto-configure IN, OUT, and Loopback interfaces...")

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
        if(lac_2_info_2):
            self.interface_lac_2_full_name = lac_2_info_2["full_name"]
            self.interface_lac_2_friendly_name = lac_2_info_2["friendly_name"]
        if(lac_2_info):
            self.interface_lac_full_name = lac_2_info['full_name']
            self.interface_lac_friendly_name = lac_2_info['friendly_name']
        if(ethernet_2_info):
            self.interface_ethernet_2_full_name =  ethernet_2_info['full_name']
            self.interface_ethernet_2_friendly_name =  ethernet_2_info['friendly_name']
        self.interface_in_full_name = in_iface_info['full_name']
        self.interface_in_friendly_name = in_iface_info['friendly_name']
        self.interface_out_full_name = out_iface_info['full_name']
        self.interface_out_friendly_name = out_iface_info['friendly_name']
        if loopback_iface_info:  # Assign if found
            self.interface_loopback_full_name = loopback_iface_info['full_name']

        # Step 2: Determine IP configurations for IN and OUT interfaces
        system_active_networks = self._get_system_networks()

        # For OUT interface: use its current IP config as router_ip_out
        current_out_ip = None
        current_out_netmask = None

        for addr in psutil.net_if_addrs().get(self.interface_out_friendly_name, []):
            if addr.family == socket.AF_INET:
                current_out_ip = addr.address
                current_out_netmask = addr.netmask
                break

        self._configure_firewall_rules()  # Configure firewall rules based on discovered OUT interface

        if current_out_ip and current_out_netmask:
            self.router_ip_out = current_out_ip
            self.router_netmask_out = current_out_netmask
            self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}",
                                                           strict=False)
            self.router_logger.log_message(
                f"[Router] Using current IP for OUT interface '{self.interface_out_friendly_name}': {self.router_ip_out}/{self.router_netmask_out}")
        else:
            self.router_logger.log_message(
                f"[Router] WARNING: Could not determine current IP for OUT interface '{self.interface_out_friendly_name}'. Attempting DHCP/dynamic configuration fallback.")
            # Fallback logic if current IP is not found - assign a new private IP or rely on DHCP
            # This is a bit unusual for a production WAN interface but ensures the router has an IP.
            # In a real scenario, you'd likely use DHCP client here or fail.
            unused_out_ip = self._find_unused_private_subnet(system_active_networks)
            if unused_out_ip:
                self.router_ip_out = unused_out_ip
                self.router_netmask_out = "255.255.255.0"
                self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}",
                                                               strict=False)
                self.router_logger.log_message(
                    f"[Router] Dynamically assigned fallback IP for OUT interface '{self.interface_out_friendly_name}': {self.router_ip_out}/{self.router_netmask_out}")
            else:
                self.router_logger.log_message(
                    "[Router] CRITICAL ERROR: Failed to assign any IP to OUT interface. Routing may not work.")
                return False  # Cannot proceed without OUT IP

        # Discover default gateway for the OUT interface (using friendly name)
        self.router_gateway_out_ip = self._get_default_gateway_for_interface(self.interface_out_friendly_name)

        # For IN interface: dynamically find an unused private subnet
        unused_in_ip = self._find_unused_private_subnet(system_active_networks)
        if unused_in_ip:
            self.router_ip_in = unused_in_ip
            self.router_netmask_in = "255.255.255.0"
            self.router_network_in = ipaddress.ip_network(f"{self.router_ip_in}/{self.router_netmask_in}", strict=False)
            self.router_logger.log_message(
                f"[Router] Dynamically assigned IP for IN interface '{self.interface_in_friendly_name}': {self.router_ip_in}/{self.router_netmask_in}")
        else:
            self.router_logger.log_message(
                "[Router] CRITICAL ERROR: Failed to assign IP to IN interface. Routing may not work.")
            return False  # Cannot proceed without IN IP

        # Step 3: Assign IPs to interfaces using OS commands (netsh for Windows)
        self.router_logger.log_message(
            "[Router] Assigning IPs to interfaces via OS commands (Requires Admin). This may cause temporary network disruption.")

        # Assign IN interface IP (using its friendly name for netsh)

        if(not use_dhcp_in):
            if not self._assign_ip_to_interface(self.interface_in_friendly_name, self.router_ip_in, self.router_netmask_in):
                self.router_logger.log_message(
                    f"[Router] CRITICAL ERROR: Failed to assign IP to IN interface. Routing may not work.")
                return False

        # Assign OUT interface IP with its (discovered/fallback) gateway (using its friendly name for netsh)
        if(not use_dhcp_out):
            if not self._assign_ip_to_interface(self.interface_out_friendly_name, self.router_ip_out,
                                                self.router_netmask_out,
                                                self.router_gateway_out_ip):
                self.router_logger.log_message(
                    f"[Router] CRITICAL ERROR: Failed to assign IP to OUT interface. Routing may not work.")
                return False

        # Step 4: Update internal _interfaces_config with assigned IPs and MACs
        # Store configurations by full Scapy name
        self._interfaces_config[self.interface_in_full_name] = {
            'ip_addr': self.router_ip_in,
            'network': self.router_network_in,
            'mac': get_if_hwaddr(self.interface_in_full_name),
            'broadcast': str(self.router_network_in.broadcast_address)
        }
        self._interfaces_config[self.interface_out_full_name] = {
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
                        "ip_addr": eth2_ip,
                        "network": eth2_network,
                        "mac": eth2_mac,
                        "broadcast": str(eth2_network.broadcast_address)
                    }
                else:
                    self._interfaces_config[ethernet_2_info["full_name"]] = {
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
                # Find the IP configuration for the LAC interface
                for addr in psutil.net_if_addrs().get(self.interface_lac_friendly_name, []):
                    if addr.family == socket.AF_INET:
                        lac_ip = addr.address
                        lac_netmask = addr.netmask
                        break

                if lac_ip and lac_netmask:
                    lac_network = ipaddress.ip_network(f"{lac_ip}/{lac_netmask}", strict=False)
                    self._interfaces_config[self.interface_lac_full_name] = {
                        "ip_addr": lac_ip,
                        "network": lac_network,
                        "mac": lac_mac,
                        "broadcast": str(lac_network.broadcast_address)
                    }
                    self.router_logger.log_message(
                        f"[Router] Added LAC interface to config: {self.interface_lac_full_name}, IP: {lac_ip}, MAC: {lac_mac}")
                else:
                    # If no IP is found, add it with a placeholder IP
                    self._interfaces_config[self.interface_lac_full_name] = {
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
                # Use the full name for getting hardware address
                lac_2_mac = get_if_hwaddr(self.interface_lac_2_full_name)
                lac_2_ip = None
                lac_2_netmask = None

                # Find the IP configuration for the second LAC interface using its friendly name
                for addr in psutil.net_if_addrs().get(self.interface_lac_2_friendly_name, []):
                    if addr.family == socket.AF_INET:
                        lac_2_ip = addr.address
                        lac_2_netmask = addr.netmask
                        break  # Stop after finding the first IPv4 address

                # If an IP and netmask were successfully found, calculate network info
                if lac_2_ip and lac_2_netmask:
                    lac_2_network = ipaddress.ip_network(f"{lac_2_ip}/{lac_2_netmask}", strict=False)

                    # Add the interface configuration to your main dictionary
                    self._interfaces_config[self.interface_lac_2_full_name] = {
                        "ip_addr": lac_2_ip,
                        "network": lac_2_network,
                        "mac": lac_2_mac,
                        "broadcast": str(lac_2_network.broadcast_address)
                    }
                    self.router_logger.log_message(
                        f"[Router] Added LAC 2 interface to config: {self.interface_lac_2_full_name}, IP: {lac_2_ip}, MAC: {lac_2_mac}")
                else:
                    # If no IP is found, add it with a placeholder IP
                    self._interfaces_config[self.interface_lac_2_full_name] = {
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
            self.add_trusted_arp_port(self.interface_ethernet_2_full_name)
        if self.interface_lac_full_name:
            self.add_trusted_arp_port(self.interface_lac_full_name)
        if self.interface_lac_2_full_name:
            self.add_trusted_arp_port(self.interface_lac_2_full_name)
        # Example: Add static ARP entry for gateway (if known)
        if self.router_gateway_out_ip:
            try:
                gateway_mac = self.arp_manager.resolve(self.router_gateway_out_ip, self.interface_out_full_name)
                if gateway_mac:
                    self.add_static_arp_entry(self.router_gateway_out_ip, gateway_mac)
                    self.router_logger.log_message(
                        f"[Router][ARP] 📌 Added static ARP entry for gateway {self.router_gateway_out_ip} → {gateway_mac}")
            except Exception as e:
                self.router_logger.log_message(f"[Router][ARP] ⚠️ Failed to resolve gateway MAC: {e}")

        # NEW: Add Loopback interface to config if found
        if self.interface_loopback_full_name:
            # Loopback usually has 127.0.0.1/8. MAC is typically '00:00:00:00:00:00' or similar virtual.
            loopback_ip = "127.0.0.1"
            loopback_netmask = "255.0.0.0"
            loopback_network = ipaddress.ip_network(f"{loopback_ip}/{loopback_netmask}", strict=False)

            # Attempt to get actual loopback MAC, but fall back to dummy if not available
            # Some platforms or virtual envs might not give a real MAC for loopback.
            try:
                loopback_mac = get_if_hwaddr(self.interface_loopback_full_name)
            except Exception:
                loopback_mac = "00:00:00:00:00:00"  # Dummy MAC for loopback

            self._interfaces_config[self.interface_loopback_full_name] = {
                'ip_addr': loopback_ip,
                'network': loopback_network,
                'mac': loopback_mac,
                "broadcast": str(loopback_network.broadcast_address)
            }
            if self.interface_loopback_full_name:
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
        # Get our own MAC addresses (re-get after IP assignment for certainty)
        self.mac_in = get_if_hwaddr(self.interface_in_full_name)
        self.mac_out = get_if_hwaddr(self.interface_out_full_name)
        self.create_link_aggregation_group("MyLANAggregation", link_group)
        conf.route.add(net=str(self.router_network_in), gw=self.router_gateway_out_ip,
                       dev=self.interface_out_friendly_name)
        conf.route.add(
            host="192.168.0.10",
            gw="192.168.0.1",
            dev=self.interface_out_friendly_name  # <-- Use the dynamically found name
        )
        # Do the same for IPv6 if needed
        conf.route6.add(
            dst="2001:db8:cafe:f000::/64",
            dev=self.interface_out_friendly_name  # <-- Use the dynamically found name
        )
        self.router_macs = {cfg.get('mac') for cfg in self._interfaces_config.values() if 'mac' in cfg}

        self.router_logger.log_message(f"\n--- Python Router Configuration Summary (Dynamically Assigned) ---")
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
    def _enable_nat_forwarding(self):
        """
        Enables NAT forwarding by first removing any old NAT instances and then creating a new one.
        This makes the operation idempotent and resilient to crashes.
        """
        if not self.router_network_in:
            self.router_logger.log_message("[NAT Setup] ⚠️ Cannot enable NAT: IN network is not configured.")
            return

        # --- Step 1: Unconditionally clean up any previous NAT rules ---
        # This prevents errors caused by stale configurations from a previous run.
        self._disable_nat_forwarding()

        # --- Step 2: Create the new NAT rule ---
        lan_network_cidr = str(self.router_network_in)
        self.router_logger.log_message(f"[NAT Setup] 🚀 Enabling NAT for network {lan_network_cidr}...")

        ps_command = [
            "powershell.exe",
            "-Command",
            f'New-NetNat -Name "PythonRouterNAT" -InternalIPInterfaceAddressPrefix "{lan_network_cidr}"'
        ]

        try:
            # Run the command. It requires administrator privileges.
            result = subprocess.run(ps_command, capture_output=True, text=True, check=True,
                                    creationflags=subprocess.CREATE_NO_WINDOW)
            self.router_logger.log_message("[NAT Setup] ✅ NAT forwarding enabled successfully.")
            if result.stdout:
                self.router_logger.log_message(f"[NAT Setup] PowerShell output: {result.stdout.strip()}")

        except subprocess.CalledProcessError as e:
            # After the cleanup step, an error here indicates a more serious problem.
            self.router_logger.log_message(f"[NAT Setup] ❌ Failed to enable NAT. Error: {e.stderr.strip()}")
            self.router_logger.log_message(
                "[NAT Setup] ℹ️ Please ensure this script is run with Administrator privileges.")
        except FileNotFoundError:
            self.router_logger.log_message("[NAT Setup] ❌ PowerShell not found. Cannot enable NAT.")
        except Exception as e:
            self.router_logger.log_message(f"[NAT Setup] ❌ An unexpected error occurred while enabling NAT: {e}")
    def _disable_nat_forwarding(self):
        """
        Removes the NAT forwarding rule created by the router.
        """
        self.router_logger.log_message("[NAT Setup] 🧹 Disabling NAT forwarding...")

        # The PowerShell command to remove the NAT rule by the name we gave it.
        # -Confirm:$false prevents it from asking "Are you sure?"
        ps_command = [
            "powershell.exe",
            "-Command",
            'Remove-NetNat -Name "PythonRouterNAT" -Confirm:$false'
        ]

        try:
            subprocess.run(ps_command, capture_output=True, text=True, check=False,
                           # check=False to ignore errors if rule doesn't exist
                           creationflags=subprocess.CREATE_NO_WINDOW)
            self.router_logger.log_message("[NAT Setup] ✅ NAT forwarding rule removed (if it existed).")
        except Exception as e:
            self.router_logger.log_message(f"[NAT Setup] ⚠️ An error occurred while disabling NAT: {e}")

    def add_static_routes_for_all_interfaces(self):
        self.rip_manager.interfaces_config = self._interfaces_config
        for ifname, cfg in self._interfaces_config.items():
            ip_addr = cfg.get("ip_addr")
            net_obj = cfg.get("network")
            if not ip_addr or not net_obj:
                continue
            self.rip_manager.add_static_route(str(net_obj), "0.0.0.0", ifname, cost=1)
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

    def _start_single_sniffer(self, iface_name: str):
        global packet_queue
        """Starts a sniffer thread + processing worker pool for a given interface."""
        RATE_LIMIT_PACKETS_PER = 5  # Can be any float value
        TOKEN_BUCKET = {"tokens": RATE_LIMIT_PACKETS_PER, "last_refill": time.time()}
        TOKEN_BUCKET_LOCK = threading.Lock()

        def refill_tokens():
            with TOKEN_BUCKET_LOCK:
                now = time.time()
                elapsed = now - TOKEN_BUCKET["last_refill"]
                TOKEN_BUCKET["last_refill"] = now

                # Accumulate tokens with float precision
                TOKEN_BUCKET["tokens"] += elapsed * RATE_LIMIT_PACKETS_PER
                # Optional: set a max burst limit (e.g., allow up to 5 tokens max)
                TOKEN_BUCKET["tokens"] = min(TOKEN_BUCKET["tokens"], 5.0)

        def consume_token() -> bool:
            refill_tokens()
            with TOKEN_BUCKET_LOCK:
                if TOKEN_BUCKET["tokens"] >= 1.0:
                    TOKEN_BUCKET["tokens"] -= 1.0
                    return True
                return False

        friendly_name_for_filter = next(
            (item['friendly_name'] for item in self._discovered_tshark_interfaces if item['full_name'] == iface_name),
            'DEFAULT')
        filter_clauses = self.BPF_FILTER_BASE_DEFINITIONS.get(friendly_name_for_filter,
                                                              self.BPF_FILTER_BASE_DEFINITIONS.get("DEFAULT", []))
        filter_str = " or ".join(f"({clause})" for clause in filter_clauses) if filter_clauses else ""

        def sniffer_loop(name=iface_name):
            self.router_logger.log_message(f"[Router] Sniffer thread for {name.split('_')[-1]} starting...")

            try:
                self.sniffer.sniff(
                    iface=name,
                    prn=lambda pkt: safe_enqueue(pkt),
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

        def packet_worker():
            while not self._stop_sniffing_event.is_set():
                try:
                    pkt = packet_queue.get(timeout=1)
                    self._process_packet(pkt, iface_name)
                except queue.Empty:
                    continue  # Normal timeout behavior
                except Exception as e:
                    import traceback
                    tb = traceback.format_exc()
                    self.router_logger.log_message(f"[Worker] ❌ Error processing packet:\n{tb}")

        def safe_enqueue(pkt):
            """
            Safely adds a packet to the queue. If the queue is full,
            it processes all existing packets and sends them back to clear the queue.
            """
            global packet_queue
            try:
                if not pkt.haslayer(Ether):
                    return
                try:
                    pkt_len = len(pkt)
                except Exception:
                    return
                if pkt_len < 14 or pkt_len > 65535:
                    return
                if not consume_token():
                    return
                try:
                    packet_queue.put(pkt, block=False)
                except queue.Full:
                    packet_queue.empty()
            except Exception as e:
                tb = traceback.format_exc()
                self.router_logger.log_message(f"[Sniffer] ❗ Error in safe_enqueue(): {e}\n{tb}")


        sniffer_thread = threading.Thread(target=sniffer_loop, name=f"Sniffer-{iface_name.split('_')[-1]}", daemon=True)

        with self._sniff_threads_lock:
            self._sniff_threads[iface_name] = sniffer_thread
        sniffer_thread.start()


        self._worker_threads[iface_name] = [] # Ensure this list is initialized for this interface
        for i in range(4):
            worker = threading.Thread(target=packet_worker, name=f"Worker-{iface_name}-{i}", daemon=True)
            worker.start()
            self._worker_threads[iface_name].append(worker)

        self.router_logger.log_message(f"[Router] Sniffing + workers started on {iface_name.split('_')[-1]}.")
    def _start_dhcp_servers(self):
        if self.router_network_in:
            dhcp_start_in_ip = str(self.router_network_in.network_address + 100)
            dhcp_end_in_ip = str(self.router_network_in.network_address + 200)
            dhcp_start_out_ip = str(self.router_network_out.network_address + 100)
            dhcp_end_out_ip = str(self.router_network_out.network_address + 200)

            self.dhcp_server_in = DHCPServer(
                self.router_logger,
                self.packet_writer,
                self.interface_in_full_name,
                dhcp_start_in_ip,
                dhcp_end_in_ip,
                self._interfaces_config
            )
            self.dhcp_server_out = DHCPServer(
                self.router_logger,
                self.packet_writer,
                self.interface_out_full_name,
                dhcp_start_out_ip,
                dhcp_end_out_ip,
                self._interfaces_config
            )
            self.arp_manager.set_dhcp_server_reference(self.dhcp_server_in, self.dhcp_server_out)
        else:
            self.router_logger.log_message("[DHCP] DHCP Server not initialized: Router IN network not configured.")
        if self.dhcp_server_in:
            self.dhcp_server_in.start()
        if self.dhcp_server_out:
            self.dhcp_server_out.start()

    def _process_packet(self, packet, inbound_iface: str):
        """
        Main packet processing pipeline with a clear separation for router-destined
        vs. transit traffic.
        """
        try:
            if packet.haslayer(Ether):
                src_mac = packet[Ether].src
                # Create a list of all router MACs dynamically to ensure it's always up to date
                if src_mac.lower() in self.router_macs:
                    self.function_call_tracker.track(
                        identifier='DroppedMacLog',
                        threshold=20,
                        final_message=f"[Router] 👻 Dropping packet from our own MAC ({src_mac}). Count: {{}}.",
                        count_message=None,
                    )
                    return  # Do not process this packet
            try:
                eth_type = packet[Ether].type
            except Exception as e:
                self.router_logger.log_message(f"[Bridge] ⚠️ Failed to extract EtherType: {e}")
                return
            # Step 1: [Layer 2] Handle non-IP packets first (e.g., ARP, L2 frames).
            # The L2 manager returns True if the packet is handled and should not be processed further.
            if self.ethernet_l2_manager.handle_packet(packet, inbound_iface):
                return
            # Step 2: [Layer 3 Check] Get the IP layer. If none exists, drop the packet.
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
            if not ip_layer:
                self.router_logger.log_message(
                    f"[Router] ⚠️ Dropping non-IP packet that bypassed L2 handler: {packet.summary()}")
                return

            dst_ip = ip_layer.dst
            iface_short = inbound_iface.split('_')[-1]
            iface_short = inbound_iface.split('_')[-1]
            if not ip_layer:
                return

            if self.isakmp_manager.handle_packet(packet, inbound_iface):
                return

            is_for_router = dst_ip in self._get_all_local_ips()

            if is_for_router:

                if packet.haslayer(DNS):
                    self.router_logger.log_message(f"[DNS] 🗺️ Intercepting DNS query on {iface_short}")
                    if self.dns_manager.handle_query(packet, inbound_iface, self._interfaces_config,
                                                     self.arp_manager.resolve,
                                                     self.rip_manager.find_route, self.packet_writer,
                                                     self.router_network_in):
                        return

                if packet.haslayer(DHCP) or packet.haslayer(DHCP6):
                    self.router_logger.log_message(f"[DHCP] 📦 DHCP packet detected on {iface_short}")
                    if self.dhcp_server_in and self.dhcp_server_in.handle_packet(packet, inbound_iface,
                                                                                 self.rip_manager.find_route):
                        return
                    if self.dhcp_server_out and self.dhcp_server_out.handle_packet(packet, inbound_iface,
                                                                                   self.rip_manager.find_route):
                        return

                if packet.haslayer(scapy.layers.inet.ICMP) and (packet[ICMP].type == 8):  # Echo Request
                    self.router_logger.log_message(f"[ICMP] 📶 Processing ICMP Echo Request on {iface_short}")
                    if self.icmp_manager.handle_packet(packet, inbound_iface):
                        return
                if packet.haslayer(RIP) or packet.haslayer(RIPEntry):
                    self.router_logger.log_message(f"[RIP] 📘 RIP packet for router detected on {iface_short}")
                    self.rip_manager.handle_packet(packet, inbound_iface)
                    return
            # --- Packet is NOT for the router, so it must be a transit packet. ---

            # Step 2: Perform Layer 3 and above processing for transit traffic.

            if not self.firewall_manager.process_packet(packet):
                self.router_logger.log_message(f"[Firewall] 🔥 Blocked packet on {iface_short}")
                return

            if self.mdns_manager.handle_packet(packet):
                return

            # Transport Layer inspection (for logging only)
            if packet.haslayer(UDP):
                udp = packet[UDP]
                if packet.haslayer(Kerberos) or udp.sport == 88 or udp.dport == 88:
                    if self.kerberos_manager.handle_kerberos_packet(packet, inbound_iface, self._interfaces_config):
                        return

            if packet.haslayer(TCP) and self.stratum_manager.handle_packet(packet, inbound_iface):
                return True  # Handled as Stratum traffic
            self.parallel_python.run_parallel(self.transport_manager.handle_packet, packet, inbound_iface, return_type="all", count_to_call=4)
            if packet.haslayer(DNS) and packet[DNS].qr == 1:
                self.dns_manager.handle_response(packet, self._interfaces_config, self.packet_writer)
                return
            # Handshake tracking for TCP sessions
            if packet.haslayer(TCP):
                self.handshake_manager.handle_packet(packet, inbound_iface)

            if packet.haslayer(TLS):
                if self.https_manager and self.https_manager.handle_packet(packet, inbound_iface):
                    return



            # Firewall check

            # DHCP packets that are not for the router (e.g., DHCP Relay agent)
            if packet.haslayer(DHCP) or packet.haslayer(DHCP6):
                self.router_logger.log_message(f"[DHCP] 📦 DHCP transit packet detected on {iface_short}")
                if self.dhcp_server_in and self.dhcp_server_in.handle_packet(packet, inbound_iface,
                                                                             self.rip_manager.find_route):
                    return
                if self.dhcp_server_out and self.dhcp_server_out.handle_packet(packet, inbound_iface,
                                                                               self.rip_manager.find_route):
                    return





            # Duplicate flow check (rate-limiting)
            proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
            sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(UDP) else 0
            dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(UDP) else 0
            if self.forwarding_manager.is_duplicate(ip_layer.src, ip_layer.dst, sport, dport, proto):
                return
            if dst_ip in self._get_all_local_ips():
                self.function_call_tracker.track(
                    identifier='DroppedDstIPSame',
                    threshold=20,
                    final_message=f"[Router] 🚫 Skipping self-forwarded packet to {dst_ip} (router's own IP).=. Count: {{}}.",
                    count_message=None,
                )
                return
            # Final forwarding logic
            self.router_logger.log_message(
                RouterRandomMessages(
                    name="Router",
                    message=f"Forwarding: {packet.summary()} | In:{iface_short}",
                    emoticons=["🚚", "🚛", "🛻", "🚒", "🚐", "🚙", "🚎", "🚕"]
                )
            )
            self.parallel_python.run_parallel(self._forward_general_ip_packet, packet, inbound_iface,
                                              return_type="void")

        except Exception as e:
            self.router_logger.log_message(
                f"[Router] ❗ ERROR while processing on {inbound_iface.split('_')[-1]}: {e}. Packet: {packet.summary()}")
    def _forward_general_ip_packet(self, packet, inbound_iface: str):
        """Forwards a transit packet, applying NAT, LAG, ARP resolution, and Layer 2 handling."""
  # Prevent loop
        iface_short = inbound_iface.split('_')[-1]
        ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)
        dst_ip = ip_layer.dst

        ip_layer = None
        if packet.haslayer(IP):
            ip_layer = packet[IP]
        elif packet.haslayer(IPv6):
            ip_layer = packet[IPv6]

        if not ip_layer:
            self.router_logger.log_message(f"[Router] ❗ No IP layer found in packet. Dropping.")
            return
        if isinstance(ip_layer, IPv6) and ipaddress.ip_address(dst_ip).is_multicast:
            self.router_logger.log_message(f"[Router] 🚧 Flooding IPv6 multicast packet for {dst_ip} via bridge.")
            # Use the EthernetBridgeManager to handle L2 flooding
            self.ethernet_manager.handle_frame(packet, inbound_iface)
            return # IMPORTANT: Stop further processing to prevent routing attempt

        src_ip = ip_layer.src
        proto = "TCP" if packet.haslayer(TCP) else "UDP" if packet.haslayer(UDP) else "IP"
        sport = packet[TCP].sport if packet.haslayer(TCP) else packet[UDP].sport if packet.haslayer(
            UDP) else 0
        dport = packet[TCP].dport if packet.haslayer(TCP) else packet[UDP].dport if packet.haslayer(
            UDP) else 0

        if self.forwarding_manager.is_duplicate(src_ip, dst_ip, sport, dport, proto):
            return

        # --- [1] Routing Lookup ---
        route = self.rip_manager.find_route(dst_ip)

        if not route:
            self.function_call_tracker.track(
                identifier='DroppedRoute',
                threshold=20,
                final_message=f"[Router] 🛑 No route to {dst_ip}. Dropping. Count: {{}}.",
                count_message=None)
            return
        initial_outbound_iface = route["interface"]
        next_hop_ip = route["next_hop"] if route["next_hop"] != "0.0.0.0" else dst_ip


        if ipaddress.ip_address(dst_ip).is_global:
            selected_iface = None
            if initial_outbound_iface in self.lag_manager.get_lag_members()["MyLANAggregation"]:
                selected_iface = self.lag_manager.get_member_interface("MyLANAggregation", packet)
            else:
                selected_iface = initial_outbound_iface
            if not selected_iface:
                self.router_logger.log_message("[Router] ❌ No outbound interface. Dropping packet.")
                return

            # Attempt normal ARP resolution
            next_hop_mac = self.arp_manager.resolve(dst_ip, iface=selected_iface)

            # Retry with custom ARP request if no MAC
            if not next_hop_mac:
                self.router_logger.log_message(f"[ARP] 💤 Retrying with direct ARP for {dst_ip}")
                next_hop_mac = self.arp_manager.send_custom_arp_request(dst_ip, iface=selected_iface)

                if not next_hop_mac:
                    self.router_logger.log_message(f"[ARP] 🚫 MAC for {dst_ip} not found. Dropping.")
                    if self.arp_manager.notification_manager:
                        event_data = {
                            "event": "MAC Resolution Failure",
                            "message": f"Unable to resolve MAC address for {dst_ip} on {selected_iface.split('_')[-1]}",
                            "iface": selected_iface,
                            "timestamp": time.time(),
                            "emojis": ["🚫", "🧲", "📡"]
                        }
                        self.notification_manager.send_notification(event_data)
                    return

            # Optional: Gratuitous ARP for our translated source IP
            # Perform dynamic NAT: translate src IP and src port
            self.nat_manager.translate_outbound(packet)

            # Gratuitous ARP for the translated public IP (only once per IP/interface ideally)
            translated_ip = self.nat_manager.public_ip
            translated_mac = self.get_interface_mac(selected_iface)
            if translated_ip and translated_mac:
                self.arp_manager.send_gratuitous_arp(translated_ip, translated_mac, selected_iface)

            # Rewrite MACs
            packet[Ether].src = self.get_interface_mac(selected_iface)
            packet[Ether].dst = next_hop_mac


            packet[IP].src = self.nat_manager.public_ip
            del packet[IP].chksum
            if packet.haslayer(TCP):
                del packet[TCP].chksum
            elif packet.haslayer(UDP):
                del packet[UDP].chksum


            # Log and send
            self.router_logger.log_message(
                RouterRandomMessages(
                    name="Router",
                    message=f"Internet-bound packet {dst_ip} to {selected_iface.split('_')[-1]}",
                    emoticons=["👽", "🌍", "🌎", "🌏", "🌠", "🌌", "🪐", "🌗"]
                )
            )
            self.packet_writer.queue_packet(packet, selected_iface)
            return


        # Step 3: [Multicast] Handle multicast traffic as a special case.
        if ipaddress.ip_address(dst_ip).is_multicast:
            if initial_outbound_iface in self.lag_manager.get_lag_members()["MyLANAggregation"]:
                initial_outbound_iface = self.lag_manager.get_member_interface("MyLANAggregation", packet)
            self.router_logger.log_message(f"[IGMP] Received multicast packet for {dst_ip} on {iface_short}.")
            self.igmp_manager.handle_packet(packet, initial_outbound_iface )
            if self.igmp_manager.should_forward_multicast(dst_ip, initial_outbound_iface ):
                self.router_logger.log_message(f"[IGMP] ✅ Forwarding {dst_ip} via L2 bridge.")
                self.ethernet_manager.handle_frame(packet, initial_outbound_iface )
            else:
                self.router_logger.log_message(f"[IGMP] 🚫 Dropping {dst_ip} - no active listeners.")

            return  # Multicast traffic is handled, do not proceed to unicast forwarding.

        is_from_internal_bridge = self.ethernet_manager.is_bridge_member(inbound_iface)
        is_to_external_wan = initial_outbound_iface in self.outbound_load_balancer.get_configured_interfaces()
        if is_from_internal_bridge and is_to_external_wan:
            self.nat_manager.translate_outbound(packet)
            ip_layer = packet.getlayer(IP) or packet.getlayer(IPv6)

        # --- [4] Intra-LAN Loop Prevention ---
        inbound_config = self._interfaces_config.get(inbound_iface)
        inbound_network = inbound_config.get("network") if inbound_config else None
        is_intra_lan = (
                inbound_network and
                ipaddress.ip_address(dst_ip) in inbound_network and
                dst_ip != inbound_config.get("ip_addr")
        )



        if inbound_iface == initial_outbound_iface:
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
                    # Try default route (0.0.0.0/0)
                    default_route = self.rip_manager.find_route("0.0.0.0")
                    if default_route:
                        actual_outbound_iface = default_route["interface"]
                        self.router_logger.log_message(
                            f"[Router] 🚵 No alternate route to {dst_ip}. Using default route via {actual_outbound_iface.split('_')[-1]}"
                        )
                        self.forwarding_manager.record_flow(src_ip, dst_ip, sport, dport, proto)
                        initial_outbound_iface = actual_outbound_iface
                    else:
                        self.router_logger.log_message(
                            f"[Router] ❌ Routing loop on {inbound_iface} and no alternate or default route for {dst_ip}. Dropping.")
                        return
            else:
                self.router_logger.log_message(
                    f"[Router] 🏠 Intra-LAN forwarding: {packet.summary()} | In:{iface_short} -> Out:{iface_short}"
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

            self.router_logger.log_message(
                f"[Router] 🌀 Loopback forwarding for {dst_ip}. No ARP needed."
            )
        elif ipaddress.ip_address(dst_ip) == outbound_network.broadcast_address:
            target_mac = "ff:ff:ff:ff:ff:ff"
            self.router_logger.log_message(f"[Router] 📢 Broadcast forwarding to {target_mac}")
        else:
            target_mac = self.arp_manager.resolve(next_hop_ip, initial_outbound_iface)

        if not target_mac:
            self.router_logger.log_message(
                f"[Router] 🕵️ ARP failed for {next_hop_ip} on {initial_outbound_iface.split('_')[-1]}. Dropping."
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
                self.router_logger.log_message(f"[Router] ⌛ TTL/Hop Limit expired for {dst_ip}. Dropping.")
                return
            if hasattr(ip_layer, "ttl"):
                packet[IP].ttl -= 1
            elif hasattr(ip_layer, "hlim"):
                packet[IPv6].hlim -= 1
        # --- [10] Adjust or Apply Ether Layer ---
        if is_loopback:
            if packet.haslayer(Ether):
                packet = packet.payload  # strip Ethernet layer
        elif packet.haslayer(Ether):
            packet[Ether].src = outbound_config["mac"]
            packet[Ether].dst = target_mac
        else:
            self.router_logger.log_message(
                f"[Router] ⚠️ Packet missing Ether layer for {initial_outbound_iface.split('_')[-1]}. Cannot send."
            )
            return

        # --- [11] Fix Checksums ---
        del ip_layer.chksum
        if packet.haslayer(TCP): del packet[TCP].chksum
        if packet.haslayer(UDP): del packet[UDP].chksum

        # --- [12] Send Packet ---
        self.packet_writer.queue_packet(packet, initial_outbound_iface)
        deterministic_value = abs(hash(str(packet))) / (2 ** 64 - 1)
        sampling_rate = self.packet_catcher_heuristic_rates.get(proto, self.packet_catcher_heuristic_rates['DEFAULT'])
        if deterministic_value < sampling_rate:
            self.parallel_python.run_parallel(self.packet_catcher.process_packet, packet, return_type="all", count_to_call=10)
        self.router_logger.log_message(
            f"[Router] 📤 Packet queued to {initial_outbound_iface.split('_')[-1]}"
        )


    def start_routing(self, use_dhcp_out, use_dhcp_in):
        """Configures interfaces and starts all manager threads."""
        try:
            try:
                self._initialize_interface_discovery()
                if not self._auto_configure_interfaces(use_dhcp_out, use_dhcp_in):
                    self.router_logger.log_message("[Router] ❌ Failed to auto-configure interfaces.")
            except Exception as e:
                self.router_logger.log_message(f"[Router] ❌ Crash in start_routing: {e}")


            self._enable_nat_forwarding()
            self.nat_manager = NATManager(self.router_logger, self.sendback_manager, self.router_ip_out, self.packet_writer, self._interfaces_config, self.rip_manager.find_route, self.arp_manager.resolve, self.function_call_tracker)


            self.notification_manager = NotificationManager(
                self.router_logger,
                self.NOTIFICATION_TARGET_IP,
                self.NOTIFICATION_TARGET_PORT,
                self.interface_in_full_name
            )

            self.isakmp_manager = ISAKMPManager(self.router_logger, self.packet_writer, self.notification_manager, self._interfaces_config)
            self.packet_catcher.notification_manager = self.notification_manager
            self.arp_manager.notification_manager = self.notification_manager
            self.packet_signer.notification_manager = self.notification_manager
            self.sniffer = SnifferSoftware(self.arp_manager, self.rip_manager, self.notification_manager, self.router_logger)

            self.rip_manager.initialize_routes(self._interfaces_config, self.router_gateway_out_ip,
                                               self.interface_out_full_name)
            self.add_static_routes_for_all_interfaces()

            google_dns_route_network = ipaddress.ip_network("8.8.8.8/32")

            current_route_details = self.rip_manager.find_route("8.8.8.8")
            if not current_route_details or current_route_details.get("type") != "static":
                self.router_logger.log_message("[Router] Adding/Updating static route for 8.8.8.8/32.")

                self.rip_manager.add_static_route(
                    network_str=str(google_dns_route_network),
                    next_hop=self.router_gateway_out_ip,
                    interface=self.interface_out_full_name,
                    cost=1
                )
                loopback_network = ipaddress.IPv6Network("::1/128")

                self.rip_manager.add_static_route(
                    network_str=str(loopback_network),
                    next_hop="::1",
                    interface=self.interface_in_full_name,  # fallback to your IN interface
                    cost=2
                )
            else:
                self.router_logger.log_message("[Router] Static route for 8.8.8.8/32 already exists.")

            self.handshake_manager = HandshakeManager(self.router_logger, self.arp_manager, self.nat_manager,
                                                      self.rip_manager)

            self.router_logger.log_message("\n--- Python Router Starting Services ---")
            self._stop_sniffing_event.clear()
            self.syn_scanner = SYNScanner(
                router_logger=self.router_logger,
                packet_writer=self.packet_writer,
                interfaces_config=self._interfaces_config,
                notification_manager=self.notification_manager,
                arp_manager=self.arp_manager,
                scan_targets=[
                    ("8.8.8.8", [53, 80]),
                    ("1.1.1.1", [443]),
                ],scan_interval=300)
            self._inject_dependencies()
            self.syn_scanner.start()
            self.rip_manager.start()
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
            sniffer_tasks = []

            for iface_name in self._interfaces_config.keys():
                sniffer_tasks.append((self._start_single_sniffer, (iface_name,)))

            self.parallel_python.run_all_parallel(sniffer_tasks, return_type="void")
        except Exception as e:
            self.router_logger.log_message(f"[Router] Error shutting down {e}")
    def stop_routing(self):
        """Stops all manager threads and cleans up network interfaces."""
        try:
            self.router_logger.log_message("[Router] --- Python Router Stopping Services ---")
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
            self.router_logger.log_message("[Router] Waiting for worker threads to finish...")
            self.router_logger.log_message("[Router] Worker threads stopped.")
            for iface_workers_list in getattr(self, "_worker_threads", {}).values():
                for worker in iface_workers_list:
                    if worker.is_alive():
                        worker.join(timeout=2)  # Give a short timeout
            self._worker_threads.clear()
            self.router_logger.log_message("[Router] Worker threads stopped.")
            # 5. Join sniffer threads (these should have died or be dying from _stop_sniffing_event)
            self.router_logger.log_message("[Router] Waiting for sniffer threads to finish...")
            # Access _sniff_threads with lock, as monitor might be trying to remove/add.
            with self._sniff_threads_lock:
                # Take a snapshot of current threads to avoid RuntimeError from dict changes during iteration
                # while a thread is joining.
                active_sniffers_snapshot = list(self._sniff_threads.values())
                for thread in active_sniffers_snapshot:
                    if thread.is_alive():
                        thread.join(timeout=2)
                self._sniff_threads.clear() # Clear out any remaining references after joining
            self.router_logger.log_message("[Router] Sniffer threads stopped.")
            self._worker_threads.clear()
            self._sniff_threads.clear()
            self.igmp_manager.stop()
            self.handshake_manager.stop()
            self.remove_l2_bridge("MyLANBridge")
            self.remove_link_aggregation_group("MyLANAggregation")
            self.remove_outbound_load_balancing_interface(self.interface_ethernet_2_full_name)
            self.remove_outbound_load_balancing_interface(self.interface_out_full_name)
            self.syn_scanner.stop()
            self.cleanup_all_network_changes()
            self.router_logger.log_message("[Router] All services stopped.")
        except Exception as e:
            self.router_logger.log_message(f"[Router] Error shutting down {e}")

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
        """Returns a set of all IPs assigned to the router’s interfaces."""
        return {
            config["ip_addr"]
            for config in self._interfaces_config.values()
            if "ip_addr" in config
        }
    def get_interface_mac(self, iface_full_name: str) -> str | None:
        """
        Returns the MAC address of a given interface using Scapy's get_if_hwaddr().
        Args:
            iface_full_name (str): The full Scapy name of the interface.
        Returns:
            str | None: The MAC address if found, else None.
        """
        try:
            mac = get_if_hwaddr(iface_full_name)
            if mac and mac.lower() != "00:00:00:00:00:00":
                return mac
            else:
                self.router_logger.log_message(
                    f"[Router] ⚠️ MAC address for '{iface_full_name}' appears invalid: {mac}")
                return None
        except Exception as e:
            self.router_logger.log_message(f"[Router] ❌ Failed to get MAC for '{iface_full_name}': {e}")
            return None
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
    def add_static_route(self, network_str: str, next_hop: str, interface_full_name: str, cost: int = 1) -> bool:
        """
        Adds a static route to the router's routing table.
        Args:
            network_str (str): CIDR notation for the destination network (e.g., "192.168.1.0/24").
            next_hop (str): The IP address of the next hop router, or "0.0.0.0" for direct delivery.
            interface_full_name (str): The full Scapy name of the outbound interface for this route.
            cost (int): The metric/cost of this route (1-15 valid, 16 = infinity).
        Returns True if added/updated, False otherwise.
        """
        return self.rip_manager.add_static_route(network_str, next_hop, interface_full_name, cost)

    def remove_static_route(self, network_str: str) -> bool:
        """
        Removes a static route from the router's routing table.
        Returns True if removed, False otherwise.
        """
        return self.rip_manager.remove_static_route(network_str)

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

            response = sr1(packet, timeout=timeout, verbose=0)

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

    def start_capture(self, main_interface_name: str = 'Wi-Fi', promiscuous=True):
        self._initialize_geoip()
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

        base_command = [
            tshark_path, '-l',
            '-T', 'json',
            '-V',
            '-o', 'tcp.desegment_tcp_streams:TRUE'
        ]
        if not promiscuous:
            base_command.append('-p')
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

    def _process_packet(self, packet_data: dict | str, interface_id: str) -> None:
        """Parse a JSON packet dict, enrich it, and push to logger / callback."""
        if not isinstance(packet_data, dict):
            return  # ignore non‑JSON / malformed

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
            # This filtering logic is now always active within _process_packet.

            # Check for IPv4 multicast/broadcast or IPv6 multicast
            try:
                dst_ip_obj = ipaddress.ip_address(dst_ip)

                # Check for IPv4 broadcast address (255.255.255.255)
                if isinstance(dst_ip_obj, ipaddress.IPv4Address) and dst_ip_obj == ipaddress.IPv4Address(
                        '255.255.255.255'):
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering IPv4 Broadcast packet to {dst_ip} on interface {interface_id}.")
                    return  # Filter this packet

                # Filter common multicast addresses and general link-local multicast/broadcast.
                if dst_ip_obj.is_multicast:
                    # Specific common multicast ranges/addresses for discovery protocols (MDNS, SSDP, etc.)
                    if (isinstance(dst_ip_obj, ipaddress.IPv4Address) and (
                            dst_ip_obj in ipaddress.IPv4Network('224.0.0.0/24') or  # Link-local multicast, MDNS
                            dst_ip_obj in ipaddress.IPv4Network('239.255.255.0/24')  # Some SSDP/UPnP
                    )) or \
                            (isinstance(dst_ip_obj, ipaddress.IPv6Address) and (
                                    dst_ip_obj in ipaddress.IPv6Network('ff02::/16')  # Link-local multicast IPv6
                            )) or \
                            dst_ip == "239.255.255.250":  # SSDP specific IPv4 multicast
                        self.logger.log_message(
                            f"[Wireshark Filter] Filtering Multicast/Discovery packet to {dst_ip} on interface {interface_id}.")
                        return  # Filter this packet
            except ValueError:
                pass  # Not a valid IP, so can't check for multicast/broadcast

            # Check for common discovery/idle protocol ports (UDP/TCP)
            # Expanded list of common noisy ports
            common_noisy_ports = [
                "5353",  # MDNS
                "1900",  # SSDP
                "137",  # NetBIOS Name Service (UDP)
                "138",  # NetBIOS Datagram Service (UDP)
                "139",  # NetBIOS Session Service (TCP)
                "445",  # SMB over TCP (can be noisy on local networks)
                "520",  # RIP (Routing Information Protocol)
                "161",  # SNMP (Simple Network Management Protocol)
                "162",  # SNMP Trap
                "67",  # DHCP Server (BOOTP Server)
                "68",  # DHCP Client (BOOTP Client)
                "546",  # DHCPv6 Client
                "547",  # DHCPv6 Server
                "5678",  # UPnP (some implementations)
                "5679",  # UPnP (some implementations)
                "3702",  # WS-Discovery (Web Services Dynamic Discovery)
                "5355"  # LLMNR (Link-Local Multicast Name Resolution)
            ]

            # Convert ports to integers for direct comparison if needed, but tshark output is string
            # So keep as strings for comparison with dictionary values.

            if "udp" in layers:
                udp_layer = layers["udp"]
                dst_port = udp_layer.get("udp.dstport", "N/A")
                src_port = udp_layer.get("udp.srcport", "N/A")
                if dst_port in common_noisy_ports or src_port in common_noisy_ports:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering Discovery/Idle UDP packet on port {dst_port} from {src_ip} to {dst_ip} on interface {interface_id}.")
                    return  # Filter this packet

            if "tcp" in layers:
                tcp_layer = layers["tcp"]
                dst_port = tcp_layer.get("tcp.dstport", "N/A")
                src_port = tcp_layer.get("tcp.srcport", "N/A")
                if dst_port in common_noisy_ports or src_port in common_noisy_ports:
                    self.logger.log_message(
                        f"[Wireshark Filter] Filtering Discovery/Idle TCP packet on port {dst_port} from {src_ip} to {dst_ip} on interface {interface_id}.")
                    return  # Filter this packet

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
                context_tags.append("via‑VPN‑out")

            # 2) Traffic already on VPN adapter
            if interface_id == self.vpn_interface_id:
                if _is_private(src_ip) and not _is_private(dst_ip):
                    context_tags.append("VPN→WAN")  # egress after encryption
                elif not _is_private(src_ip) and _is_private(dst_ip):
                    context_tags.append("WAN→VPN")  # ingress before decryption
                else:
                    context_tags.append("VPN‑internal")

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
            #              Application‑layer quick peeks
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
            #           Optional reassembled payload preview (TCP)
            # ----------------------------------------------------------
            raw_payload_hex_str = None
            if tcp_layer and tcp_layer.get("tcp.payload"):
                raw_payload_hex_str = tcp_layer["tcp.payload"].replace(":", "")
            elif "data-text-lines" in layers:
                # TShark sometimes puts reassembled data here, might not be hex string
                reassembled = layers["data-text-lines"]
                if isinstance(reassembled, list): # data-text-lines can be an array of lines
                    reassembled = "\n".join(reassembled)

                # Attempt to convert to bytes if it's not already binary and get hex
                try:
                    raw_payload_hex_str = reassembled.encode('utf-8', errors='ignore').hex()
                except Exception:
                    raw_payload_hex_str = None # Couldn't convert to hex from this source

            if raw_payload_hex_str:
                # Truncate raw hex for logging
                truncated_hex_display = raw_payload_hex_str[:128] + ("..." if len(raw_payload_hex_str) > 128 else "")
                self.logger.log_message(f"[Payload-Wireshark] 📦 Raw payload (hex): {truncated_hex_display}...")

                # Attempt to decode to human-readable string
                try:
                    # Convert hex string to bytes, then decode
                    payload_bytes = bytes.fromhex(raw_payload_hex_str)
                    decoded_payload = payload_bytes.decode('utf-8', errors='replace')

                    # Heuristic for human-readability (same as in TransportLayerManager)
                    replacement_char_count = decoded_payload.count('\ufffd')
                    printable_char_count = sum(1 for char in decoded_payload if char in string.printable)

                    is_human_readable = True
                    if len(decoded_payload) > 0:
                        if replacement_char_count / len(decoded_payload) > 0.10:
                            is_human_readable = False
                        elif printable_char_count / len(decoded_payload) < 0.50:
                            is_human_readable = False
                    elif len(payload_bytes) > 0: # If decoded_payload is empty but payload has content, it's not readable
                        is_human_readable = False

                    if is_human_readable and len(decoded_payload.strip()) > 0:
                        self.logger.log_message(f"[Payload-Wireshark] 📝 Decoded payload: {decoded_payload}")
                    else:
                        self.logger.log_message("[Payload-Wireshark] ⚠️ Decoded payload not considered human-readable.")

                except UnicodeDecodeError: # Less likely with errors='replace', but good to catch
                    self.logger.log_message("[Payload-Wireshark] ⚠️ Could not decode payload as UTF-8.")
                except Exception as e:
                    self.logger.log_message(f"[Payload-Wireshark] ❌ Error processing/decoding payload: {e}")
            else:
                self.logger.log_message(f"[Payload-Wireshark] 📦 No reassembled payload data found.")

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
