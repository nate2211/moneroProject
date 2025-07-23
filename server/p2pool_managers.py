from pathlib import Path
from socket import AF_INET

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
from scapy.all import send, sr1, conf, get_if_list
from scapy.arch import get_if_hwaddr
from scapy.layers.dns import DNSQR, DNS
from scapy.layers.inet import TCP, IP, ICMP, UDP
from scapy.layers.l2 import ARP, Ether
from scapy.sendrecv import srp, sendp, sniff
from scapy.packet import Packet, bind_layers
from scapy.fields import ByteField, ShortField, IntField, IPField, PacketListField
from scapy.layers.inet import IP, UDP        # (already imported elsewhere, keep only one copy)
class RIPEntry(Packet):
    name = "RIPEntry"
    fields_desc = [
        ShortField("addr_family", 2),          # IPv4
        ShortField("route_tag",   0),
        IPField  ("address",     "0.0.0.0"),   # Network address
        IPField  ("subnet_mask", "0.0.0.0"),
        IPField  ("next_hop",    "0.0.0.0"),
        IntField ("metric",      1)            # 1–15 valid, 16 = infinity
    ]

class SimpleRIP(Packet):
    name = "SimpleRIP"
    fields_desc = [
        ByteField ("command", 2),              # 1 = request, 2 = response
        ByteField ("version", 2),              # RIPv2
        ShortField("unused",  0),
        PacketListField("entries", [], RIPEntry)
    ]

# Bind to UDP/520 so Scapy can dissect/construct automatically
bind_layers(UDP, SimpleRIP, dport=520)
bind_layers(UDP, SimpleRIP, sport=520)

class PythonRouterManager:
    """
    Manages sniffing packets on multiple interfaces and routing them
    based on a simplified routing table. Self-contained for interface discovery and IP assignment.
    """

    # --- Configuration Defaults (used if dynamic assignment fails or as starting points) ---
    DEFAULT_IN_IFACE_FRIENDLY_NAME = "Ethernet"
    DEFAULT_OUT_IFACE_FRIENDLY_NAME = "Wi-Fi"

    # Default private IP ranges to try for the IN interface if auto-picking
    PRIVATE_SUBNETS_TO_TRY = [
        "192.168.100.0/24", "192.168.101.0/24", "192.168.102.0/24", "192.168.103.0/24",
        "10.0.10.0/24", "10.0.11.0/24", "10.0.12.0/24",
        "172.16.10.0/24", "172.16.11.0/24", "172.16.12.0/24"
    ]

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self._interfaces_config = {}

        self.interface_in_full_name = None  # Stores \Device\NPF_{GUID} for Scapy
        self.interface_in_friendly_name = None  # Stores "Ethernet" for netsh
        self.interface_out_full_name = None  # Stores \Device\NPF_{GUID} for Scapy
        self.interface_out_friendly_name = None  # Stores "Wi-Fi" for netsh

        self.mac_in = None
        self.mac_out = None
        self.router_ip_in = None
        self.router_netmask_in = None
        self.router_network_in = None
        self.router_ip_out = None
        self.router_netmask_out = None
        self.router_network_out = None
        self.router_gateway_out_ip = None

        self._sniff_threads = {}
        self._stop_sniffing_event = threading.Event()
        self._arp_cache = {}
        self._arp_cache_lock = threading.Lock()

        self._tshark_path = None
        self._discovered_tshark_interfaces = []


        self.RIP_PORT                = 520
        self.RIP_MCAST_ADDR          = "224.0.0.9"    # std. RIPv2
        self.RIP_UPDATE_INTERVAL     = 10             # seconds
        self._routing_table          = {}             # {IPv4Network: {...}}
        self._rt_lock                = threading.Lock()
        self._rip_stop_event         = threading.Event()
        self._rip_thread             = None

        # --- NAT Attributes (NEW) ---
        self.NAT_PORT_MIN = 49152  # Recommended ephemeral port start
        self.NAT_PORT_MAX = 65535  # Max TCP/UDP port
        self._nat_table = {}  # Maps (internal_ip, internal_port) -> external_port
        self._nat_reverse_table = {} # Maps external_port -> (internal_ip, internal_port)
        self._nat_lock = threading.Lock()
        self._next_nat_port = self.NAT_PORT_MIN

        self.router_logger.log_message("[RouterManager] Initializing Python Router Manager (self-contained).")


    def _get_tshark_path(self) -> str | None:
        """Discover the path to tshark.exe (copied from your WiresharkManager)."""
        if getattr(sys, "frozen", False):
            tshark_exe = Path(sys._MEIPASS) / "Wireshark" / "tshark.exe"
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

        self.router_logger.log_message(
            "[RouterManager] Error: tshark.exe not found. Cannot discover interfaces via tshark -D.")
        return None

    def _initialize_routing_table(self):
        """Seed the table with directly connected nets + default route."""
        with self._rt_lock:
            self._routing_table.clear()
            # directly connected
            for ifname, cfg in self._interfaces_config.items():
                net = cfg["network"]
                self._routing_table[net] = {
                    "next_hop": str(cfg["ip_addr"]),
                    "cost": 1,
                    "interface": ifname,
                    "advertised_by": "self",
                    "last_update": time.time(),
                }
            # default route (if WAN gw known)
            if self.router_gateway_out_ip and self.interface_out_full_name:
                default_net = ipaddress.ip_network("0.0.0.0/0")
                self._routing_table[default_net] = {
                    "next_hop": self.router_gateway_out_ip,
                    "cost": 1,
                    "interface": self.interface_out_full_name,
                    "advertised_by": "self",
                    "last_update": time.time(),
                }

    def _get_next_nat_port(self) -> int:
        """
        Allocates the next available port for a new NAT entry.
        NOTE: Must be called inside self._nat_lock.
        """
        # A more robust implementation would check for port collisions,
        # but for this simulation, a simple increment-and-wrap is sufficient.
        port = self._next_nat_port
        self._next_nat_port += 1
        if self._next_nat_port > self.NAT_PORT_MAX:
            self._next_nat_port = self.NAT_PORT_MIN
        return port

    def _un_nat_and_forward(self, packet, original_client_info):
        """
        Handles an incoming packet from the WAN that matches a NAT entry.
        It translates the packet back to its original destination and forwards it.
        """
        original_ip, original_port = original_client_info
        ip_layer = packet.getlayer(IP)
        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)

        self.router_logger.log_message(
            f"[NAT] ⬅️  Return packet for {original_ip}:{original_port} (from {ip_layer.src}:{transport_layer.sport})")

        # --- Modify Packet (Reverse NAT) ---
        ip_layer.dst = original_ip
        transport_layer.dport = original_port

        # --- Forward to Internal Client ---
        # The modified packet is now treated like any other packet needing forwarding.
        self._forward_general_ip_packet(packet, self.interface_out_full_name)

    def _send_rip_advertisement(self):
        with self._rt_lock:
            table_snapshot = list(self._routing_table.items())

        for ifname, cfg in self._interfaces_config.items():
            if cfg["ip_addr"] is None:  # skip un‑IPed
                continue

            entries = []
            for net, det in table_snapshot:
                # Split‑horizon with poison reverse
                metric = 16 if det["interface"] == ifname and det["advertised_by"] != "self" else det["cost"]
                entries.append(
                    RIPEntry(address=str(net.network_address),
                             subnet_mask=str(net.netmask),
                             metric=metric)
                )

            if not entries:
                continue

            pkt = (
                    IP(src=cfg["ip_addr"], dst=self.RIP_MCAST_ADDR) /
                    UDP(sport=self.RIP_PORT, dport=self.RIP_PORT) /
                    SimpleRIP(command=2, version=2, entries=entries)
            )
            try:
                sendp(pkt, iface=ifname, verbose=0)
                self.router_logger.log_message(
                    f"[RIP] ⬆  advertised {len(entries)} routes on {ifname}"
                )
            except Exception as e:
                self.router_logger.log_message(f"[RIP] send failed on {ifname}: {e}")
    def _rip_advertisement_loop(self):
        while not self._rip_stop_event.is_set():
            self._send_rip_advertisement()
            self._rip_stop_event.wait(self.RIP_UPDATE_INTERVAL)
        self.router_logger.log_message("[RIP] advertisement thread exit.")

    def _handle_rip_update(self, pkt, inbound_ifname):
        rip = pkt.getlayer(SimpleRIP)
        if rip.command != 2:               # only RESPONSES
            return
        src_router = pkt[IP].src
        changed = False

        with self._rt_lock:
            for entry in rip.entries:
                net  = ipaddress.ip_network(f"{entry.address}/{entry.subnet_mask}", strict=False)
                cost = min(entry.metric + 1, 16)    # hop through src_router
                cur  = self._routing_table.get(net)

                if cur is None and cost < 16:
                    self._routing_table[net] = {
                        "next_hop"     : src_router,
                        "cost"         : cost,
                        "interface"    : inbound_ifname,
                        "advertised_by": src_router,
                        "last_update"  : time.time(),
                    }
                    changed = True
                elif cur and cur["advertised_by"] == src_router:
                    if cost != cur["cost"]:
                        cur["cost"] = cost
                        cur["last_update"] = time.time()
                        changed = True
                elif cur and cost < cur["cost"]:
                    # better path from different neighbor
                    self._routing_table[net] = {
                        "next_hop"     : src_router,
                        "cost"         : cost,
                        "interface"    : inbound_ifname,
                        "advertised_by": src_router,
                        "last_update"  : time.time(),
                    }
                    changed = True

        if changed:
            self.router_logger.log_message(f"[RIP] table updated from {src_router}")
    def _initialize_interface_discovery(self):
        """Discover network interfaces using tshark -D and store them internally."""
        self._tshark_path = self._get_tshark_path()
        if not self._tshark_path:
            self.router_logger.log_message("[RouterManager] Cannot perform interface discovery: tshark not found.")
            return

        self.router_logger.log_message("[RouterManager] Discovering network interfaces via tshark -D...")
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
                f"[RouterManager] Discovered {len(self._discovered_tshark_interfaces)} interfaces via tshark.")
        except Exception as e:
            self.router_logger.log_message(f"[RouterManager] Error during tshark interface discovery: {e}")

    def _execute_netsh(self, full_netsh_command_args: list[str]) -> bool:
        """
        Helper to run netsh commands.
        Takes the full list of arguments *after* 'netsh interface ipv4'.
        """
        full_command = ["netsh", "interface", "ipv4"] + full_netsh_command_args
        try:
            self.router_logger.log_message(f"[Netsh] Executing: {' '.join(full_command)}")
            result = subprocess.run(
                full_command, capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            if result.stdout: self.router_logger.log_message(f"[Netsh] STDOUT: {result.stdout.strip()}")
            return True
        except subprocess.CalledProcessError as e:
            self.router_logger.log_message(f"[Netsh] ERROR executing netsh (Return Code: {e.returncode}):")
            if e.stdout: self.router_logger.log_message(f"[Netsh] STDOUT: {e.stdout.strip()}")
            if e.stderr: self.router_logger.log_message(f"[Netsh] STDERR: {e.stderr.strip()}")
            self.router_logger.log_message(f"[Netsh] Command was: {' '.join(full_command)}")
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
            f"[RouterManager] Assigning IP {ip_address}/{netmask} to '{iface_friendly_name}'...")

        # Build the netsh command arguments in the correct order for 'set address'
        # Crucial: Add 'source=static', 'address=', and 'mask=' tags
        netsh_args = [
            "set", "address",
            f'name={iface_friendly_name}',
            "source=static",
            f"address={ip_address}",  # ADDED 'address=' tag
            f"mask={netmask}"  # ADDED 'mask=' tag
        ]

        if gateway:
            netsh_args.append(f"gateway={gateway}")
            netsh_args.append("gwmetric=1")  # Metric
        else:
            netsh_args.append("gateway=none")

        # Call _execute_netsh with the fully constructed arguments
        if not self._execute_netsh(netsh_args):
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Failed to assign IP {ip_address} to '{iface_friendly_name}'.")
            return False
        self.router_logger.log_message(
            f"[RouterManager] Successfully assigned IP {ip_address} to '{iface_friendly_name}'.")
        return True

    def _get_system_networks(self) -> list[ipaddress.IPv4Network]:
        """Gets all currently active IPv4 networks on the system using psutil."""
        active_networks = []
        try:
            for iface_name, addrs in psutil.net_if_addrs().items():
                for addr in addrs:
                    if addr.family == AF_INET and addr.address and addr.netmask:
                        try:
                            network_obj = ipaddress.ip_network(f"{addr.address}/{addr.netmask}", strict=False)
                            active_networks.append(network_obj)
                        except (ValueError, ipaddress.AddressValueError, ipaddress.NetmaskValueError) as e:
                            self.router_logger.log_message(
                                f"[RouterManager] Warning: Could not parse network {addr.address}/{addr.netmask}: {e}")
        except Exception as e:
            self.router_logger.log_message(f"[RouterManager] Error getting system networks via psutil: {e}")
        return active_networks

    def _find_unused_private_subnet(self, existing_networks: list[ipaddress.IPv4Network],
                                    subnet_size: int = 24) -> str | None:
        """
        Finds the first available /24 private subnet from a predefined list that
        does not conflict with existing_networks.
        Returns IP address (e.g., '192.168.X.1') from the first available subnet.
        """
        self.router_logger.log_message("[RouterManager] Searching for an unused private subnet for IN interface...")
        for potential_network_str in self.PRIVATE_SUBNETS_TO_TRY:
            try:
                potential_network = ipaddress.ip_network(potential_network_str, strict=False)

                conflicts = False
                for existing_net in existing_networks:
                    if potential_network.overlaps(existing_net):
                        self.router_logger.log_message(
                            f"[RouterManager] Subnet {potential_network} conflicts with {existing_net}. Skipping.")
                        conflicts = True
                        break

                if not conflicts:
                    router_ip = str(potential_network.network_address + 1)
                    self.router_logger.log_message(
                        f"[RouterManager] Found unused subnet: {potential_network}. Router IN IP: {router_ip}")
                    return router_ip
            except ValueError as e:
                self.router_logger.log_message(
                    f"[RouterManager] Invalid potential subnet '{potential_network_str}': {e}")

        self.router_logger.log_message("[RouterManager] ERROR: No unused private subnet found from predefined list.")
        return None

    def _get_default_gateway_for_interface(self, iface_friendly_name: str) -> str | None:
        """
        Attempts to get the default gateway IP for a specific interface using PowerShell.
        (Windows specific: uses Get-NetRoute and Get-NetAdapter)
        """
        self.router_logger.log_message(f"[RouterManager] Discovering default gateway for '{iface_friendly_name}'...")
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
                    f"[RouterManager] Discovered gateway for '{iface_friendly_name}': {gateway_ip}")
                return gateway_ip
            else:
                self.router_logger.log_message(
                    f"[RouterManager] Could not discover gateway for '{iface_friendly_name}'. STDOUT: {result.stdout.strip()}, STDERR: {result.stderr.strip()}")
                return None
        except Exception as e:
            self.router_logger.log_message(
                f"[RouterManager] Error discovering gateway for '{iface_friendly_name}': {e}")
            return None

    def _auto_configure_interfaces(self):
        """
        Automatically finds and configures IN and OUT interfaces.
        Sets their IP addresses dynamically and determines default gateway.
        """
        in_iface_info = None  # Initialize
        out_iface_info = None  # Initialize

        self.router_logger.log_message("[RouterManager] Attempting to auto-configure IN and OUT interfaces...")

        for iface_info in self._discovered_tshark_interfaces:
            # Check for IN interface
            # Corrected: Use `is None` for explicit check against previous assignment
            if self.DEFAULT_IN_IFACE_FRIENDLY_NAME.lower() in iface_info[
                'friendly_name'].lower() and in_iface_info is None:
                in_iface_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found IN interface: {self.DEFAULT_IN_IFACE_FRIENDLY_NAME} as {in_iface_info['full_name']}")

            # Check for OUT interface
            # Corrected: Use `is None` for explicit check against previous assignment
            if self.DEFAULT_OUT_IFACE_FRIENDLY_NAME.lower() in iface_info[
                'friendly_name'].lower() and out_iface_info is None:
                out_iface_info = iface_info
                self.router_logger.log_message(
                    f"[RouterManager] Found OUT interface: {self.DEFAULT_OUT_IFACE_FRIENDLY_NAME} as {out_iface_info['full_name']}")

            if in_iface_info is not None and out_iface_info is not None:
                break  # Both found, exit loop

        # IMPORTANT: If either interface was not found, exit *before* trying to use them.
        if in_iface_info is None or out_iface_info is None:
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Could not auto-configure required interfaces ('{self.DEFAULT_IN_IFACE_FRIENDLY_NAME}' and '{self.DEFAULT_OUT_IFACE_FRIENDLY_NAME}').")
            self.router_logger.log_message(
                f"[RouterManager] Please check interface names and ensure they are active. Available: {[i['friendly_name'] for i in self._discovered_tshark_interfaces]}")

            # Set internal attributes to None to reflect failure
            self.interface_in_full_name = None
            self.interface_out_full_name = None
            self.interface_in_friendly_name = None
            self.interface_out_friendly_name = None
            self.mac_in = None
            self.mac_out = None
            return False  # Exit early

        # Assign full and friendly names to instance attributes (only if both were found)
        self.interface_in_full_name = in_iface_info['full_name']
        self.interface_in_friendly_name = in_iface_info['friendly_name']
        self.interface_out_full_name = out_iface_info['full_name']
        self.interface_out_friendly_name = out_iface_info['friendly_name']

        # Step 2: Determine IP configurations for IN and OUT interfaces
        system_active_networks = self._get_system_networks()

        # For OUT interface: use its current IP config as router_ip_out
        current_out_ip = None
        current_out_netmask = None

        try:
            # Use the already resolved friendly name: self.interface_out_friendly_name
            for addr in psutil.net_if_addrs().get(self.interface_out_friendly_name, []):
                if addr.family == AF_INET:
                    current_out_ip = addr.address
                    current_out_netmask = addr.netmask
                    break

            if current_out_ip and current_out_netmask:
                self.router_ip_out = current_out_ip
                self.router_netmask_out = current_out_netmask
                self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}",
                                                               strict=False)
                self.router_logger.log_message(
                    f"[RouterManager] Using current IP for OUT interface '{self.interface_out_friendly_name}': {self.router_ip_out}/{self.router_netmask_out}")
            else:
                self.router_logger.log_message(
                    f"[RouterManager] Warning: Could not get current IP for OUT interface via psutil. Falling back to default config.")
                self.router_ip_out = self.ROUTER_IP_OUT
                self.router_netmask_out = self.ROUTER_NETMASK_OUT
                self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}",
                                                               strict=False)

        except Exception as e:
            self.router_logger.log_message(
                f"[RouterManager] Error getting current IP for OUT interface: {e}. Falling back to default.")
            self.router_ip_out = self.ROUTER_IP_OUT
            self.router_netmask_out = self.ROUTER_NETMASK_OUT
            self.router_network_out = ipaddress.ip_network(f"{self.router_ip_out}/{self.router_netmask_out}",
                                                           strict=False)

        # Discover default gateway for the OUT interface (using friendly name)
        self.router_gateway_out_ip = self._get_default_gateway_for_interface(self.interface_out_friendly_name)
        if not self.router_gateway_out_ip:
            self.router_logger.log_message(
                f"[RouterManager] WARNING: Could not dynamically find default gateway for '{self.interface_out_friendly_name}'. Using {self.ROUTER_GATEWAY_OUT_IP} as fallback (MUST BE CORRECT!).")
            self.router_gateway_out_ip = self.ROUTER_GATEWAY_OUT_IP

        # For IN interface: dynamically find an unused private subnet
        unused_in_ip = self._find_unused_private_subnet(system_active_networks)
        if not unused_in_ip:
            self.router_logger.log_message(
                "[RouterManager] CRITICAL ERROR: No unused subnet found for IN interface. Using fallback IP.")
            self.router_ip_in = self.ROUTER_IP_IN
            self.router_netmask_in = self.ROUTER_NETMASK_IN
            self.router_network_in = self.ROUTER_NETWORK_IN
        else:
            self.router_ip_in = unused_in_ip
            self.router_netmask_in = "255.255.255.0"
            self.router_network_in = ipaddress.ip_network(f"{self.router_ip_in}/{self.router_netmask_in}", strict=False)
            self.router_logger.log_message(
                f"[RouterManager] Dynamically assigned IP for IN interface '{self.interface_in_friendly_name}': {self.router_ip_in}/{self.router_netmask_in}")

        # Step 3: Assign IPs to interfaces using OS commands (netsh for Windows)
        self.router_logger.log_message(
            "[RouterManager] Assigning IPs to interfaces via OS commands (Requires Admin). This may cause temporary network disruption.")

        # Assign IN interface IP (using its friendly name for netsh)
        if not self._assign_ip_to_interface(self.interface_in_friendly_name, self.router_ip_in, self.router_netmask_in):
            self.router_logger.log_message(
                "[RouterManager] CRITICAL ERROR: Failed to assign IP to IN interface. Routing may not work.")
            return False

        # Assign OUT interface IP with its (discovered/fallback) gateway (using its friendly name for netsh)
        if not self._assign_ip_to_interface(self.interface_out_friendly_name, self.router_ip_out,
                                            self.router_netmask_out,
                                            self.router_gateway_out_ip):
            self.router_logger.log_message(
                "[RouterManager] CRITICAL ERROR: Failed to assign IP to OUT interface. Routing may not work.")
            return False

        # Step 4: Update internal _interfaces_config with assigned IPs and MACs
        self._interfaces_config[self.interface_in_full_name] = {
            'ip_addr': self.router_ip_in,
            'network': self.router_network_in,
            'mac': get_if_hwaddr(self.interface_in_full_name)
        }
        self._interfaces_config[self.interface_out_full_name] = {
            'ip_addr': self.router_ip_out,
            'network': self.router_network_out,
            'mac': get_if_hwaddr(self.interface_out_full_name),
            'is_default_gateway_iface': True
        }
        self.default_gateway_ip = self.router_gateway_out_ip

        # Get our own MAC addresses (re-get after IP assignment for certainty)
        self.mac_in = get_if_hwaddr(self.interface_in_full_name)
        self.mac_out = get_if_hwaddr(self.interface_out_full_name)

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
        return True  # Configuration successful

    def add_interface(self, iface_name: str, ip_address: str, netmask: str) -> bool:
        """
        Adds a network interface to the router's configuration.
        This interface must have the given static IP and netmask.
        Returns True on success, False on failure.
        """
        try:
            current_mac = get_if_hwaddr(iface_name)  # Use full Scapy name for Scapy functions
            if not current_mac:
                self.router_logger.log_message(
                    f"[RouterManager] ERROR: Could not get MAC for {iface_name}. Interface may not exist or be active.")
                return False

            ip_obj = ipaddress.ip_address(ip_address)
            network_obj = ipaddress.ip_network(f"{ip_address}/{netmask}", strict=False)

            self._interfaces_config[iface_name] = {  # Store config by full Scapy name
                'ip_addr': str(ip_obj),
                'network': network_obj,
                'mac': current_mac
            }
            self.router_logger.log_message(
                f"[RouterManager] Added interface to config: {iface_name} (IP: {ip_address}, Net: {network_obj})")
            return True
        except Exception as e:
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Failed to add interface {iface_name} to config: {e}")
            return False

    def set_default_gateway(self, gateway_ip: str, outbound_iface_name: str) -> bool:
        """
        Sets the default gateway IP and the interface through which to reach it.
        outbound_iface_name here is the full Scapy interface name.
        """
        if outbound_iface_name not in self._interfaces_config:
            self.router_logger.log_message(
                f"[RouterManager] ERROR: Outbound interface '{outbound_iface_name}' not configured for default gateway.")
            return False

        self.default_gateway_ip = gateway_ip
        self._interfaces_config[outbound_iface_name]['is_default_gateway_iface'] = True
        self.router_logger.log_message(f"[RouterManager] Set default gateway: {gateway_ip} via {outbound_iface_name}")
        return True

    def _get_mac_address(self, ip_address: str, iface: str) -> str | None:
        """Resolve MAC address for a given IP using ARP, or from cache. iface is full Scapy name."""
        with self._arp_cache_lock:
            if ip_address in self._arp_cache:
                return self._arp_cache[ip_address]

        self.router_logger.log_message(f"[ARP] Resolving MAC for {ip_address} on {iface}...")
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address), timeout=2, verbose=0, iface=iface)
            if ans:
                resolved_mac = ans[0][1].hwsrc
                with self._arp_cache_lock:
                    self._arp_cache[ip_address] = resolved_mac
                self.router_logger.log_message(f"[ARP] Resolved {ip_address} to {resolved_mac}")
                return resolved_mac
            self.router_logger.log_message(f"[ARP] Could not resolve MAC for {ip_address} on {iface}.")
            return None
        except Exception as e:
            self.router_logger.log_message(f"[ARP] Error during ARP resolution for {ip_address} on {iface}: {e}")
            return None

    def _process_packet(self, packet, inbound_iface_name: str):
        """
        Core packet processing logic for a single sniffing thread.
        Decides whether to drop or forward the packet.
        """
        # Ensure packet has IP layer (we only route IP traffic)
        if not packet.haslayer(IP):
            return

        ip_layer = packet.getlayer(IP)
        dst_ip = ip_layer.dst
        src_ip = ip_layer.src

        # Get config for inbound interface
        inbound_iface_config = self._interfaces_config.get(inbound_iface_name)
        if not inbound_iface_config:
            self.router_logger.log_message(
                f"[RouterManager] Packet from unconfigured interface {inbound_iface_name}, dropping.")
            return

        self.router_logger.log_message(
            f"\n[{threading.current_thread().name}] Packet: {src_ip} -> {dst_ip} (In: {inbound_iface_name})")

        # --- 1. Handle NAT Return Traffic (WAN -> LAN) ---
        if dst_ip == self.router_ip_out and (packet.haslayer(TCP) or packet.haslayer(UDP)):
            transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
            with self._nat_lock:
                original_client_info = self._nat_reverse_table.get(transport_layer.dport)

            if original_client_info:
                # This is a return packet for a NAT'd connection.
                self._un_nat_and_forward(packet, original_client_info)
                return  # Packet handled

        # --- NEW: Handle DNS Queries (UDP on port 53) ---
        if packet.haslayer(UDP) and packet.getlayer(UDP).dport == 53 and packet.haslayer(DNS):
            self._handle_dns_query(packet, inbound_iface_name, ip_layer, packet.getlayer(UDP), packet.getlayer(DNS))
            return  # DNS handled, don't pass to general forwarding logic

        # --- NEW: Handle DNS Responses (UDP on port 53, from external DNS server) ---
        if packet.haslayer(UDP) and packet.getlayer(UDP).sport == 53 and packet.haslayer(DNS):
            self._handle_dns_response(packet, inbound_iface_name, ip_layer, packet.getlayer(UDP), packet.getlayer(DNS))
            return  # DNS handled, don't pass to general forwarding logic

        if packet.haslayer(SimpleRIP):
            self._handle_rip_update(packet, inbound_iface_name)
            return
        # 1. Check if packet is for the router itself
        # This includes packets originating from the host and destined for its own IP
        is_for_router = False
        for iface_config in self._interfaces_config.values():
            if dst_ip == iface_config['ip_addr']:
                is_for_router = True
                break

        if is_for_router:
            self.router_logger.log_message(f"  -> Packet is for router itself ({dst_ip}), processing locally.")
            return  # Don't forward, let the OS handle it

        # --- NEW: Check if packet is originating FROM the host and needs forwarding ---
        # This handles traffic from the host machine itself going out to other networks (e.g., Internet)
        # We assume if the source IP is one of our router's IPs, it's host-originated for our purpose here.
        # This is a simplification; a real router wouldn't treat its own IP as "host originated traffic for forwarding".
        # But for an all-in-one host/router, it's a common simplification.
        if src_ip == inbound_iface_config['ip_addr']:  # Packet originated from the host
            # It's host-originated, and not for the router itself (checked above), so it needs forwarding
            self._forward_general_ip_packet(packet, inbound_iface_name)
            return

        # 2. Check TTL (Time To Live)
        if ip_layer.ttl <= 1:
            self.router_logger.log_message(f"  -> TTL expired ({ip_layer.ttl}). Dropping packet.")
            return

        # 3. Determine outbound interface and next hop based on destination network (for passing traffic)
        # This part handles traffic that's *not* originating from the host, but is passing *through* the router.
        self._forward_general_ip_packet(packet, inbound_iface_name)

    # --- NEW: DNS Handling Helpers ---
    def _handle_dns_query(self, packet, inbound_iface_name: str, ip_layer: IP, udp_layer: UDP, dns_layer: DNS):
        """Intercepts DNS queries, proxies them to a public DNS server, and tracks for response."""
        self.router_logger.log_message(
            f"  -> Intercepted DNS Query (ID: {dns_layer.id}) from {ip_layer.src}:{udp_layer.sport} for {dns_layer.qd.qname.decode()} ({dns_layer.qd.qtype}).")

        # Decide which external DNS server to use (e.g., Google's)
        external_dns_server_ip = self.PRIMARY_DNS_SERVER  # Or dynamically from self.router_gateway_out_ip

        # Determine the outbound interface for the DNS query
        outbound_iface_name = self.interface_out_full_name  # Assuming outbound is always WAN
        outbound_iface_config = self._interfaces_config.get(outbound_iface_name)

        if not outbound_iface_config:
            self.router_logger.log_message(
                f"  -> ERROR: Outbound interface '{outbound_iface_name}' not configured for DNS proxy.")
            return

        # Store the original packet's Layer 2 info and inbound interface for sending reply back
        with self._dns_requests_lock:
            # Key: (Original Source IP, Original Source Port, DNS Query ID)
            # Value: (Original Ether.src, Original Ether.dst, Inbound Interface)
            self._dns_requests[(ip_layer.src, udp_layer.sport, dns_layer.id)] = (
                packet[Ether].src, packet[Ether].dst, inbound_iface_name
            )
            self.router_logger.log_message(f"  -> DNS request {dns_layer.id} stored for reply.")

        # Modify the packet to send to the external DNS server
        modified_packet = packet.copy()
        modified_packet[IP].dst = external_dns_server_ip
        modified_packet[IP].src = outbound_iface_config['ip_addr']  # Source IP is router's OUT IP
        modified_packet[UDP].sport = udp_layer.sport  # Keep original source port to match reply

        # Decrement TTL
        modified_packet[IP].ttl -= 1

        # Update Layer 2 headers for the external DNS server
        modified_packet[Ether].src = outbound_iface_config['mac']
        # Get MAC of the external DNS server's next hop (likely the default gateway)
        target_mac = self._get_mac_address(self.router_gateway_out_ip, outbound_iface_name)
        if not target_mac:
            self.router_logger.log_message(
                f"  -> ERROR: Could not resolve MAC for gateway {self.router_gateway_out_ip} for DNS query.")
            del self._dns_requests[(ip_layer.src, udp_layer.sport, dns_layer.id)]  # Clean up
            return

        modified_packet[Ether].dst = target_mac

        # Delete checksums for recalculation by Scapy
        del modified_packet[IP].chksum
        del modified_packet[UDP].chksum

        try:
            sendp(modified_packet, iface=outbound_iface_name, verbose=0)
            self.router_logger.log_message(f"  -> Forwarded DNS query {dns_layer.id} to {external_dns_server_ip}.")
        except Exception as e:
            self.router_logger.log_message(f"  -> ERROR sending DNS query {dns_layer.id}: {e}")
            with self._dns_requests_lock:
                if (ip_layer.src, udp_layer.sport, dns_layer.id) in self._dns_requests:
                    del self._dns_requests[(ip_layer.src, udp_layer.sport, dns_layer.id)]  # Clean up on failure

    def _handle_dns_response(self, packet, inbound_iface_name: str, ip_layer: IP, udp_layer: UDP, dns_layer: DNS):
        """Intercepts DNS responses and proxies them back to the original client."""
        # Check if this response is for a query we proxied
        original_key = (ip_layer.dst, udp_layer.dport,
                        dns_layer.id)  # Dest IP is original source, dport is original sport

        with self._dns_requests_lock:
            original_request_info = self._dns_requests.pop(original_key, None)

        if original_request_info:
            original_ether_src, original_ether_dst, original_inbound_iface_name = original_request_info

            self.router_logger.log_message(
                f"  -> Intercepted DNS Response (ID: {dns_layer.id}) from {ip_layer.src} for {original_key[0]}.")

            # Modify the packet to send back to the original client
            modified_packet = packet.copy()
            modified_packet[IP].src = ip_layer.src  # Keep source as the DNS server
            modified_packet[IP].dst = original_key[0]  # Original client's IP
            modified_packet[UDP].sport = udp_layer.sport  # Keep source port as 53
            modified_packet[UDP].dport = original_key[1]  # Original client's port

            # Decrement TTL (already done by the router on the way out)
            modified_packet[IP].ttl -= 1

            # Update Layer 2 headers for sending back to original client
            modified_packet[Ether].src = self._interfaces_config[original_inbound_iface_name]['mac']
            modified_packet[Ether].dst = original_ether_src  # Original packet's Layer 2 source is now the dest

            # Delete checksums for recalculation
            del modified_packet[IP].chksum
            del modified_packet[UDP].chksum

            try:
                sendp(modified_packet, iface=original_inbound_iface_name, verbose=0)
                self.router_logger.log_message(f"  -> Forwarded DNS response {dns_layer.id} back to {original_key[0]}.")
            except Exception as e:
                self.router_logger.log_message(f"  -> ERROR sending DNS response {dns_layer.id}: {e}")
        # else:
        #     self.router_logger.log_message(f"  -> Unmatched DNS response from {ip_layer.src} (ID: {dns_layer.id}). Dropping.")

    def _forward_general_ip_packet(self, packet, inbound_iface_name: str):
        """
        Handles all packet forwarding using the RIP routing table.
        Applies NAT for traffic going from the LAN to the WAN.
        """
        ip_layer = packet.getlayer(IP)
        dst_ip = ip_layer.dst
        src_ip = ip_layer.src

        try:
            dst_ip_obj = ipaddress.ip_address(dst_ip)
        except ValueError:
            self.router_logger.log_message(f"  -> Invalid destination IP '{dst_ip}'. Dropping.")
            return

        # --- 1. Route Lookup (Longest-prefix match using the RIP table) ---
        best_match = None
        best_prefix = -1

        with self._rt_lock:
            # Find the most specific matching route in our table
            for net, rt_details in self._routing_table.items():
                if dst_ip_obj in net:
                    if net.prefixlen > best_prefix and rt_details["cost"] < 16:  # Ensure route is reachable
                        best_prefix = net.prefixlen
                        best_match = rt_details

        if not best_match:
            self.router_logger.log_message(f"  -> No route in table for {dst_ip}. Dropping.")
            return

        # --- 2. Determine Outbound Interface and Next Hop IP from the Route ---
        outbound_iface_name = best_match["interface"]

        # If the next_hop in the table is "0.0.0.0", it means the destination is on a
        # directly connected network. The actual next hop is the packet's final destination.
        # Otherwise, the next hop is the gateway/router specified in the table.
        if best_match["next_hop"] == "0.0.0.0":
            next_hop_ip = dst_ip
        else:
            next_hop_ip = best_match["next_hop"]

        # --- 3. Apply NAT (if traffic is crossing from LAN to WAN) ---
        is_lan_to_wan = (inbound_iface_name == self.interface_in_full_name and
                         outbound_iface_name == self.interface_out_full_name)

        if is_lan_to_wan and (packet.haslayer(TCP) or packet.haslayer(UDP)):
            transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
            key = (src_ip, transport_layer.sport)
            new_entry_created = False

            with self._nat_lock:
                if key not in self._nat_table:
                    # Create a new NAT entry if one doesn't exist
                    new_port = self._get_next_nat_port()
                    self._nat_table[key] = new_port
                    self._nat_reverse_table[new_port] = key
                    new_entry_created = True

                # Get the assigned external port
                new_port = self._nat_table[key]

            if new_entry_created:
                self.router_logger.log_message(
                    f"[NAT] ➡️  New mapping: {src_ip}:{transport_layer.sport} -> {self.router_ip_out}:{new_port}")
                # self.log_nat_table() # Optional: uncomment to log the table on each new entry

            # Modify the packet's source IP and port for NAT
            ip_layer.src = self.router_ip_out
            transport_layer.sport = new_port

        # --- 4. L2 Resolution and Packet Rewrite ---
        target_mac = self._get_mac_address(next_hop_ip, outbound_iface_name)
        if not target_mac:
            self.router_logger.log_message(f"  -> Could not resolve MAC for next hop {next_hop_ip}. Dropping.")
            return

        # Decrement TTL; drop if it's expired
        if ip_layer.ttl <= 1:
            self.router_logger.log_message("  -> TTL expired. Dropping.")
            return
        ip_layer.ttl -= 1

        # Set the new Ethernet source and destination MAC addresses
        packet[Ether].src = self._interfaces_config[outbound_iface_name]["mac"]
        packet[Ether].dst = target_mac

        # Delete checksums so Scapy recalculates them upon sending
        del ip_layer.chksum
        if packet.haslayer(TCP): del packet[TCP].chksum
        if packet.haslayer(UDP): del packet[UDP].chksum

        # --- 5. Send the Packet ---
        try:
            sendp(packet, iface=outbound_iface_name, verbose=0)
            self.router_logger.log_message(
                f"  -> Forwarded: {src_ip} -> {dst_ip} (Out: {outbound_iface_name}, Next MAC: {target_mac})")
        except Exception as e:
            self.router_logger.log_message(
                f"  -> ERROR sending packet via {outbound_iface_name}: {e}. Dropping.")

    def start_routing(self):
        """Starts sniffing on all configured interfaces to begin routing."""
        self._initialize_interface_discovery()
        self._auto_configure_interfaces()
        if not self._interfaces_config:
            self.router_logger.log_message("[RouterManager] No interfaces configured for routing. Aborting start.")
            return
        if not self.interface_in_full_name or not self.interface_out_full_name:
            self.router_logger.log_message(
                "[RouterManager] Auto-configuration of IN/OUT interfaces failed. Cannot start routing.")
            return

        self.router_logger.log_message("\n--- Starting Python Router ---")
        self._stop_sniffing_event.clear()

        for iface_name in self._interfaces_config.keys():
            thread = threading.Thread(target=lambda: sniff(
                iface=iface_name,
                prn=lambda pkt: self._process_packet(pkt, iface_name),
                store=0,
                stop_filter=lambda p: self._stop_sniffing_event.is_set()),
                                      name=f"Sniffer-{iface_name}",
                                      daemon=True)
            self._sniff_threads[iface_name] = thread
            thread.start()
            self.router_logger.log_message(f"[RouterManager] Sniffing started on {iface_name} in thread {thread.name}.")

        self.router_logger.log_message("Python router sniffing launched on all configured interfaces.")

    def stop_routing(self):
        """Signals sniffing threads to stop and cleans up."""
        if not self._sniff_threads:
            self.router_logger.log_message("[RouterManager] Router is not running.")
            return

        self.router_logger.log_message("\n--- Stopping Python Router ---")
        self._stop_sniffing_event.set()

        for iface_name, thread in self._sniff_threads.items():
            if thread.is_alive():
                self.router_logger.log_message(
                    f"[RouterManager] Waiting for sniffer thread {thread.name} on {iface_name} to stop...")
                thread.join(timeout=2)
                if thread.is_alive():
                    self.router_logger.log_message(
                        f"[RouterManager] Sniffer thread {thread.name} on {iface_name} did not terminate gracefully.")

        self._sniff_threads.clear()

        self.cleanup_all_network_changes()

        self.router_logger.log_message("Python router stopped.")

    def cleanup_all_network_changes(self):
        """
        Cleans up all network changes made by the router, reverting IPs and DNS
        to DHCP for the interfaces it managed.
        """
        self.router_logger.log_message("\n--- Cleaning up all network changes made by Python Router ---")

        if self.interface_in_friendly_name and self.router_ip_in:
            self.router_logger.log_message(
                f"[RouterManager Cleanup] Cleaning up IN interface '{self.interface_in_friendly_name}'...")
            self._cleanup_interface_ip(self.interface_in_friendly_name)
        else:
            self.router_logger.log_message(
                "[RouterManager Cleanup] No IN interface IP to clean up (not assigned or auto-config failed).")

        if self.interface_out_friendly_name and self.router_ip_out:
            self.router_logger.log_message(
                f"[RouterManager Cleanup] Cleaning up OUT interface '{self.interface_out_friendly_name}'...")
            self._cleanup_interface_ip(self.interface_out_friendly_name)
        else:
            self.router_logger.log_message(
                "[RouterManager Cleanup] No OUT interface IP to clean up (not assigned or auto-config failed).")

        self.router_logger.log_message("--- Network cleanup complete. ---")

    def _cleanup_interface_ip(self, iface_friendly_name: str):
        """
        Resets the IP configuration of an interface to DHCP.
        """
        self.router_logger.log_message(
            f"[RouterManager] Cleaning up IP for '{iface_friendly_name}' (setting to DHCP)...")

        netsh_args = ["set", "address", f'name="{iface_friendly_name}"', "source=dhcp"]

        if self._execute_netsh(netsh_args):
            self.router_logger.log_message(f"[RouterManager] Successfully set '{iface_friendly_name}' to DHCP.")
            return True
        else:
            self.router_logger.log_message(
                f"[RouterManager] WARNING: Failed to set '{iface_friendly_name}' to DHCP. Manual reset may be required.")
            return False

class PacketManager:
    def __init__(self, packet_logger):
        self.packet_logger = packet_logger  # Dedicated logger for ALL PacketManager logs
        self._interface = None  # To store the name of the active interface for Scapy

        # NEW: Internal storage for discovered interfaces (full name -> ID, and friendly name -> full name)
        self._tshark_interfaces = []  # List of {'id': 'X', 'name': 'Full Name (Friendly Name)'} dicts
        self._tshark_path = None  # Path to tshark.exe

        # Discover tshark path and interfaces on initialization
        self._initialize_interface_discovery()

        # Attempt to set default interface on initialization
        # This will now use the internally discovered interfaces
        self.packet_logger.log_message(
            "[PacketManager] Attempting to set default Scapy interface to 'Wi-Fi' on initialization...")
        self.set_interface("Wi-Fi")  # Call the public setter with a friendly name

    def _get_tshark_path(self) -> str | None:
        """Discover the path to tshark.exe."""
        if getattr(sys, "frozen", False):
            tshark_exe = Path(sys._MEIPASS) / "Wireshark" / "tshark.exe"
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

        self.packet_logger.log_message(
            "[PacketManager] Error: tshark.exe not found. Cannot discover interfaces via tshark -D.")
        return None

    def _initialize_interface_discovery(self):
        """Discover network interfaces using tshark -D and store them."""
        self._tshark_path = self._get_tshark_path()
        if not self._tshark_path:
            self.packet_logger.log_message("[PacketManager] Cannot perform interface discovery: tshark not found.")
            return

        self.packet_logger.log_message("[PacketManager] Discovering network interfaces via tshark -D...")
        try:
            proc = subprocess.run(
                [self._tshark_path, '-D'], capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            # Regex to capture both the main name and the optional friendly name in parentheses
            pattern = re.compile(r"(\d+)\.\s+([^(]+)(?:\((.*)\))?")  # Capture part before '(' and part inside '()'
            interface_output_lines = proc.stdout.strip().split('\n')

            for line in interface_output_lines:
                match = pattern.match(line)
                if match:
                    iface_id = match.group(1)
                    # The full name is match.group(2).strip()
                    # The friendly name is match.group(3) or None
                    full_name = match.group(2).strip()
                    friendly_name = match.group(3) if match.group(3) else ""

                    # Store both full name (for Scapy) and friendly name (for matching)
                    self._tshark_interfaces.append({
                        'id': iface_id,
                        'full_name': full_name,  # e.g., \Device\NPF_{GUID}
                        'friendly_name': friendly_name  # e.g., Wi-Fi
                    })
            self.packet_logger.log_message(
                f"[PacketManager] Discovered {len(self._tshark_interfaces)} interfaces via tshark.")
        except Exception as e:
            self.packet_logger.log_message(f"[PacketManager] Error during tshark interface discovery: {e}")

    def set_interface(self, user_friendly_name: str) -> bool:
        """
        Sets the network interface for Scapy using a user-friendly name
        (e.g., 'Wi-Fi', 'Ethernet'). It resolves this to the exact system name.
        Returns True if successful, False otherwise.
        """
        if not user_friendly_name:
            self.packet_logger.log_message("[PacketManager] Error: User-friendly interface name cannot be empty.")
            self._interface = None
            return False

        found_system_name_for_scapy = None

        # Try to resolve using the internally discovered tshark interfaces
        for iface_dict in self._tshark_interfaces:
            # Check if user_friendly_name matches the full name OR the friendly name part
            # Use .lower() for case-insensitive comparison
            if (user_friendly_name.lower() in iface_dict['full_name'].lower() or
                    user_friendly_name.lower() in iface_dict['friendly_name'].lower()):
                found_system_name_for_scapy = iface_dict['full_name']  # This is the \Device\NPF_{GUID} part
                break

        if found_system_name_for_scapy:
            # Call the internal helper to set the interface with the resolved full name (without friendly part)
            return self._set_interface_by_full_name(found_system_name_for_scapy)
        else:
            self.packet_logger.log_message(
                f"[PacketManager] ERROR: Could not resolve '{user_friendly_name}' to a system interface using tshark list. "
                "Packet sending interface not set. Ensure interface is active and Npcap is installed/running as admin."
            )
            self._interface = None
            return False

    def _set_interface_by_full_name(self, full_system_iface_name: str) -> bool:

        if not full_system_iface_name:
            self.packet_logger.log_message("[PacketManager] Error: Full system interface name cannot be empty.")
            return False

        try:
            available_scapy_names = get_if_list()
            if full_system_iface_name not in available_scapy_names:
                self.packet_logger.log_message(
                    f"[PacketManager] WARNING: Provided raw interface name '{full_system_iface_name}' "
                    f"not found by Scapy's get_if_list(). This might indicate a problem, but trying anyway. "
                    f"Available Scapy interfaces: {', '.join(available_scapy_names) if available_scapy_names else 'None'}"
                )

            conf.iface = full_system_iface_name
            self._interface = full_system_iface_name
            self.packet_logger.log_message(
                f"[PacketSender] Scapy outgoing interface explicitly set to: '{self._interface}'")
            return True
        except Exception as e:
            self.packet_logger.log_message(
                f"[PacketManager] CRITICAL ERROR: Could not explicitly set Scapy interface to '{full_system_iface_name}': {e}. "
                "Packet sending will likely fail. Ensure Npcap/WinPcap is installed and running as administrator.")
            self._interface = None
            return False

    def _send_packet_with_interface_check(self, packet, timeout: int = 2):
        """Helper to send a packet after verifying the interface is set."""
        if not self._interface:
            self.packet_logger.log_message(
                "[PacketSender] Error: Outgoing interface not set for Scapy. Cannot send packet.")
            return None

        try:
            # Explicitly pass the interface to sr1/send
            if hasattr(packet, "haslayer") and packet.haslayer(TCP) and (
                    packet.getlayer(TCP).flags & 0x04):  # If it's an RST
                send(packet, verbose=0, iface=self._interface)
                return True
            else:  # For sr1, where we expect a response
                response = sr1(packet, timeout=timeout, verbose=0, iface=self._interface)
                return response
        except PermissionError:
            self.packet_logger.log_message(
                "[PacketSender] Permission Error: Packet sending requires administrator/root privileges.")
            self.packet_logger.log_message(
                "[PacketManager] Caught PermissionError. Ensure application runs as administrator.")
            return None
        except Exception as e:
            self.packet_logger.log_message(
                f"[PacketSender] An error occurred while sending packet: {e}. Check network connectivity and permissions.")
            self.packet_logger.log_message(f"[PacketManager] Caught generic exception during packet send: {e}")
            return None

    def send_ping(self, target_ip: str, count: int = 1, timeout: int = 2):
        """Sends ICMP Echo Request (ping) packets to a target IP."""
        self.packet_logger.log_message(f"[PacketSender] Sending {count} ICMP Echo Request(s) to {target_ip}...")
        results = []
        for i in range(count):
            packet = IP(dst=target_ip) / ICMP()
            response = self._send_packet_with_interface_check(packet, timeout=timeout)
            if response is not None:
                if response is True:
                    results.append(True)
                elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 0:
                    self.packet_logger.log_message(
                        f"[PacketSender] Received ICMP Echo Reply from {response.src} (Seq={response.id}, TTL={response.ttl})"
                    )
                    results.append(True)
                else:
                    self.packet_logger.log_message(
                        f"[PacketSender] Received non-ICMP Echo Reply from {response.src}: {response.summary()}"
                    )
                    results.append(False)
            else:
                self.packet_logger.log_message(
                    f"[PacketSender] No response from {target_ip} after {timeout}s (Ping {i + 1}/{count}). Packet send may have failed.")
                results.append(False)
            time.sleep(0.1)
        self.packet_logger.log_message(f"[PacketSender] Finished sending pings to {target_ip}.")
        return all(results)

    def send_tcp_syn(self, target_ip: str, target_port: int, src_port: int = 12345, timeout: int = 2):
        """Sends a TCP SYN packet to a target IP and port."""
        self.packet_logger.log_message(
            f"[PacketSender] Sending TCP SYN to {target_ip}:{target_port} from port {src_port}...")
        packet = IP(dst=target_ip) / TCP(dport=target_port, sport=src_port, flags="S")
        response = self._send_packet_with_interface_check(packet, timeout=timeout)

        if response is not None:
            if response is True:
                self.packet_logger.log_message(f"[PacketSender] Unexpected direct send success for TCP SYN.")
                return False
            elif response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN-ACK
                    self.packet_logger.log_message(
                        f"[PacketSender] Port {target_port} on {target_ip} is OPEN (received SYN-ACK).")
                    rst_packet = IP(dst=target_ip) / TCP(dport=target_port, sport=src_port, flags="R",
                                                         seq=tcp_layer.ack, ack=tcp_layer.seq + 1)
                    self._send_packet_with_interface_check(rst_packet)
                    return True
                elif tcp_layer.flags & 0x04:  # RST (0x04)
                    self.packet_logger.log_message(
                        f"[PacketSender] Port {target_port} on {target_ip} is CLOSED (received RST).")
                    return False
                else:
                    self.packet_logger.log_message(
                        f"[PacketSender] Received unusual TCP flags: {tcp_layer.flags} from {target_ip}:{target_port}.")
                    return False
            else:
                self.packet_logger.log_message(f"[PacketSender] Received non-TCP response from {target_ip}.")
                return False
        else:
            self.packet_logger.log_message(
                f"[PacketSender] No response from {target_ip}:{target_port} after {timeout}s (likely filtered/firewalled, or send failed).")
            return False

    def send_udp_packet(self, target_ip: str, target_port: int, payload: bytes = b"Hello", src_port: int = 54321,
                        timeout: int = 2):
        self.packet_logger.log_message(
            f"[PacketSender] Sending UDP packet to {target_ip}:{target_port} from port {src_port} with payload '{payload.decode(errors='ignore')}'...")
        packet = IP(dst=target_ip) / UDP(dport=target_port, sport=src_port) / payload
        response = self._send_packet_with_interface_check(packet, timeout=timeout)

        if response is not None:
            if response is True:
                self.packet_logger.log_message(f"[PacketSender] Unexpected direct send success for UDP.")
                return False
            elif response.haslayer(ICMP) and response.getlayer(ICMP).type == 3 and response.getlayer(ICMP).code in [1,
                                                                                                                    2,
                                                                                                                    3,
                                                                                                                    9,
                                                                                                                    10,
                                                                                                                    13]:
                self.packet_logger.log_message(
                    f"[PacketSender] UDP Port {target_port} on {target_ip} is CLOSED (received ICMP Destination Unreachable).")
                return False
            else:
                self.packet_logger.log_message(
                    f"[PacketSender] Received a response from {target_ip}:{target_port}: {response.summary()}. UDP port likely OPEN.")
                return True
        else:
            self.packet_logger.log_message(
                f"[PacketSender] No response from {target_ip}:{target_port} after {timeout}s (UDP port likely OPEN or filtered, or send failed).")
            return False

    def send_dns_query(self, target_dns_server: str, domain: str, record_type: str = "A", timeout: int = 2):
        self.packet_logger.log_message(
            f"[PacketSender] Sending DNS query for '{domain}' ({record_type}) to {target_dns_server}...")
        packet = IP(dst=target_dns_server) / UDP(dport=53) / DNS(rd=1, qd=DNSQR(qname=domain, qtype=record_type))
        response = self._send_packet_with_interface_check(packet, timeout=timeout)

        if response is not None:
            if response is True:
                self.packet_logger.log_message(f"[PacketSender] Unexpected direct send success for DNS query.")
                return False
            elif response.haslayer(DNS):
                dns_layer = response.getlayer(DNS)
                if dns_layer.ancount > 0:
                    self.packet_logger.log_message(
                        f"[PacketSender] DNS response from {target_dns_server} for {domain}:")
                    for i in range(dns_layer.ancount):
                        an = dns_layer.an[i]
                        name = an.rrname.decode(errors='ignore')
                        rdata_val = an.rdata
                        if isinstance(rdata_val, bytes):
                            try:
                                rdata_val = str(ipaddress.ip_address(rdata_val))
                            except ValueError:
                                rdata_val = rdata_val.decode(errors='ignore')
                        self.packet_logger.log_message(f"  - {name} {rdata_val} (Type: {an.type})")
                    return True
                elif dns_layer.rcode != 0:
                    self.packet_logger.log_message(
                        f"[PacketSender] DNS error response from {target_dns_server}: RCODE {dns_layer.rcode} ({dns_layer.qr})")
                    return False
                else:
                    self.packet_logger.log_message(
                        f"[PacketSender] No answer records for {domain} from {target_dns_server}.")
                    return False
            else:
                self.packet_logger.log_message(f"[PacketSender] Received non-DNS response from {target_dns_server}.")
                return False
        else:
            self.packet_logger.log_message(
                f"[PacketSender] No response from DNS server {target_dns_server} after {timeout}s (or send failed).")
            return False

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
        self._initialize_geoip()

    def _initialize_geoip(self):
        """Finds and loads the GeoLite2-City database."""
        try:
            # Determine base path for GeoIP files based on execution mode
            if getattr(sys, "frozen", False):
                # Running in bundled mode (PyInstaller)
                # sys._MEIPASS is the path to the temporary directory where PyInstaller extracts files
                base_path = Path(sys._MEIPASS)
            else:
                # Running in development mode
                # Path(__file__).resolve().parent is 'server' directory, .parent gets 'project_root'
                base_path = Path(__file__).resolve().parent.parent

            # Define path for the uncompressed database file
            self._decompressed_db_path = base_path / "server" / "tools" / "GeoLite2-City.mmdb"

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
            reassembled = None
            if tcp_layer and tcp_layer.get("tcp.payload"):
                reassembled = bytes.fromhex(tcp_layer["tcp.payload"].replace(":", "")).decode(
                    "utf-8", errors="ignore")
            elif "data-text-lines" in layers:
                reassembled = layers["data-text-lines"]

            if reassembled:
                # Check if the reassembled data is mostly printable ASCII
                printable_chars = sum(1 for char in reassembled if 32 <= ord(char) <= 126 or ord(char) in [9, 10,
                                                                                                           13])  # ASCII printable + tab, newline, carriage return
                total_chars = len(reassembled)

                if total_chars > 0 and (printable_chars / total_chars) > 0.7:  # Heuristic: >70% printable
                    self.logger.log_message(f"[StreamData-{interface_id}]{tag_str} Text Payload: {reassembled.strip()}")
                else:
                    # If not mostly printable, it's likely binary. Log hex for debugging.
                    # Limit hex output to avoid excessively long logs
                    raw_payload_hex = tcp_layer.get("tcp.payload", "").replace(":", "")
                    truncated_hex = raw_payload_hex[:128] + ("..." if len(raw_payload_hex) > 128 else "")
                    self.logger.log_message(
                        f"[StreamData-{interface_id}]{tag_str} Binary Payload (Hex): {truncated_hex}")
            else:
                self.logger.log_message(
                    f"[StreamData-{interface_id}]{tag_str} No reassembled text/binary payload found.")

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