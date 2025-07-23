import queue
import socket
import ssl
from pathlib import Path
from socket import AF_INET
from typing import Optional, List, Tuple

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
import select
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


class PacketWriter:
    """
    A self-contained class that sends Layer 2 network packets on a dedicated
    thread using a queue. This prevents the calling thread from blocking on I/O.
    """

    def __init__(self, logger):
        """
        Initializes the PacketWriter.
        Args:
            logger: A logger instance for logging messages.
        """
        self.logger = logger
        self.packet_queue = queue.Queue()
        self.worker_thread = None
        self._stop_event = threading.Event()
        self.logger.log_message("[PacketWriter] Initialized.")

    def _worker_loop(self):
        """The main loop for the worker thread that sends packets."""
        self.logger.log_message("[PacketWriter] Worker thread started.")
        while not self._stop_event.is_set():
            try:
                # Block until a packet is available or the thread is stopped
                item = self.packet_queue.get(timeout=1)
                if item is None:  # Sentinel value to stop the thread
                    continue

                packet, interface_name = item
                self._send_raw_packet(packet, interface_name)

            except queue.Empty:
                continue  # Loop back and wait for another item

        self.logger.log_message("[PacketWriter] Worker thread has stopped.")

    def _send_raw_packet(self, packet, interface: str):
        """
        Uses Scapy's sendp to send a Layer 2 packet on a specified interface
        and logs a detailed summary of the sent packet.
        """
        if not interface:
            self.logger.log_message("[PacketWriter] ⚠️ Error: Cannot send packet, interface name is not specified.")
            return
        try:
            if packet.haslayer(IP):
                dst_ip = ipaddress.ip_address(packet[IP].dst)

                if not (dst_ip.is_global or dst_ip.is_private):
                    ## ENHANCED LOGGING ##
                    self.logger.log_message(
                        f"[PacketWriter] 🚫 Dropped non-unicast packet to {dst_ip}. Summary: {packet.summary()}"
                    )
                    return
                else:
                    packet_summary = packet.summary()
                    sendp(packet, iface=interface, verbose=0)
                    ## ENHANCED LOGGING ##
                    self.logger.log_message(
                        f"[PacketWriter] ✅ Sent (Len:{len(packet)}) on {interface} -> {packet_summary}"
                    )
            else:
                # For non-IP packets like ARP, etc.
                packet_summary = packet.summary()
                sendp(packet, iface=interface, verbose=0)
                ## ENHANCED LOGGING ##
                self.logger.log_message(
                    f"[PacketWriter] ✅ Sent (Len:{len(packet)}) on {interface} -> {packet_summary}"
                )

        except Exception as e:
            self.logger.log_message(f"[PacketWriter] ❌ Failed to send packet on interface '{interface}': {e}")

    def start(self):
        """Starts the packet-sending worker thread."""
        if self.worker_thread and self.worker_thread.is_alive():
            self.logger.log_message("[PacketWriter] Already running.")
            return

        self._stop_event.clear()
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True, name="PacketWriterThread")
        self.worker_thread.start()

    def stop(self):
        """Stops the packet-sending worker thread gracefully."""
        if not self.worker_thread or not self.worker_thread.is_alive():
            return

        self.logger.log_message("[PacketWriter] Stopping...")
        self._stop_event.set()
        # Add a sentinel value to the queue to unblock the worker's get() call
        self.packet_queue.put(None)
        self.worker_thread.join(timeout=2)

    def queue_packet(self, packet, interface: str):
        """
        Public method to add a packet to the sending queue. This is non-blocking.

        Args:
            packet: The Scapy packet to be sent (must be a Layer 2 packet like Ether).
            interface (str): The name of the interface to send the packet on.
        """
        if self._stop_event.is_set():
            self.logger.log_message("[PacketWriter] ⚠️ Warning: Attempted to queue packet while writer is stopping.")
            return

        self.packet_queue.put((packet, interface))

class TLSProxyManager:
    """
    Handles the application-layer TLS proxying of connections handed off by the router.
    Accepts (client_socket, target_host, target_port) tuples from the router.
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.connection_queue = queue.Queue()
        self._stop_event = threading.Event()
        self.worker_thread = None

    def start(self):
        """Starts the TLS proxy worker thread."""
        self.worker_thread = threading.Thread(target=self._worker_loop, daemon=True)
        self.worker_thread.start()
        self.router_logger.log_message("[TLSProxy] Worker thread started.")

    def stop(self):
        """Stops the TLS proxy worker thread."""
        self._stop_event.set()
        self.connection_queue.put(None)  # Unblock the queue if it's waiting
        self.worker_thread.join(timeout=2)
        self.router_logger.log_message("[TLSProxy] Worker thread stopped.")

    def _worker_loop(self):
        """Main loop for proxying queued connections."""
        while not self._stop_event.is_set():
            try:
                conn_details = self.connection_queue.get(timeout=1)
                if conn_details is None:
                    continue
                client_socket, target_host, target_port = conn_details
                self.router_logger.log_message(
                    f"[TLSProxy] Handling connection to {target_host}:{target_port}"
                )
                self._handle_tls_proxy(client_socket, target_host, target_port)
            except queue.Empty:
                continue
            except Exception as e:
                self.router_logger.log_message(f"[TLSProxy] Unexpected error: {e}")

    def _handle_tls_proxy(self, client_socket: socket.socket, target_host: str, target_port: int):
        """Establishes TLS connection to target and relays data between sockets."""
        try:
            # Set both sockets to non-blocking
            client_socket.setblocking(False)

            # Connect to the remote TLS server
            context = ssl.create_default_context()
            raw_server_socket = socket.create_connection((target_host, target_port), timeout=10)
            server_socket = context.wrap_socket(raw_server_socket, server_hostname=target_host)
            server_socket.setblocking(False)

            self.router_logger.log_message(f"[TLSProxy] TLS handshake with {target_host} complete.")

            # Main relay loop
            sockets = [client_socket, server_socket]
            while True:
                readable, _, exceptional = select.select(sockets, [], sockets, 1)
                if exceptional:
                    break

                for sock in readable:
                    try:
                        data = sock.recv(4096)
                        if not data:
                            raise ConnectionResetError("Connection closed")

                        # Relay to the opposite socket
                        if sock is client_socket:
                            server_socket.sendall(data)
                        else:
                            client_socket.sendall(data)
                    except (ssl.SSLWantReadError, ssl.SSLWantWriteError, BlockingIOError):
                        continue
                    except Exception as e:
                        self.router_logger.log_message(f"[TLSProxy] Socket relay error: {e}")
                        return

        except Exception as e:
            self.router_logger.log_message(f"[TLSProxy] TLS proxy failed: {e}")
        finally:
            try:
                client_socket.close()
            except:
                pass
            try:
                server_socket.close()
            except:
                pass
            self.router_logger.log_message(f"[TLSProxy] Connection closed.")

    def queue_connection(self, client_socket: socket.socket, target_host: str, target_port: int):
        """Enqueue a new connection for TLS proxying."""
        self.connection_queue.put((client_socket, target_host, target_port))


class RIPManager:
    """
    Manages the routing table and all RIPv2 protocol interactions.
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.RIP_PORT = 520
        self.RIP_MCAST_ADDR = "224.0.0.9"
        self.RIP_UPDATE_INTERVAL = 10  # seconds
        self.ROUTE_TIMEOUT = 180  # seconds until a route is considered invalid

        self._routing_table = {}
        self._rt_lock = threading.Lock()
        self._stop_event = threading.Event()
        self._thread = None
        self._interfaces_config = {}

    def initialize_routes(self, interfaces_config: dict, default_gateway_ip: str, default_gateway_iface: str):
        """
        Seeds the table with directly connected nets and a default route.
        Must be called before starting the manager.
        """
        self._interfaces_config = interfaces_config
        with self._rt_lock:
            self._routing_table.clear()
            # Add directly connected networks
            for ifname, cfg in self._interfaces_config.items():
                net = cfg["network"]
                self._routing_table[net] = {
                    "next_hop": "0.0.0.0",  # Indicates direct connection
                    "cost": 1,
                    "interface": ifname,
                    "advertised_by": "self",
                    "last_update": time.time(),
                }
            # Add default route if available
            if default_gateway_ip and default_gateway_iface:
                default_net = ipaddress.ip_network("0.0.0.0/0")
                self._routing_table[default_net] = {
                    "next_hop": default_gateway_ip,
                    "cost": 1,
                    "interface": default_gateway_iface,
                    "advertised_by": "self",
                    "last_update": time.time(),
                }
        self.router_logger.log_message(f"[RIP] Routing table initialized with {len(self._routing_table)} entries.")

    def find_route(self, dest_ip_str: str):
        """Finds the best route for a destination IP using longest prefix match."""
        try:
            dest_ip_obj = ipaddress.ip_address(dest_ip_str)
            best_match = None
            best_prefix = -1

            with self._rt_lock:
                for net, rt_details in self._routing_table.items():
                    if dest_ip_obj in net:
                        # Find the most specific matching route (longest prefix)
                        if net.prefixlen > best_prefix and rt_details["cost"] < 16:
                            best_prefix = net.prefixlen
                            best_match = rt_details
            return best_match
        except ValueError:
            return None

    def handle_packet(self, pkt, inbound_ifname: str):
        """Processes an incoming RIP packet with detailed logging."""
        ## NEW LOGGING ##
        self.router_logger.log_message(f"[RIP] Received packet on {inbound_ifname}: {pkt.summary()}")

        rip = pkt.getlayer(SimpleRIP)
        if rip.command == 1:  # 1 = request
            self.router_logger.log_message(f"[RIP] Ignoring RIP request from {pkt[IP].src}")
            return
        if rip.command != 2:  # 2 = response
            self.router_logger.log_message(
                f"[RIP] Ignored non-response/request RIP packet (command={rip.command}) from {pkt[IP].src}")
            return

        src_router = pkt[IP].src
        changed = False
        with self._rt_lock:
            for entry in rip.entries:
                net = ipaddress.ip_network(f"{entry.address}/{entry.subnet_mask}", strict=False)
                cost = min(entry.metric + 1, 16)
                current_route = self._routing_table.get(net)

                if current_route is None and cost < 16:
                    self._routing_table[net] = {
                        "next_hop": src_router, "cost": cost, "interface": inbound_ifname,
                        "advertised_by": src_router, "last_update": time.time(),
                    }
                    self.router_logger.log_message(
                        f"[RIP] ✅ New route discovered: {net} via {src_router} (cost={cost})")
                    changed = True
                elif current_route and current_route["advertised_by"] == src_router:
                    if current_route["cost"] != cost:
                        self.router_logger.log_message(
                            f"[RIP] 🔄 Route update: {net} via {src_router} (cost changed {current_route['cost']}→{cost})")
                    current_route["cost"] = cost
                    current_route["last_update"] = time.time()
                    changed = True
                elif current_route and cost < current_route["cost"]:
                    self.router_logger.log_message(
                        f"[RIP] ✨ Better route found: {net} via {src_router} (cost improved {current_route['cost']}→{cost})")
                    self._routing_table[net] = {
                        "next_hop": src_router, "cost": cost, "interface": inbound_ifname,
                        "advertised_by": src_router, "last_update": time.time(),
                    }
                    changed = True

        if changed:
            self.router_logger.log_message(f"[RIP] Routing table updated by neighbor {src_router}.")

    def _advertisement_loop(self):
        """Periodically sends RIP advertisements and purges timed-out routes."""
        while not self._stop_event.is_set():
            self._send_advertisements()
            self._purge_routes()
            self._stop_event.wait(self.RIP_UPDATE_INTERVAL)
        self.router_logger.log_message("[RIP] Advertisement thread has exited.")

    def _send_advertisements(self):
        """Sends RIP updates on all configured interfaces."""
        with self._rt_lock:
            table_snapshot = list(self._routing_table.items())

        for ifname, cfg in self._interfaces_config.items():
            if cfg.get("ip_addr") is None: continue
            entries = [
                RIPEntry(
                    address=str(net.network_address),
                    subnet_mask=str(net.netmask),
                    metric=16 if details["interface"] == ifname and details["advertised_by"] != "self" else details[
                        "cost"]
                ) for net, details in table_snapshot
            ]
            if not entries: continue

            rip_packet = Ether(src=cfg["mac"], dst="01:00:5e:00:00:09") / \
                         IP(src=cfg["ip_addr"], dst=self.RIP_MCAST_ADDR) / \
                         UDP(sport=self.RIP_PORT, dport=self.RIP_PORT) / \
                         SimpleRIP(command=2, version=2, entries=entries)
            try:
                ## NEW LOGGING ##
                self.router_logger.log_message(f"[RIP] Sending advertisement on {ifname} ({len(entries)} entries)")
                sendp(rip_packet, iface=ifname, verbose=0)
            except Exception as e:
                self.router_logger.log_message(f"[RIP] ❌ Advertisement send failed on {ifname}: {e}")

    def _purge_routes(self):
        """Removes routes that have not been updated recently."""
        with self._rt_lock:
            now = time.time()
            timed_out_routes = [
                net for net, details in self._routing_table.items()
                if details["advertised_by"] != "self" and (now - details["last_update"]) > self.ROUTE_TIMEOUT
            ]
            for net in timed_out_routes:
                del self._routing_table[net]
                self.router_logger.log_message(f"[RIP] 🗑️ Timed out and removed route: {net}")

    def start(self):
        """Starts the RIP advertisement thread."""
        self._stop_event.clear()
        self._thread = threading.Thread(target=self._advertisement_loop, daemon=True, name="RIPManagerThread")
        self._thread.start()
        self.router_logger.log_message("[RIP] Manager thread started.")

    def stop(self):
        """Stops the RIP advertisement thread."""
        if self._thread and self._thread.is_alive():
            self.router_logger.log_message("[RIP] Stopping manager thread...")
            self._stop_event.set()
            self._thread.join(timeout=2)
class NATManager:
    """
    Manages Network Address Translation (NAT) with enhanced debugging.
    """

    def __init__(self, router_logger, router_public_ip: str):
        self.router_logger = router_logger
        self.public_ip = router_public_ip
        self.NAT_PORT_MIN = 49152
        self.NAT_PORT_MAX = 65535

        self._nat_table = {}
        self._nat_reverse_table = {}
        self._lock = threading.Lock()
        self._next_port = self.NAT_PORT_MIN

    def _get_next_port(self) -> int:
        with self._lock:
            port = self._next_port
            self._next_port += 1
            if self._next_port > self.NAT_PORT_MAX:
                self._next_port = self.NAT_PORT_MIN
            return port

    def translate_outbound(self, packet):
        """Translates an outbound packet and logs the new mapping."""
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return

        ip_layer = packet.getlayer(IP)
        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)
        key = (ip_layer.src, transport_layer.sport)

        with self._lock:
            if key not in self._nat_table:
                new_port = self._get_next_port()
                self._nat_table[key] = new_port
                self._nat_reverse_table[new_port] = key
                # --- CRUCIAL OUTBOUND LOG ---
                self.router_logger.log_message(
                    f"[NAT] ➡️ Creating mapping: {ip_layer.src}:{transport_layer.sport} -> {self.public_ip}:{new_port}"
                )

            # Rewrite the packet
            ip_layer.src = self.public_ip
            transport_layer.sport = self._nat_table[key]

    def translate_inbound(self, packet):
        """Translates an inbound packet and logs the lookup attempt."""
        if not (packet.haslayer(TCP) or packet.haslayer(UDP)):
            return None

        transport_layer = packet.getlayer(TCP) or packet.getlayer(UDP)

        # --- CRUCIAL INBOUND LOG ---
        self.router_logger.log_message(
            f"[NAT] ⬅️ Looking for port {transport_layer.dport} in NAT table..."
        )
        # For deep debugging, you can log the entire table:
        # self.router_logger.log_message(f"[NAT] Reverse Table state: {self._nat_reverse_table}")

        with self._lock:
            original_client_info = self._nat_reverse_table.get(transport_layer.dport)

        if original_client_info:
            original_ip, original_port = original_client_info
            ip_layer = packet.getlayer(IP)
            self.router_logger.log_message(
                f"[NAT] ✅ Found mapping for {original_ip}:{original_port}."
            )
            # Rewrite the packet
            ip_layer.dst = original_ip
            transport_layer.dport = original_port
            return True  # Indicates successful translation

        return None

class DNSManager:
    """
    Manages DNS query proxying. Intercepts local DNS requests and forwards
    them to a public DNS server.
    """

    def __init__(self, router_logger):
        self.router_logger = router_logger
        self.PRIMARY_DNS_SERVER = "8.8.8.8"  # Google's public DNS
        self._pending_requests = {}  # Tracks ongoing DNS queries
        self._lock = threading.Lock()

    def handle_query(self, packet, inbound_iface: str, router_interfaces: dict, get_mac_function, find_route_function):
        """
        Processes a DNS query packet, forwarding it to a public DNS server.
        Returns True if the packet was handled, False otherwise.
        """
        if not (packet.haslayer(DNS) and packet[DNS].qr == 0):  # 0 = query
            return False

        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet.getlayer(DNS)

        # Use the find_route_function to get the default route and its interface
        default_route = find_route_function("8.8.8.8")
        if not default_route:
            self.router_logger.log_message("[DNS] Cannot proxy query: No default route found.")
            return False

        outbound_iface_name = default_route.get("interface")
        if not outbound_iface_name or inbound_iface == outbound_iface_name:
            return False

        outbound_iface_config = router_interfaces.get(outbound_iface_name)
        if not outbound_iface_config:
            return False

        key = (ip_layer.src, udp_layer.sport, dns_layer.id)
        with self._lock:
            self._pending_requests[key] = {
                "original_mac_src": packet[Ether].src,
                "inbound_iface": inbound_iface
            }

        self.router_logger.log_message(
            f"[DNS] ➡️  Proxying query for {dns_layer.qd.qname.decode()} from {ip_layer.src}"
        )

        modified_packet = packet.copy()
        modified_packet[IP].src = outbound_iface_config['ip_addr']
        modified_packet[IP].dst = self.PRIMARY_DNS_SERVER
        modified_packet[Ether].src = outbound_iface_config['mac']

        gateway_ip = default_route.get("next_hop")
        target_mac = get_mac_function(gateway_ip, outbound_iface_name) if gateway_ip else None

        if not target_mac:
            self.router_logger.log_message(f"[DNS] Could not resolve gateway MAC for {gateway_ip}. Dropping query.")
            with self._lock:
                self._pending_requests.pop(key, None)
            return True

        modified_packet[Ether].dst = target_mac
        del modified_packet[IP].chksum
        del modified_packet[UDP].chksum

        try:
            sendp(modified_packet, iface=outbound_iface_name, verbose=0)
        except Exception as e:
            self.router_logger.log_message(f"[DNS] Failed to send proxied query: {e}")
            with self._lock:
                self._pending_requests.pop(key, None)
        return True

    def handle_response(self, packet, router_interfaces: dict):
        """
        Processes a DNS response, rewriting and forwarding it to the original client.
        Returns True if the packet was handled, False otherwise.
        """
        if not (packet.haslayer(DNS) and packet[DNS].qr == 1):
            return False

        ip_layer = packet.getlayer(IP)
        udp_layer = packet.getlayer(UDP)
        dns_layer = packet.getlayer(DNS)
        key = (ip_layer.dst, udp_layer.dport, dns_layer.id)

        with self._lock:
            original_request = self._pending_requests.pop(key, None)

        if original_request:
            self.router_logger.log_message(
                f"[DNS] ⬅️  Routing response for {dns_layer.qd.qname.decode()} to {key[0]}"
            )

            response_iface_name = original_request["inbound_iface"]
            response_iface_config = router_interfaces.get(response_iface_name)
            if not response_iface_config:
                return True

            modified_packet = packet.copy()
            modified_packet[IP].src = self.PRIMARY_DNS_SERVER
            modified_packet[IP].dst = key[0]
            modified_packet[Ether].src = response_iface_config['mac']
            modified_packet[Ether].dst = original_request["original_mac_src"]

            del modified_packet[IP].chksum
            del modified_packet[UDP].chksum

            try:
                sendp(modified_packet, iface=response_iface_name, verbose=0)
            except Exception as e:
                self.router_logger.log_message(f"[DNS] Failed to send proxied response: {e}")
            return True
        return False

class ARPManager:
    """
    Manages ARP resolution, caching, and related ARP operations for the router.
    """

    def __init__(self, router_logger, cache_timeout_seconds=300):
        """
        Initializes the ARP Manager.
        Args:
            router_logger: The logger instance for logging messages.
            cache_timeout_seconds (int): How long a cache entry is valid.
        """
        self.router_logger = router_logger
        self._arp_cache = {}  # Maps IP -> (MAC, timestamp)
        self._arp_cache_lock = threading.Lock()
        self.CACHE_TIMEOUT = cache_timeout_seconds

    def resolve(self, ip_address: str, iface: str) -> str | None:
        """
        Resolves an IP address to a MAC address using the ARP protocol.
        Checks the cache first. If the entry is not found or is stale, it sends a new ARP request.

        Args:
            ip_address (str): The IP address to resolve.
            iface (str): The full Scapy name of the interface to send the request from.

        Returns:
            The resolved MAC address as a string, or None if resolution fails.
        """
        # Check cache for a valid, non-stale entry
        with self._arp_cache_lock:
            cached_entry = self._arp_cache.get(ip_address)
            if cached_entry:
                mac, timestamp = cached_entry
                if time.time() - timestamp < self.CACHE_TIMEOUT:
                    self.router_logger.log_message(f"[ARP] Cache hit for {ip_address} -> {mac}")
                    return mac
                else:
                    self.router_logger.log_message(f"[ARP] Stale cache entry for {ip_address}. Re-resolving.")

        # If not in cache or stale, send a new ARP request
        self.router_logger.log_message(f"[ARP] Cache miss. Sending ARP request for {ip_address} on {iface}...")
        try:
            # srp() sends a packet at Layer 2 and waits for an answer
            ans, unans = srp(
                Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip_address),
                timeout=2,
                iface=iface,
                verbose=0
            )

            if ans:
                # The answer is a list of (request, reply) tuples
                resolved_mac = ans[0][1].hwsrc
                with self._arp_cache_lock:
                    self._arp_cache[ip_address] = (resolved_mac, time.time())
                self.router_logger.log_message(f"[ARP] ✅ Resolved {ip_address} to {resolved_mac}")
                return resolved_mac
            else:
                self.router_logger.log_message(f"[ARP] ⚠️ Could not resolve MAC for {ip_address} on {iface}.")
                return None
        except Exception as e:
            self.router_logger.log_message(f"[ARP] ❌ Error during ARP resolution for {ip_address}: {e}")
            return None

    def get_cache_view(self) -> dict:
        """Returns a copy of the current ARP cache for inspection."""
        with self._arp_cache_lock:
            return self._arp_cache.copy()

    def clear_cache(self):
        """Clears all entries from the ARP cache."""
        with self._arp_cache_lock:
            self._arp_cache.clear()
        self.router_logger.log_message("[ARP] Cache cleared.")


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
        self.interface_in_full_name = None
        self.interface_in_friendly_name = None
        self.interface_out_full_name = None
        self.interface_out_friendly_name = None
        self.router_ip_in = None
        self.router_ip_out = None
        self.router_gateway_out_ip = None

        self._sniff_threads = {}
        self._stop_sniffing_event = threading.Event()
        self._tshark_path = None
        self._discovered_tshark_interfaces = []

        # Instantiate all specialized managers
        self.dns_manager = DNSManager(router_logger)
        self.rip_manager = RIPManager(router_logger)
        self.nat_manager = None  # Initialized after public IP is known
        self.tls_proxy_manager = TLSProxyManager(router_logger)
        self.arp_manager = ARPManager(router_logger)

        self.packet_writer = PacketWriter(router_logger)

        self.router_logger.log_message("[RouterManager] Orchestrator Initialized.")

    def _get_tshark_path(self) -> str | None:
        """Discover the path to tshark.exe (copied from your WiresharkManager)."""
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

        self.router_logger.log_message(
            "[RouterManager] Error: tshark.exe not found. Cannot discover interfaces via tshark -D.")
        return None

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

    def _configure_firewall_rules(self):
        """
        Adds firewall rules to allow traffic between IN and OUT interfaces.
        """
        try:
            for direction, iface in [("Outbound", self.interface_out_friendly_name),
                                     ("Inbound", self.interface_out_friendly_name)]:
                rule_name = f"PythonRouter-Allow-{direction}"
                direction_flag = "Out" if direction == "Outbound" else "In"

                ps_command = [
                    "powershell.exe",
                    "-Command",
                    f"New-NetFirewallRule -DisplayName '{rule_name}' -Direction {direction_flag} "
                    f"-InterfaceAlias '{iface}' -Action Allow -Profile Any -Protocol Any"
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
            for rule_name in ["PythonRouter-Allow-Outbound", "PythonRouter-Allow-Inbound"]:
                ps_command = ["powershell.exe", "-Command", f"Remove-NetFirewallRule -DisplayName '{rule_name}'"]
                result = subprocess.run(ps_command, capture_output=True, text=True,
                                        creationflags=subprocess.CREATE_NO_WINDOW)
                if result.returncode == 0:
                    self.router_logger.log_message(f"[Firewall] 🧹 Removed rule: {rule_name}")
                else:
                    self.router_logger.log_message(
                        f"[Firewall] ⚠️ Failed to remove rule: {rule_name}. STDERR: {result.stderr.strip()}")
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
            self._configure_firewall_rules()
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

    def _process_packet(self, packet, inbound_iface: str):
        """Main packet processing pipeline."""
        if not packet.haslayer(IP):
            return
        self.router_logger.log_message(f"CAPTURED on {inbound_iface.split('_')[1]}: {packet.summary()}")
        # --- High-priority packet handling ---
        # **FIX 3**: Call DNS handler with the correct, existing functions for ARP and routing.
        if packet.haslayer(UDP) and (packet[UDP].sport == 53 or packet[UDP].dport == 53):
            if self.dns_manager.handle_query(packet, inbound_iface, self._interfaces_config, self.arp_manager.resolve,
                                             self.rip_manager.find_route):
                return
            if self.dns_manager.handle_response(packet, self._interfaces_config):
                return

        dst_ip = packet[IP].dst
        router_ips = [cfg["ip_addr"] for cfg in self._interfaces_config.values() if "ip_addr" in cfg]
        is_for_router = any(dst_ip == ip for ip in router_ips)

        if is_for_router:
            if packet.haslayer(SimpleRIP):
                self.rip_manager.handle_packet(packet, inbound_iface)
                return

            # **FIX 2**: Correctly handle inbound NAT packets. Use the `inbound_iface` variable
            # instead of a hardcoded value.
            if self.nat_manager and self.nat_manager.translate_inbound(packet):
                # After translation, the packet is for an internal client. Forward it.
                self._forward_general_ip_packet(packet, inbound_iface)
            return

        # If not for the router, it's transit traffic to be forwarded
        self._forward_general_ip_packet(packet, inbound_iface)

    def _forward_general_ip_packet(self, packet, inbound_iface: str):
        """Forwards a transit packet, applying NAT and other rules."""
        ip_layer = packet.getlayer(IP)
        dst_ip = ip_layer.dst

        if ip_layer.ttl <= 1:
            self.router_logger.log_message(f"-> TTL expired for {dst_ip}. Dropping.")
            return

        route = self.rip_manager.find_route(dst_ip)
        if not route:
            self.router_logger.log_message(f"-> No route to {dst_ip}. Dropping.")
            return

        outbound_iface = route["interface"]
        next_hop_ip = route["next_hop"] if route["next_hop"] != "0.0.0.0" else dst_ip

        # **FIX 1**: Prevent forwarding packets back out the same interface (hairpinning).
        # This directly stops the "capturing from IN and sending through IN" behavior for LAN traffic.
        if inbound_iface == outbound_iface:
            self.router_logger.log_message(
                f"-> Dropping packet for {dst_ip} to prevent hairpinning on interface {inbound_iface}.")
            return

        is_lan_to_wan = (inbound_iface == self.interface_in_full_name and
                         outbound_iface == self.interface_out_full_name)

        self.router_logger.log_message(
            f"✅ FORWARDING: {packet.summary()} | In:{inbound_iface.split('_')[1]} -> Out:{outbound_iface.split('_')[1]}"
        )

        if is_lan_to_wan and self.nat_manager:
            self.nat_manager.translate_outbound(packet)

        target_mac = self.arp_manager.resolve(next_hop_ip, outbound_iface)
        if not target_mac:
            self.router_logger.log_message(f"-> ARP failed for next hop {next_hop_ip}. Dropping.")
            return

        packet.ttl -= 1
        packet[Ether].src = self._interfaces_config[outbound_iface]["mac"]
        packet[Ether].dst = target_mac

        del ip_layer.chksum
        if packet.haslayer(TCP): del packet[TCP].chksum
        if packet.haslayer(UDP): del packet[UDP].chksum

        self.packet_writer.queue_packet(packet, outbound_iface)

    def start_routing(self):
        """Configures interfaces and starts all manager threads."""
        self._initialize_interface_discovery()
        if not self._auto_configure_interfaces():
            self.router_logger.log_message("[Router] Auto-configuration failed. Aborting start.")
            return

        self.nat_manager = NATManager(self.router_logger, self.router_ip_out)
        self.rip_manager.initialize_routes(self._interfaces_config, self.router_gateway_out_ip,
                                           self.interface_out_full_name)

        self.rip_manager.start()
        self.tls_proxy_manager.start()
        self.packet_writer.start()

        self.router_logger.log_message("\n--- Python Router Starting Services ---")
        self._stop_sniffing_event.clear()

        for iface_name in self._interfaces_config.keys():
            # Define the target function with error handling
            def sniffer_loop(name=iface_name):
                try:
                    sniff(
                        iface=name,
                        prn=lambda pkt: self._process_packet(pkt, name),
                        store=0,
                        stop_filter=lambda p: self._stop_sniffing_event.is_set()
                    )
                except Exception as e:
                    # If a thread crashes, this will log it!
                    self.router_logger.log_message(f"‼️ CRITICAL ERROR in sniffer thread for {name}: {e}")

            thread = threading.Thread(target=sniffer_loop, name=f"Sniffer-{iface_name}", daemon=True)
            self._sniff_threads[iface_name] = thread
            thread.start()
            self.router_logger.log_message(f"[Router] Sniffing started on {iface_name}.")

    def stop_routing(self):
        """Stops all manager threads and cleans up network interfaces."""
        self.router_logger.log_message("\n--- Python Router Stopping Services ---")
        self._stop_sniffing_event.set()

        # Stop all manager threads
        self.rip_manager.stop()
        self.tls_proxy_manager.stop()
        self.packet_writer.stop()
        for thread in self._sniff_threads.values():
            if thread.is_alive():
                thread.join(timeout=2)
        self._sniff_threads.clear()

        self.cleanup_all_network_changes()
        self.router_logger.log_message("[Router] All services stopped.")

    def cleanup_all_network_changes(self):
        """
        Cleans up all network changes made by the router, reverting IPs and DNS
        to DHCP for the interfaces it managed.
        """
        self.router_logger.log_message("\n--- Cleaning up all network changes made by Python Router ---")
        self._remove_firewall_rules()
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

        netsh_args = ["set", "address", f'name={iface_friendly_name}', "source=dhcp"]

        if self._execute_netsh(netsh_args):
            self.router_logger.log_message(f"[RouterManager] Successfully set '{iface_friendly_name}' to DHCP.")
            return True
        else:
            self.router_logger.log_message(
                f"[RouterManager] WARNING: Failed to set '{iface_friendly_name}' to DHCP. Manual reset may be required.")
            return False

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

            response = sr1(packet, timeout=timeout, verbose=0, iface=iface)

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

            response = sr1(packet, timeout=timeout, verbose=0, iface=iface)

            if response is None: return 'FILTERED', None

            if response.haslayer(TCP):
                tcp_layer = response.getlayer(TCP)
                if tcp_layer.flags == 0x12:  # SYN/ACK
                    rst_src_ip = response[IP].dst
                    rst_packet = IP(dst=target_ip, src=rst_src_ip) / TCP(
                        dport=target_port, sport=packet[TCP].sport, flags='R', seq=tcp_layer.ack
                    )
                    send(rst_packet, verbose=0, iface=iface)
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

            response = sr1(packet, timeout=timeout, verbose=0, iface=iface)

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

            response = sr1(packet, timeout=timeout, verbose=0, iface=iface)

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