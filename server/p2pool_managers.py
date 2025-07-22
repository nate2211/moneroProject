import ipaddress
import os
import re
import shutil
import subprocess
import sys
import threading
import json
import time
from collections import deque
from pathlib import Path
# NEW: Import the geoip2 library
import geoip2.database
import geoip2.errors


class WiresharkManager:
    """
    Manages tshark subprocesses for network capture, TCP stream reassembly,
    and GeoIP location lookup on multiple interfaces simultaneously.
    """

    def __init__(self, p2pool_data, logger):
        self.p2pool_data = p2pool_data
        self.logger = logger
        self.tshark_procs = {}
        self.redirect_threads = {}
        self.stop_event = threading.Event()
        self.geoip_reader = None

        # NEW: Attributes for stateful correlation engine
        self.correlation_lock = threading.Lock()

        self.stream_map = {}  # Stores the final loopback <-> VPN mappings
        self.loopback_interface_id = None
        self.vpn_interface_id = None

        self._initialize_geoip()

    # NEW: Method to load the GeoIP database
    def _initialize_geoip(self):
        """Finds and loads the GeoLite2-City database."""
        try:
            # Assumes the database is in a standard location within the project
            server_dir = Path(__file__).resolve().parent
            project_root = server_dir.parent
            db_path = project_root / "tools" / "GeoIP" / "GeoLite2-City.mmdb"

            if not db_path.exists():
                self.logger.log_message(f"[GeoIP] Warning: Database not found at {db_path}. GeoIP lookups disabled.")
                return

            self.geoip_reader = geoip2.database.Reader(str(db_path))
            self.logger.log_message("[GeoIP] Successfully loaded GeoIP database.")

        except Exception as e:
            self.logger.log_message(f"[GeoIP] Error loading database: {e}. GeoIP lookups disabled.")
            self.geoip_reader = None

    # NEW: Method to perform the lookup for a single IP
    # Method to perform the lookup for a single IP
    def _get_geoip_location(self, ip_address: str) -> str:
        """Looks up an IP address and returns a formatted location string."""
        if not self.geoip_reader or not ip_address:
            return ""

        try:
            if not geoip2.database.Reader.is_public_ip(ip_address):
                # Return the string WITHOUT parentheses here
                return "Private IP"

            response = self.geoip_reader.city(ip_address)
            city = response.city.name or "Unknown City"
            country = response.country.iso_code or "N/A"
            return f"{city}, {country}"

        except geoip2.errors.AddressNotFoundError:
            return "Unknown"
        except Exception:
            return "Lookup Error"
    def _get_tshark_path(self) -> str | None:
        # (This method is unchanged)
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
        # (This method is unchanged)
        self.logger.log_message("[Wireshark] Discovering network interfaces...")
        interfaces = []
        try:
            proc = subprocess.run(
                [tshark_path, '-D'], capture_output=True, text=True, check=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            pattern = re.compile(r"(\d+)\.\s+(.*)")
            for line in proc.stdout.strip().split('\n'):
                match = pattern.match(line)
                if match:
                    interfaces.append({'id': match.group(1), 'name': match.group(2).strip()})
            self.logger.log_message(f"[Wireshark] Found {len(interfaces)} interfaces.")
        except Exception as e:
            self.logger.log_message(f"[Wireshark] An error occurred while listing interfaces: {e}")
        return interfaces

    def start_capture(self, main_interface_id='1', promiscuous=True):
        # (This method is unchanged)
        tshark_path = self._get_tshark_path()
        if not tshark_path: return False
        if self.tshark_procs:
            self.logger.log_message("[Wireshark] Capture is already running.")
            return False
        available_interfaces = self._list_interfaces(tshark_path)
        if not available_interfaces: return False
        interfaces_to_capture = {main_interface_id}
        for iface in available_interfaces:
            if "WireGuard Tunnel" in iface['name'] or "ProtonVPN" in iface['name']:
                self.logger.log_message(
                    f"[Wireshark] Detected active VPN interface: {iface['name']} (ID: {iface['id']}). Adding to capture.")
                interfaces_to_capture.add(iface['id'])
            elif "Loopback" in iface['name']:
                self.logger.log_message(
                    f"[Wireshark] Detected Loopback interface: {iface['name']} (ID: {iface['id']}). Adding to capture.")
                interfaces_to_capture.add(iface['id'])
        self.logger.log_message(f"[Wireshark] Final capture list (IDs): {list(interfaces_to_capture)}")
        self.logger.log_message(
            f"[CorrelationEngine] Watching for 'cause' on Loopback ID: {self.loopback_interface_id}")
        self.logger.log_message(f"[CorrelationEngine] Watching for 'effect' on VPN ID: {self.vpn_interface_id}")

        self.logger.log_message(f"[Wireshark] Final capture list (IDs): {list(interfaces_to_capture)}")
        self.stop_event.clear()

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
        # MODIFIED: Close the GeoIP reader when stopping
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

            ip_layer = layers.get("ip") or layers.get("ipv6")
            src_ip = ip_layer.get("ip.src", ip_layer.get("ipv6.src", "N/A")) if ip_layer else "N/A"
            dst_ip = ip_layer.get("ip.dst", ip_layer.get("ipv6.dst", "N/A")) if ip_layer else "N/A"

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
                self.logger.log_message(
                    f"[StreamData-{interface_id}]{tag_str} {reassembled.strip()}")

        except Exception as e:
            self.logger.log_message(
                f"[Wireshark-Process] Error processing packet on interface {interface_id}: {e}")

    def _redirect_output(self, process: subprocess.Popen, interface_id: str):
        # (This method is unchanged from the last working version)
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