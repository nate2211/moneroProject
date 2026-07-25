import ctypes
import os
import queue
import threading
import asyncio

from PyQt5.QtWidgets import QMainWindow, QTabWidget
from PyQt5.QtCore import QObject, pyqtSignal, QThread
from p2pool_gui_elements import P2PoolTab, WiresharkTab, RouterTab, PacketSenderTab, AsyncWorker, PacketSendingThread, \
    PacketSenderWorker, GeminiChatTab, NmapTab, GobusterTab, ScrapingTab, OllamaModelTab, OllamaLogger


def is_admin():
    """Checks if the script is running with administrator privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAdmin()
    except:
        return False

# Centralized stylesheet (unchanged)
DARK_STYLESHEET = """
    QMainWindow, QTabWidget, QWidget {
        background-color: #2b2b2b;
    }
    QTabWidget::pane {
        border-top: 2px solid #4f4f4f;
    }
    QTabBar::tab {
        background: #4a4a4a;
        color: #dcdcdc;
        padding: 8px 20px;
        border: 1px solid #5a5a5a;
        border-bottom: none;
        border-top-left-radius: 4px;
        border-top-right-radius: 4px;
    }
    QTabBar::tab:selected, QTabBar::tab:hover {
        background: #5a5a5a;
    }
    QPlainTextEdit {
        background-color: #212121;
        color: #dcdcdc;
        border: 1px solid #4f4f4f;
        font-family: Consolas, Courier New, monospace;
        font-size: 12px;
    }
    QPushButton {
        background-color: #4a4a4a;
        color: #dcdcdc;
        border: 1px solid #5a5a5a;
        padding: 5px 15px;
        border-radius: 3px;
        font-size: 13px;
        font-weight: bold;
    }
    QPushButton:hover {
        background-color: #5a5a5a;
        border-color: #6a6a6a;
    }
    QPushButton:pressed {
        background-color: #3a3a3a;
    }
    QPushButton:disabled {
        background-color: #333333;
        color: #777777;
        border-color: #444444;
    }
    #start_button, #start_wireshark_button, #start_router_button {
        color: #a9f5a9;
    }
    #start_button:hover, #start_wireshark_button:hover, #start_router_button:hover {
        background-color: #38761d;
    }
    #stop_button, #stop_wireshark_button, #stop_router_button {
        color: #ff9999;
    }
    #stop_button:hover, #stop_wireshark_button:hover, #stop_router_button:hover {
        background-color: #990000;
    }
    #send_button, #clear_history_button { /* Styling for Gemini Chat buttons */
        background-color: #6a5acd; /* Slate Blue */
        color: #dcdcdc;
        border: 1px solid #7b68ee;
    }
    #send_button:hover, #clear_history_button:hover {
        background-color: #7b68ee;
    }
    #send_button:pressed, #clear_history_button:pressed {
        background-color: #5a4b9c;
    }
    #send_button:disabled {
        background-color: #333333;
        color: #777777;
        border-color: #444444;
    }
"""


class ConsoleLogger(QObject):
    message_signal = pyqtSignal(str)

    def log_message(self, msg): self.message_signal.emit(str(msg).rstrip())

    def write(self, msg):
        if msg.strip(): self.log_message(msg)

    def flush(self): pass


class WiresharkLogger(QObject):
    """A dedicated logger for Wireshark-related messages (packet capture)."""
    message_signal = pyqtSignal(str)

    def log_message(self, msg): self.message_signal.emit(str(msg).rstrip())


class PacketLogger(QObject):
    """A dedicated logger for packet sending operations (Scapy)."""
    message_signal = pyqtSignal(str)

    def log_message(self, msg): self.message_signal.emit(str(msg).rstrip())

class RouterLogger(QObject):
    message_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def log_message(self, msg):
        self.message_signal.emit(str(msg).rstrip())
class GeminiLogger(QObject):
    """A dedicated logger for Gemini chat messages."""
    message_signal = pyqtSignal(str, str)  # Now emits content and message_type

    def log_message(self, msg: str, message_type: str = "info"):
        self.message_signal.emit(msg.rstrip(), message_type)

class NmapLogger(QObject):
    """A dedicated logger for Gemini chat messages."""
    message_signal = pyqtSignal(str, str)  # Now emits content and message_type

    def log_message(self, msg: str, message_type: str = "info"):
        self.message_signal.emit(msg.rstrip(), message_type)

class GobusterLogger(QObject): # NEW: Gobuster Logger
    message_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def log_message(self, msg: str):
        self.message_signal.emit(msg)
class ScrapingLogger(QObject): # NEW: Gobuster Logger
    message_signal = pyqtSignal(str)

    def __init__(self):
        super().__init__()

    def log_message(self, msg: str):
        self.message_signal.emit(msg)


class P2PoolGUI(QMainWindow):
    # Signals to trigger the worker thread's slots
    trigger_send_ping = pyqtSignal(str, str, str, int)
    trigger_send_tcp_syn = pyqtSignal(str, int, str, str, int)
    trigger_send_udp_packet = pyqtSignal(str, int, bytes, str, str, int)
    trigger_send_dns_query = pyqtSignal(str, str, str, str, str, int)

    def __init__(self, gui_logger, wireshark_logger, packet_logger, router_logger, gemini_logger, nmap_logger, gobuster_logger, scraping_logger,
                 application_main_loop, p2pool_helper, parent=None):
        super().__init__(parent)
        # --- Core Components ---
        self.gui_logger = gui_logger
        self.wireshark_logger = wireshark_logger
        self.packet_logger = packet_logger
        self.router_logger = router_logger
        self.gemini_logger = gemini_logger
        self.nmap_logger = nmap_logger
        self.gobuster_logger = gobuster_logger # Store gobuster_logger
        self.scraping_logger = scraping_logger

        self.ollama_logger = OllamaLogger()
        self.helper = p2pool_helper
        self.packet_manager = self.helper.packet_manager
        self.application_main_loop = application_main_loop

        # --- Threading and Workers ---
        self.main_worker_stop_event = None
        self.background_thread = None
        self.async_worker = None

        # New packet sending infrastructure
        self.packet_request_queue = queue.Queue()
        self.packet_sender_qthread = None
        self.packet_sender_worker = None
        self.packet_sending_thread = None

        # --- UI Setup ---
        self.setWindowTitle("Nate's Server")
        self.setGeometry(100, 100, 1000, 700)
        self.setStyleSheet(DARK_STYLESHEET)
        self._start_main_application_worker()
        self.create_tabs()
        self.connect_signals()

        # --- Start Services ---
        self._start_packet_sender_system()
        self.on_services_started()

        # --- Initial Log Messages ---
        self.gui_logger.log_message("[GUI] P2Pool Log Initialized.")
        self.wireshark_logger.log_message("[GUI] Wireshark Log Initialized.")
        self.packet_logger.log_message("[GUI] Packet Sender Log Initialized.")
        self.router_logger.log_message("[GUI] Router Log Initialized.")
        self.gemini_logger.log_message("<b>[GUI]</b> Gemini Chat Log Initialized.")
        self.nmap_logger.log_message("[GUI] Nmap Log Initialized.")
        self.gobuster_logger.log_message("[GUI] Gobuster Log Initialized.") # Initial message for Gobuster tab

        local_ip = self.helper.get_local_ip()
        public_ip_at_start = self.helper.get_public_ip()
        port = 5000

        self.gui_logger.log_message("=======================================================================")
        self.gui_logger.log_message(f"[*] Dashboard running. Access it at:")
        self.gui_logger.log_message(f"    - On this machine: http://127.0.0.1:{port}")
        self.gui_logger.log_message(f"    - On your local network: http://{local_ip}:{port}")
        if public_ip_at_start:
            self.gui_logger.log_message(f"    - On the internet (if port forwarded): http://{public_ip_at_start}:{port}")
        self.gui_logger.log_message("=======================================================================")
        self.gui_logger.log_message("[+] Background services are running. Use the GUI to start P2Pool.")

        self.gui_logger.log_message("[GUI] Main application background thread started.")

    def _start_main_application_worker(self):
        """Initializes and starts the background worker for the main asyncio loop."""
        self.background_thread = QThread()
        self.main_worker_stop_event = threading.Event()

        self.async_worker = AsyncWorker(self.main_worker_stop_event, self.application_main_loop)
        self.async_worker.moveToThread(self.background_thread)

        self.background_thread.started.connect(self.async_worker.run)
        self.async_worker.finished.connect(self.background_thread.quit)
        self.async_worker.finished.connect(self.async_worker.deleteLater)
        self.background_thread.finished.connect(self.background_thread.deleteLater)

        self.background_thread.start()

    def create_tabs(self):
        """Creates the main tab widget and adds the modular tab widgets."""
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.p2pool_tab = P2PoolTab(self.helper)
        self.wireshark_tab = WiresharkTab()
        self.packet_sender_tab = PacketSenderTab()
        self.router_tab = RouterTab(self.router_logger)
        self.gemini_chat_tab = GeminiChatTab(self.gemini_logger)
        self.nmap_tab = NmapTab(self.nmap_logger, self.async_worker.loop)
        self.gobuster_tab = GobusterTab(self.gobuster_logger, self.async_worker.loop)
        self.scraping_tab = ScrapingTab(self.scraping_logger, self.async_worker.loop)
        self.ollama_model_tab = OllamaModelTab(
            self.ollama_logger,
            router_provider=lambda: self.helper.router_manager,
        )

        self.tabs.addTab(self.p2pool_tab, "P2Pool")
        self.tabs.addTab(self.wireshark_tab, "Wireshark Capture")
        self.tabs.addTab(self.packet_sender_tab, "Send Packets")
        self.tabs.addTab(self.router_tab, "Router")
        self.tabs.addTab(self.gemini_chat_tab, "Gemini Chat")
        self.tabs.addTab(self.nmap_tab, "Nmap Scan")
        self.tabs.addTab(self.gobuster_tab, "Gobuster Scan")
        self.tabs.addTab(self.scraping_tab, "Scraping")
        self.tabs.addTab(self.ollama_model_tab, "Ollama Model")

    def connect_signals(self):
        """Connects signals from UI elements to backend logic."""
        self.gui_logger.message_signal.connect(self.p2pool_tab.log_message) # General console messages to P2Pool tab (or a dedicated general console tab)
        self.wireshark_logger.message_signal.connect(self.wireshark_tab.log_message)
        self.packet_logger.message_signal.connect(self.packet_sender_tab.log_message)
        self.gemini_logger.message_signal.connect(self.gemini_chat_tab.log_message)
        self.nmap_logger.message_signal.connect(self.nmap_tab.log_message)
        self.gobuster_logger.message_signal.connect(self.gobuster_tab.log_message) # Connect Gobuster logger to its tab's log
        self.scraping_logger.message_signal.connect(self.scraping_tab.log_message)
        self.ollama_logger.message_signal.connect(self.ollama_model_tab.log_message)
        self.p2pool_tab.start_p2pool_button.clicked.connect(self.start_p2pool)
        self.p2pool_tab.stop_p2pool_button.clicked.connect(self.stop_p2pool)

        self.wireshark_tab.start_wireshark_button.clicked.connect(self.start_wireshark)
        self.wireshark_tab.stop_wireshark_button.clicked.connect(self.stop_wireshark)

        self.router_tab.start_router_button.clicked.connect(self.start_router)
        self.router_tab.stop_router_button.clicked.connect(self.stop_router)

        self.packet_sender_tab.send_ping_requested.connect(self.trigger_send_ping)
        self.packet_sender_tab.send_tcp_syn_requested.connect(self.trigger_send_tcp_syn)
        self.packet_sender_tab.send_udp_requested.connect(self.trigger_send_udp_packet)
        self.packet_sender_tab.send_dns_requested.connect(self.trigger_send_dns_query)
        self.packet_sender_tab.populate_interfaces(self.packet_manager.get_interfaces())


    def _start_packet_sender_system(self):
        """Initializes and starts the entire packet sending system."""
        self.packet_sending_thread = PacketSendingThread(self.packet_request_queue, self.packet_manager,
                                                         self.packet_logger)
        self.packet_sending_thread.start()

        self.packet_sender_qthread = QThread()
        self.packet_sender_worker = PacketSenderWorker(self.packet_request_queue)
        self.packet_sender_worker.moveToThread(self.packet_sender_qthread)

        self.trigger_send_ping.connect(self.packet_sender_worker.do_send_ping)
        self.trigger_send_tcp_syn.connect(self.packet_sender_worker.do_send_tcp_syn)
        self.trigger_send_udp_packet.connect(self.packet_sender_worker.do_send_udp_packet)
        self.trigger_send_dns_query.connect(self.packet_sender_worker.do_send_dns_query)

        self.packet_sender_qthread.start()

    def on_services_started(self):
        """
        Enables UI controls after checking for necessary privileges.
        Allows a safe non-admin test mode for PacketManager / router-injection testing.
        """
        self.p2pool_tab.start_p2pool_button.setEnabled(True)
        self.wireshark_tab.start_wireshark_button.setEnabled(True)
        self.router_tab.start_router_button.setEnabled(True)

        packet_manager = self.packet_manager

        # Explicit opt-in test mode
        non_admin_test_mode = bool(
            os.environ.get("P2POOL_ALLOW_NONADMIN_PACKET_TESTS", "").strip() == "1"
        )

        router_injection_available = bool(
            getattr(packet_manager, "router", None) is not None
            and hasattr(packet_manager.router, "process_packet")
        )

        allow_packet_tab = is_admin() or non_admin_test_mode or router_injection_available

        if allow_packet_tab:
            self.packet_sender_tab.send_ping_button.setEnabled(True)
            self.packet_sender_tab.send_tcp_button.setEnabled(True)
            self.packet_sender_tab.send_udp_button.setEnabled(True)
            self.packet_sender_tab.send_dns_button.setEnabled(True)

            if is_admin():
                self.packet_logger.log_message(
                    "[+] Running with Administrator privileges. Packet sender enabled."
                )
            elif router_injection_available:
                self.packet_logger.log_message(
                    "[TEST] Non-admin router-injection mode enabled. "
                    "Packets will be tested through packet_manager.router.process_packet(...) when possible."
                )
            else:
                self.packet_logger.log_message(
                    "[TEST] Non-admin packet test mode enabled. "
                    "Direct raw sends may still fail; use this for UI/queue/PacketManager testing."
                )
        else:
            self.packet_logger.log_message("=" * 60)
            self.packet_logger.log_message("WARNING: Application not running as Administrator.")
            self.packet_logger.log_message(
                "Packet sending functionality has been disabled to prevent crashes."
            )
            self.packet_logger.log_message(
                "Set P2POOL_ALLOW_NONADMIN_PACKET_TESTS=1 for test mode, "
                "or run as Administrator for real direct sends."
            )
            self.packet_logger.log_message("=" * 60)

            self.packet_sender_tab.send_ping_button.setEnabled(False)
            self.packet_sender_tab.send_tcp_button.setEnabled(False)
            self.packet_sender_tab.send_udp_button.setEnabled(False)
            self.packet_sender_tab.send_dns_button.setEnabled(False)

    def start_p2pool(self):
        self.gui_logger.log_message("[GUI] Requesting to start P2Pool...")
        if self.helper.asyncio_main_loop and self.helper.processor:
            asyncio.run_coroutine_threadsafe(self.helper.processor.start_p2pool(), self.helper.asyncio_main_loop)
            self.p2pool_tab.start_p2pool_button.setEnabled(False)
            self.p2pool_tab.stop_p2pool_button.setEnabled(True)
        else:
            self.gui_logger.log_message("[GUI] P2Pool service is not ready.")

    def stop_p2pool(self):
        self.gui_logger.log_message("[GUI] Requesting to stop P2Pool...")
        if self.helper.asyncio_main_loop and self.helper.processor:
            asyncio.run_coroutine_threadsafe(self.helper.processor.stop_p2pool(), self.helper.asyncio_main_loop)
            self.p2pool_tab.start_p2pool_button.setEnabled(True)
            self.p2pool_tab.stop_p2pool_button.setEnabled(False)
        else:
            self.gui_logger.log_message("[GUI] P2Pool service is not ready.")

    def start_wireshark(self):
        self.wireshark_logger.log_message("[GUI] Requesting to start Wireshark capture...")
        if self.helper.wireshark_manager:
            if self.helper.wireshark_manager.start_capture(main_interface_name='Wi-Fi', router_manager=self.helper.router_manager):
                self.wireshark_tab.start_wireshark_button.setEnabled(False)
                self.wireshark_tab.stop_wireshark_button.setEnabled(True)
            else:
                self.wireshark_logger.log_message("[GUI] Failed to start Wireshark capture.")
        else:
            self.wireshark_logger.log_message("[GUI] Wireshark manager not available.")

    def stop_wireshark(self):
        self.wireshark_logger.log_message("[GUI] Requesting to stop Wireshark capture...")
        if self.helper.wireshark_manager:
            self.helper.wireshark_manager.stop_capture()
            self.wireshark_tab.start_wireshark_button.setEnabled(True)
            self.wireshark_tab.stop_wireshark_button.setEnabled(False)
        else:
            self.wireshark_logger.log_message("[GUI] Wireshark manager not available.")

    @staticmethod
    def _csv_setting(value: str) -> list[str]:
        return [
            item.strip()
            for item in str(value or "").split(",")
            if item.strip()
        ]

    @staticmethod
    def _validated_ip_list(
        values,
        label: str,
        *,
        version: int | None = None,
    ) -> list[str]:
        import ipaddress

        validated = []
        for value in values or []:
            try:
                parsed = ipaddress.ip_address(str(value).strip())
            except Exception as exc:
                raise ValueError(
                    f"{label} contains an invalid address: {value}"
                ) from exc
            if version is not None and parsed.version != version:
                raise ValueError(
                    f"{label} requires IPv{version} addresses: {value}"
                )
            validated.append(str(parsed))
        return validated

    @staticmethod
    def _int_setting(
        value,
        label: str,
        *,
        minimum: int | None = None,
        maximum: int | None = None,
        allow_blank: bool = False,
    ):
        raw = str(value or "").strip()
        if not raw and allow_blank:
            return None
        if not raw:
            raise ValueError(f"{label} is required.")
        try:
            parsed = int(raw)
        except Exception as exc:
            raise ValueError(f"{label} must be a whole number.") from exc
        if minimum is not None and parsed < minimum:
            raise ValueError(f"{label} must be at least {minimum}.")
        if maximum is not None and parsed > maximum:
            raise ValueError(f"{label} must be at most {maximum}.")
        return parsed

    @classmethod
    def _port_list_setting(
        cls,
        value,
        label: str,
    ) -> list[int]:
        ports = []
        for item in cls._csv_setting(value):
            ports.append(
                cls._int_setting(
                    item,
                    label,
                    minimum=1,
                    maximum=65535,
                )
            )
        if not ports:
            raise ValueError(
                f"{label} requires at least one port."
            )
        return sorted(set(ports))

    @staticmethod
    def _float_setting(
        value,
        label: str,
        *,
        minimum: float | None = None,
    ) -> float:
        raw = str(value or "").strip()
        if not raw:
            raise ValueError(f"{label} is required.")
        try:
            parsed = float(raw)
        except Exception as exc:
            raise ValueError(f"{label} must be numeric.") from exc
        if minimum is not None and parsed < minimum:
            raise ValueError(f"{label} must be at least {minimum}.")
        return parsed

    @staticmethod
    def _validate_ipv4_scope(
        *,
        label: str,
        pool_start: str,
        pool_end: str,
        router_ip: str = "",
        netmask: str = "",
        enforce_same_subnet: bool = True,
    ) -> None:
        import ipaddress

        if not pool_start or not pool_end:
            raise ValueError(
                f"{label} pool start and pool end are both required."
            )

        try:
            start = ipaddress.IPv4Address(pool_start)
            end = ipaddress.IPv4Address(pool_end)
        except Exception as exc:
            raise ValueError(
                f"{label} pool contains an invalid IPv4 address."
            ) from exc

        if start > end:
            raise ValueError(
                f"{label} pool start must not be after pool end."
            )

        if router_ip and netmask and enforce_same_subnet:
            try:
                router_address = ipaddress.IPv4Address(router_ip)
                network = ipaddress.IPv4Network(
                    f"{router_address}/{netmask}",
                    strict=False,
                )
            except Exception as exc:
                raise ValueError(
                    f"{label} router IP or netmask is invalid."
                ) from exc

            if start not in network or end not in network:
                raise ValueError(
                    f"{label} pool must be inside {network}."
                )
            if start <= router_address <= end:
                raise ValueError(
                    f"{label} pool must not include router address "
                    f"{router_address}."
                )

    def start_router(self):
        self.router_logger.log_message("[GUI] Requesting to start Router...")

        if not self.helper.router_manager:
            self.router_logger.log_message("[GUI] Router manager not available.")
            return

        tab = self.router_tab

        try:
            ipc_emit_host = tab.ipc_host_input.text().strip()
            p2pool_server_ip = tab.p2pool_server_ip_input.text().strip()

            use_stratum_comm = tab.stratum_comm_checkbox.isChecked()
            use_blocknet = tab.blocknet_checkbox.isChecked()
            use_peer_to_peer = tab.peer_to_peer_checkbox.isChecked()

            use_dhcp_out = tab.dhcp_out_checkbox.isChecked()
            use_dhcp_in = tab.dhcp_in_checkbox.isChecked()
            use_static = tab.use_static_checkbox.isChecked()
            use_hyperv = tab.use_hyperv_checkbox.isChecked()
            use_netroute = tab.use_netroute_checkbox.isChecked()
            router_ip_out = tab.router_ip_out_input.text().strip()
            netmask_out = tab.router_netmask_out_input.text().strip()
            router_ip_in = tab.router_ip_in_input.text().strip()
            netmask_in = tab.router_netmask_in_input.text().strip()
            use_hostbypass = tab.use_hostbypass_checkbox.isChecked()
            blocknet_relay = tab.blocknet_relay_input.text().strip()
            blocknet_token = tab.blocknet_token_input.text().strip()
            use_gateway = tab.use_gateway_checkbox.isChecked()
            use_lan = tab.use_lan_checkbox.isChecked()
            use_uplink = tab.use_uplink_checkbox.isChecked()
            nat_os = tab.nat_os_checkbox.isChecked()
            python_server = tab.python_server_checkbox.isChecked()
            promisc = tab.promisc_checkbox.isChecked()
            use_socket = tab.use_socket.isChecked()
            use_ollama = tab.ollama_checkbox.isChecked()
            use_scrapewebsite = (
                tab.use_scrapewebsite_checkbox.isChecked()
            )
            scrapewebsite_endpoint = (
                tab.scrapewebsite_endpoint_input.text().strip()
            )

            if use_blocknet and not blocknet_relay:
                raise ValueError(
                    "BlockNet is enabled but BlockNet Relay is empty."
                )

            import ipaddress

            for value, label in (
                (router_ip_out, "Router WAN IP"),
                (router_ip_in, "Router LAN IP"),
            ):
                if value:
                    try:
                        ipaddress.IPv4Address(value)
                    except Exception as exc:
                        raise ValueError(
                            f"{label} is not a valid IPv4 address."
                        ) from exc

            for address, mask, label in (
                (
                    router_ip_out,
                    netmask_out,
                    "Router WAN netmask",
                ),
                (
                    router_ip_in,
                    netmask_in,
                    "Router LAN netmask",
                ),
            ):
                if address:
                    try:
                        ipaddress.IPv4Network(
                            f"{address}/{mask}",
                            strict=False,
                        )
                    except Exception as exc:
                        raise ValueError(
                            f"{label} is invalid."
                        ) from exc

            # ---------------- Stratum ----------------
            stratum_mode = (
                "daemon"
                if tab.stratum_mode_dropdown.currentText()
                == "Local Monero Daemon"
                else "pool"
            )
            stratum_pool_port = 3333
            stratum_proxy_port = 3334
            stratum_wallet = tab.stratum_wallet_input.text().strip()
            stratum_password = tab.stratum_password_input.text()
            stratum_worker = (
                tab.stratum_worker_input.text().strip()
                or "PythonProxy"
            )
            stratum_use_tls = {
                "Enabled": True,
                "Disabled": False,
            }.get(
                tab.stratum_tls_dropdown.currentText(),
                "auto",
            )
            stratum_tls_hostname = (
                tab.stratum_sni_input.text().strip() or None
            )
            stratum_enable_proxy = (
                tab.stratum_proxy_checkbox.isChecked()
            )
            stratum_proxy_host = (
                tab.stratum_proxy_host_input.text().strip()
                or "127.0.0.1"
            )
            stratum_user_agent = (
                tab.stratum_user_agent_input.text().strip()
                or "pystratum/0.5"
            )
            stratum_daemon_url = (
                tab.stratum_daemon_url_input.text().strip()
            )
            stratum_zmq_address = (
                tab.stratum_zmq_address_input.text().strip()
            )

            if use_stratum_comm:
                if not stratum_wallet:
                    raise ValueError(
                        "Stratum wallet/login is required."
                    )

                if stratum_mode == "pool":
                    if not p2pool_server_ip:
                        raise ValueError(
                            "Stratum pool host is required."
                        )
                    stratum_pool_port = self._int_setting(
                        tab.stratum_pool_port_input.text(),
                        "Stratum pool port",
                        minimum=1,
                        maximum=65535,
                    )
                    if stratum_enable_proxy:
                        stratum_proxy_port = self._int_setting(
                            tab.stratum_proxy_port_input.text(),
                            "Stratum proxy port",
                            minimum=1,
                            maximum=65535,
                        )

                        local_names = {
                            "127.0.0.1",
                            "localhost",
                            "::1",
                        }
                        if (
                            p2pool_server_ip.casefold()
                            in local_names
                            and stratum_proxy_host.casefold()
                            in local_names.union({"0.0.0.0", "::"})
                            and stratum_pool_port
                            == stratum_proxy_port
                        ):
                            raise ValueError(
                                "The local Stratum proxy port must differ "
                                "from the local upstream pool port."
                            )
                elif not stratum_daemon_url or not stratum_zmq_address:
                    raise ValueError(
                        "Daemon RPC URL and ZMQ address are required "
                        "for Local Monero Daemon mode."
                    )

            # ---------------- DHCP ----------------
            enable_dhcp_server = tab.dhcp_server_checkbox.isChecked()
            serve_dhcp_on_wan = (
                tab.serve_dhcp_on_wan_checkbox.isChecked()
            )

            dhcp_server_settings = {}
            if enable_dhcp_server:
                dhcp_pool_start = (
                    tab.dhcp_pool_start_input.text().strip()
                )
                dhcp_pool_end = tab.dhcp_pool_end_input.text().strip()
                dhcp_enforce_subnet = (
                    tab.dhcp_enforce_subnet_checkbox.isChecked()
                )

                if bool(dhcp_pool_start) != bool(dhcp_pool_end):
                    raise ValueError(
                        "LAN DHCP pool start and end must both be "
                        "filled or both left blank for automatic sizing."
                    )
                if dhcp_pool_start and dhcp_pool_end:
                    self._validate_ipv4_scope(
                        label="LAN DHCP",
                        pool_start=dhcp_pool_start,
                        pool_end=dhcp_pool_end,
                        router_ip=router_ip_in,
                        netmask=netmask_in,
                        enforce_same_subnet=dhcp_enforce_subnet,
                    )

                dhcp_dns_v4 = self._validated_ip_list(
                    self._csv_setting(tab.dhcp_dns_input.text()),
                    "LAN DHCP DNS",
                    version=4,
                )
                dhcp_dns_v6 = self._validated_ip_list(
                    self._csv_setting(tab.dhcp_dns_v6_input.text()),
                    "LAN DHCP IPv6 DNS",
                    version=6,
                )
                dhcp_relay_target = (
                    tab.dhcp_relay_input.text().strip() or None
                )
                if dhcp_relay_target:
                    self._validated_ip_list(
                        [dhcp_relay_target],
                        "LAN DHCP relay",
                        version=4,
                    )
                dhcp6_relay_target = (
                    tab.dhcp6_relay_input.text().strip() or None
                )
                if dhcp6_relay_target:
                    self._validated_ip_list(
                        [dhcp6_relay_target],
                        "LAN DHCPv6 relay",
                        version=6,
                    )
                dhcp6_prefix = (
                    tab.dhcp6_prefix_input.text().strip() or None
                )
                if dhcp6_prefix:
                    try:
                        parsed_prefix = ipaddress.ip_network(
                            dhcp6_prefix,
                            strict=False,
                        )
                    except Exception as exc:
                        raise ValueError(
                            "LAN DHCPv6 prefix is invalid."
                        ) from exc
                    if parsed_prefix.version != 6:
                        raise ValueError(
                            "LAN DHCPv6 prefix must be IPv6."
                        )
                    dhcp6_prefix = str(parsed_prefix)

                dhcp_server_settings = {
                    "pool_start": dhcp_pool_start or None,
                    "pool_end": dhcp_pool_end or None,
                    "dns_v4": dhcp_dns_v4,
                    "domain_name": (
                        tab.dhcp_domain_input.text().strip()
                        or "lan.internal"
                    ),
                    "lease_duration_seconds": self._int_setting(
                        tab.dhcp_lease_seconds_input.text(),
                        "LAN DHCP lease seconds",
                        minimum=60,
                    ),
                    "max_leases": self._int_setting(
                        tab.dhcp_max_leases_input.text(),
                        "LAN DHCP max leases",
                        minimum=1,
                        allow_blank=True,
                    ),
                    "authoritative": (
                        tab.dhcp_authoritative_checkbox.isChecked()
                    ),
                    "allow_out_of_pool": (
                        tab.dhcp_allow_out_of_pool_checkbox.isChecked()
                    ),
                    "enforce_same_subnet": dhcp_enforce_subnet,
                    "rogue_policy": (
                        "nak_on_mismatch"
                        if tab.dhcp_rogue_policy_dropdown.currentText()
                        == "NAK on Mismatch"
                        else "log"
                    ),
                    "dhcp_relay_target_ip": dhcp_relay_target,
                    "dhcp6_prefix": dhcp6_prefix,
                    "dhcp6_relay_target_ip": dhcp6_relay_target,
                    "dns_v6": dhcp_dns_v6,
                    "search_domains": self._csv_setting(
                        tab.dhcp_search_domains_input.text()
                    ),
                }

            wan_dhcp_server_settings = {}
            if serve_dhcp_on_wan:
                wan_pool_start = (
                    tab.wan_dhcp_pool_start_input.text().strip()
                )
                wan_pool_end = (
                    tab.wan_dhcp_pool_end_input.text().strip()
                )
                wan_enforce_subnet = (
                    tab.wan_dhcp_enforce_subnet_checkbox.isChecked()
                )
                if not router_ip_out:
                    raise ValueError(
                        "Router WAN IP is required when WAN DHCP is enabled."
                    )
                self._validate_ipv4_scope(
                    label="WAN DHCP",
                    pool_start=wan_pool_start,
                    pool_end=wan_pool_end,
                    router_ip=router_ip_out,
                    netmask=netmask_out,
                    enforce_same_subnet=wan_enforce_subnet,
                )

                wan_dns_v4 = self._validated_ip_list(
                    self._csv_setting(
                        tab.wan_dhcp_dns_input.text()
                    ),
                    "WAN DHCP DNS",
                    version=4,
                )
                wan_relay_target = (
                    tab.wan_dhcp_relay_input.text().strip() or None
                )
                if wan_relay_target:
                    self._validated_ip_list(
                        [wan_relay_target],
                        "WAN DHCP relay",
                        version=4,
                    )

                wan_dhcp_server_settings = {
                    "pool_start": wan_pool_start,
                    "pool_end": wan_pool_end,
                    "dns_v4": wan_dns_v4,
                    "domain_name": (
                        tab.wan_dhcp_domain_input.text().strip()
                        or "wan.router"
                    ),
                    "lease_duration_seconds": self._int_setting(
                        tab.wan_dhcp_lease_seconds_input.text(),
                        "WAN DHCP lease seconds",
                        minimum=60,
                    ),
                    "max_leases": self._int_setting(
                        tab.wan_dhcp_max_leases_input.text(),
                        "WAN DHCP max leases",
                        minimum=1,
                        allow_blank=True,
                    ),
                    "authoritative": (
                        tab.wan_dhcp_authoritative_checkbox.isChecked()
                    ),
                    "allow_out_of_pool": (
                        tab.wan_dhcp_allow_out_of_pool_checkbox.isChecked()
                    ),
                    "enforce_same_subnet": wan_enforce_subnet,
                    "rogue_policy": (
                        "nak_on_mismatch"
                        if (
                            tab.wan_dhcp_rogue_policy_dropdown.currentText()
                            == "NAK on Mismatch"
                        )
                        else "log"
                    ),
                    "dhcp_relay_target_ip": wan_relay_target,
                }

                self.router_logger.log_message(
                    "[RouterTab][DHCP-WAN] ⚠️ WAN DHCP is enabled. "
                    f"Serving {wan_pool_start}-{wan_pool_end} only on "
                    "the selected WAN interface."
                )

            # ---------------- manager settings ----------------
            gateway_settings = {}
            if use_gateway:
                gateway_upstream_dns = self._validated_ip_list(
                    self._csv_setting(
                        tab.gateway_upstream_dns_input.text()
                    ),
                    "Gateway upstream DNS",
                )
                gateway_dns64_prefix = (
                    tab.gateway_dns64_prefix_input.text().strip()
                    or "64:ff9b::/96"
                )
                try:
                    parsed_dns64_prefix = ipaddress.ip_network(
                        gateway_dns64_prefix,
                        strict=False,
                    )
                except Exception as exc:
                    raise ValueError(
                        "Gateway DNS64 prefix is invalid."
                    ) from exc
                if parsed_dns64_prefix.version != 6:
                    raise ValueError(
                        "Gateway DNS64 prefix must be IPv6."
                    )
                gateway_settings = {
                    "health_interval_sec": self._float_setting(
                        tab.gateway_health_interval_input.text(),
                        "Gateway health interval",
                        minimum=0.5,
                    ),
                    "enable_dns64": (
                        tab.gateway_dns64_checkbox.isChecked()
                    ),
                    "dns64_prefix": str(parsed_dns64_prefix),
                    "upstream_dns": gateway_upstream_dns,
                    "repair_on_failure": (
                        tab.gateway_repair_checkbox.isChecked()
                    ),
                    "pin_gateway_arp": (
                        tab.gateway_pin_arp_checkbox.isChecked()
                    ),
                    "probe_budget_max_packets": self._int_setting(
                        tab.gateway_probe_budget_input.text(),
                        "Gateway probe budget",
                        minimum=1,
                    ),
                }

            lan_settings = {}
            if use_lan:
                lan_settings = {
                    "bridge_name": (
                        tab.lan_bridge_name_input.text().strip()
                        or "ManagedLANBridge"
                    ),
                    "create_bridge": (
                        tab.lan_create_bridge_checkbox.isChecked()
                    ),
                    "health_interval_sec": self._float_setting(
                        tab.lan_health_interval_input.text(),
                        "LAN health interval",
                        minimum=5.0,
                    ),
                    "handle_icmp": (
                        tab.lan_handle_icmp_checkbox.isChecked()
                    ),
                    "start_transport_dhcp_client": (
                        tab.lan_transport_dhcp_client_checkbox.isChecked()
                    ),
                }

            uplink_settings = {}
            if use_uplink:
                uplink_settings = {
                    "health_interval_sec": self._float_setting(
                        tab.uplink_health_interval_input.text(),
                        "Uplink health interval",
                        minimum=5.0,
                    ),
                    "preferred_iface_names": self._csv_setting(
                        tab.uplink_preferred_ifaces_input.text()
                    ) or ["Wi-Fi"],
                    "allow_router_failover": (
                        tab.uplink_allow_failover_checkbox.isChecked()
                    ),
                    "preserve_wifi_link": (
                        tab.uplink_preserve_wifi_checkbox.isChecked()
                    ),
                    "minimum_public_score_to_activate": (
                        self._float_setting(
                            tab.uplink_min_score_input.text(),
                            "Uplink minimum public score",
                            minimum=0.0,
                        )
                    ),
                }

            python_server_settings = {}
            if python_server:
                python_server_settings = {
                    "host": (
                        tab.python_server_host_input.text().strip()
                        or "0.0.0.0"
                    ),
                    "port": self._int_setting(
                        tab.python_server_port_input.text(),
                        "Python server port",
                        minimum=1,
                        maximum=65535,
                    ),
                    "dashboard_title": (
                        tab.python_server_title_input.text().strip()
                        or "Router Dashboard"
                    ),
                    "max_packets": self._int_setting(
                        tab.python_server_max_packets_input.text(),
                        "Python server max packets",
                        minimum=100,
                    ),
                    "max_logs": self._int_setting(
                        tab.python_server_max_logs_input.text(),
                        "Python server max logs",
                        minimum=100,
                    ),
                    "max_events": self._int_setting(
                        tab.python_server_max_events_input.text(),
                        "Python server max events",
                        minimum=200,
                    ),
                    "store_raw_packets": (
                        tab.python_server_store_raw_checkbox.isChecked()
                    ),
                    "max_raw_packet_bytes": self._int_setting(
                        tab.python_server_max_raw_bytes_input.text(),
                        "Python server max raw packet bytes",
                        minimum=0,
                    ),
                }

            # ---------------- core packet managers ----------------
            packet_catcher_tcp_rate = self._float_setting(
                tab.packet_catcher_tcp_rate_input.text(),
                "Packet catcher TCP rate",
                minimum=0.0,
            )
            packet_catcher_udp_rate = self._float_setting(
                tab.packet_catcher_udp_rate_input.text(),
                "Packet catcher UDP rate",
                minimum=0.0,
            )
            packet_catcher_default_rate = self._float_setting(
                tab.packet_catcher_default_rate_input.text(),
                "Packet catcher default rate",
                minimum=0.0,
            )
            for rate_name, rate_value in (
                ("Packet catcher TCP rate", packet_catcher_tcp_rate),
                ("Packet catcher UDP rate", packet_catcher_udp_rate),
                (
                    "Packet catcher default rate",
                    packet_catcher_default_rate,
                ),
            ):
                if rate_value > 1.0:
                    raise ValueError(
                        f"{rate_name} must not exceed 1.0."
                    )

            manager_settings = {
                "enable_firewall": (
                    tab.core_firewall_checkbox.isChecked()
                ),
                "enable_packet_analyzer": (
                    tab.core_packet_analyzer_checkbox.isChecked()
                ),
                "enable_packet_catcher": (
                    tab.core_packet_catcher_checkbox.isChecked()
                ),
                "enable_handshake": (
                    tab.core_handshake_checkbox.isChecked()
                ),
                "enable_syn_scanner": (
                    tab.core_syn_scanner_checkbox.isChecked()
                ),
                "enable_igmp": (
                    tab.core_igmp_checkbox.isChecked()
                ),
                "enable_mdns": (
                    tab.core_mdns_checkbox.isChecked()
                ),
                "handshake_timeout_half_open": self._int_setting(
                    tab.handshake_half_open_timeout_input.text(),
                    "Handshake half-open timeout",
                    minimum=1,
                ),
                "handshake_timeout_established": self._int_setting(
                    tab.handshake_established_timeout_input.text(),
                    "Handshake established timeout",
                    minimum=1,
                ),
                "handshake_rate_limit_threshold": self._int_setting(
                    tab.handshake_rate_threshold_input.text(),
                    "Handshake rate threshold",
                    minimum=1,
                ),
                "handshake_rate_limit_period": self._int_setting(
                    tab.handshake_rate_period_input.text(),
                    "Handshake rate period",
                    minimum=1,
                ),
                "handshake_ban_duration": self._int_setting(
                    tab.handshake_ban_duration_input.text(),
                    "Handshake ban duration",
                    minimum=1,
                ),
                "handshake_log_tcp_lifecycle": (
                    tab.handshake_log_tcp_checkbox.isChecked()
                ),
                "handshake_log_non_tls_tcp": (
                    tab.handshake_log_non_tls_checkbox.isChecked()
                ),
                "handshake_log_tls_records": (
                    tab.handshake_log_tls_records_checkbox.isChecked()
                ),
                "handshake_log_application_data": (
                    tab.handshake_log_app_data_checkbox.isChecked()
                ),
                "handshake_log_tls13_key_events": (
                    tab.handshake_log_tls13_keys_checkbox.isChecked()
                ),
                "syn_scan_interval": self._int_setting(
                    tab.syn_scan_interval_input.text(),
                    "SYN scan interval",
                    minimum=1,
                ),
                "packet_catcher_tcp_rate": (
                    packet_catcher_tcp_rate
                ),
                "packet_catcher_udp_rate": (
                    packet_catcher_udp_rate
                ),
                "packet_catcher_default_rate": (
                    packet_catcher_default_rate
                ),
            }

            # ---------------- transport managers ----------------
            transport_settings = {
                "enabled": (
                    tab.transport_enabled_checkbox.isChecked()
                ),
                "protocol_enabled": {
                    key: checkbox.isChecked()
                    for key, checkbox
                    in tab.transport_protocol_checkboxes.items()
                },
                "stratum_ports": self._port_list_setting(
                    tab.transport_stratum_ports_input.text(),
                    "Transport Stratum ports",
                ),
                "monero_ports": self._port_list_setting(
                    tab.transport_monero_ports_input.text(),
                    "Transport Monero ports",
                ),
                "voip_port_start": self._int_setting(
                    tab.transport_voip_start_input.text(),
                    "Transport VoIP start port",
                    minimum=1,
                    maximum=65535,
                ),
                "voip_port_end": self._int_setting(
                    tab.transport_voip_end_input.text(),
                    "Transport VoIP end port",
                    minimum=1,
                    maximum=65535,
                ),
                "parallel_analysis": (
                    tab.transport_parallel_analysis_checkbox.isChecked()
                ),
                "inspection_log_rps": self._float_setting(
                    tab.transport_inspection_rps_input.text(),
                    "Inspection logs per second",
                    minimum=0.01,
                ),
                "inspection_log_burst": self._int_setting(
                    tab.transport_inspection_burst_input.text(),
                    "Inspection log burst",
                    minimum=1,
                ),
                "inspection_flow_cooldown_sec": self._float_setting(
                    tab.transport_inspection_cooldown_input.text(),
                    "Inspection flow cooldown",
                    minimum=0.0,
                ),
                "stratum_log_rps": self._float_setting(
                    tab.transport_stratum_rps_input.text(),
                    "Transport Stratum logs per second",
                    minimum=0.01,
                ),
                "stratum_log_burst": self._int_setting(
                    tab.transport_stratum_burst_input.text(),
                    "Transport Stratum log burst",
                    minimum=1,
                ),
                "stratum_flow_cooldown_sec": self._float_setting(
                    tab.transport_stratum_cooldown_input.text(),
                    "Transport Stratum cooldown",
                    minimum=0.0,
                ),
                "monero_log_rps": self._float_setting(
                    tab.transport_monero_rps_input.text(),
                    "Transport Monero logs per second",
                    minimum=0.01,
                ),
                "monero_log_burst": self._int_setting(
                    tab.transport_monero_burst_input.text(),
                    "Transport Monero log burst",
                    minimum=1,
                ),
                "monero_flow_cooldown_sec": self._float_setting(
                    tab.transport_monero_cooldown_input.text(),
                    "Transport Monero cooldown",
                    minimum=0.0,
                ),
                "dns_pending_ttl_sec": self._int_setting(
                    tab.transport_dns_pending_ttl_input.text(),
                    "Transport DNS pending TTL",
                    minimum=1,
                ),
                "dns_gc_interval_sec": self._int_setting(
                    tab.transport_dns_gc_interval_input.text(),
                    "Transport DNS GC interval",
                    minimum=1,
                ),
                "dns_alert_on_rebind": (
                    tab.transport_dns_rebind_alert_checkbox.isChecked()
                ),
                "dhcp_transaction_ttl_sec": self._int_setting(
                    tab.transport_dhcp_transaction_ttl_input.text(),
                    "Transport DHCP transaction TTL",
                    minimum=1,
                ),
                "dhcp_lease_ttl_sec": self._int_setting(
                    tab.transport_dhcp_lease_ttl_input.text(),
                    "Transport DHCP observed lease TTL",
                    minimum=60,
                ),
                "https_logging": (
                    tab.transport_https_logging_checkbox.isChecked()
                ),
                "https_parse_certificates": (
                    tab.transport_https_certificates_checkbox.isChecked()
                ),
                "https_parse_quic_crypto": (
                    tab.transport_https_quic_crypto_checkbox.isChecked()
                ),
            }
            if (
                    transport_settings["voip_port_start"]
                    > transport_settings["voip_port_end"]
            ):
                raise ValueError(
                    "Transport VoIP start port must not exceed "
                    "the end port."
                )

            # ---------------- Wi-Fi host ----------------
            use_wifi_host = tab.use_wifi_host_checkbox.isChecked()
            wifi_ssid = tab.wifi_ssid_input.text().strip()
            wifi_password = tab.wifi_password_input.text()
            wifi_settings = {}

            if use_wifi_host:
                if not wifi_ssid:
                    raise ValueError(
                        "Enter a wireless network name."
                    )
                ssid_length = len(wifi_ssid.encode("utf-8"))
                if not 1 <= ssid_length <= 32:
                    raise ValueError(
                        "The SSID must contain 1-32 UTF-8 bytes."
                    )
                if not 8 <= len(wifi_password) <= 63:
                    raise ValueError(
                        "The wireless password must contain "
                        "8-63 characters."
                    )

                wifi_router_ip = (
                    tab.wifi_router_ip_input.text().strip()
                )
                try:
                    ipaddress.IPv4Address(wifi_router_ip)
                except Exception as exc:
                    raise ValueError(
                        "Wireless router IP is invalid."
                    ) from exc

                wifi_settings = {
                    "hotspot_router_ip": wifi_router_ip,
                    "hotspot_prefix_length": self._int_setting(
                        tab.wifi_prefix_length_input.text(),
                        "Wireless prefix length",
                        minimum=1,
                        maximum=30,
                    ),
                    "auto_restart": (
                        tab.wifi_auto_restart_checkbox.isChecked()
                    ),
                    "start_timeout": self._float_setting(
                        tab.wifi_start_timeout_input.text(),
                        "Wireless start timeout",
                        minimum=5.0,
                    ),
                    "adapter_timeout": self._float_setting(
                        tab.wifi_adapter_timeout_input.text(),
                        "Wireless adapter timeout",
                        minimum=5.0,
                    ),
                }

                self.router_logger.log_message(
                    "[RouterTab][WiFi] 📶 Wireless hosting enabled for "
                    f"SSID '{wifi_ssid}'."
                )

        except ValueError as exc:
            self.router_logger.log_message(
                f"[RouterTab] ❌ Settings error: {exc}"
            )
            return
        except Exception as exc:
            self.router_logger.log_message(
                f"[RouterTab] ❌ Could not read settings: {exc}"
            )
            return

        try:
            self.helper.router_manager.start_routing(
                use_dhcp_out=use_dhcp_out,
                use_dhcp_in=use_dhcp_in,
                router_ip_out=router_ip_out,
                netmask_out=netmask_out,
                use_static=use_static,
                use_hyperv=use_hyperv,
                use_stratum_comm=use_stratum_comm,
                p2pool_server_ip=p2pool_server_ip,
                ipc_emit_host=ipc_emit_host,
                use_peer_to_peer=use_peer_to_peer,
                use_blocknet=use_blocknet,
                blocknet_relay=blocknet_relay,
                blocknet_token=blocknet_token,
                use_netroute=use_netroute,
                use_hostbypass=use_hostbypass,
                use_gateway=use_gateway,
                use_lan=use_lan,
                use_uplink=use_uplink,
                nat_os=nat_os,
                python_server=python_server,
                promisc=promisc,
                use_socket=use_socket,
                use_ollama=use_ollama,
                use_scrapewebsite=use_scrapewebsite,
                scrapewebsite_endpoint=scrapewebsite_endpoint,
                use_wifi_host=use_wifi_host,
                wifi_ssid=wifi_ssid,
                wifi_password=(
                    wifi_password
                    if use_wifi_host
                    else None
                ),
                wifi_executable_path=None,
                router_ip_in=router_ip_in or None,
                netmask_in=netmask_in,
                enable_dhcp_server=enable_dhcp_server,
                serve_dhcp_on_wan=serve_dhcp_on_wan,
                dhcp_server_settings=dhcp_server_settings,
                wan_dhcp_server_settings=wan_dhcp_server_settings,
                gateway_settings=gateway_settings,
                lan_settings=lan_settings,
                uplink_settings=uplink_settings,
                python_server_settings=python_server_settings,
                wifi_settings=wifi_settings,
                stratum_connection_mode=stratum_mode,
                stratum_pool_port=stratum_pool_port,
                stratum_wallet=stratum_wallet,
                stratum_password=stratum_password,
                stratum_worker=stratum_worker,
                stratum_proxy_host=stratum_proxy_host,
                stratum_proxy_port=stratum_proxy_port,
                stratum_enable_proxy=stratum_enable_proxy,
                stratum_use_tls=stratum_use_tls,
                stratum_tls_hostname=stratum_tls_hostname,
                stratum_user_agent=stratum_user_agent,
                stratum_daemon_url=stratum_daemon_url,
                stratum_zmq_address=stratum_zmq_address,
                manager_settings=manager_settings,
                transport_settings=transport_settings,
            )
        except Exception as e:
            self.router_logger.log_message(
                f"[RouterTab] ❌ Exception during router start: {e}"
            )
            return

        if not getattr(self.helper.router_manager, "started", False):
            self.router_logger.log_message(
                "[RouterTab] ❌ Router startup did not complete. "
                "Review the Router log for the failing manager."
            )
            return

        self._active_router_stop_flags = {
            "use_stratum_comm": use_stratum_comm,
            "use_dhcp_out": use_dhcp_out,
            "use_dhcp_in": use_dhcp_in,
            "use_static": use_static,
            "use_hyperv": use_hyperv,
            "use_netroute": use_netroute,
            "nat_os": nat_os,
            "use_ollama": use_ollama,
        }
        self.router_tab.start_router_button.setEnabled(False)
        self.router_tab.stop_router_button.setEnabled(True)

    def stop_router(self):
        self.router_logger.log_message("[GUI] Requesting to stop Router...")

        if not self.helper.router_manager:
            self.router_logger.log_message("[GUI] Router manager not available.")
            return

        # Prevent double-stop clicks immediately
        self.router_tab.stop_router_button.setEnabled(False)

        try:
            active_flags = getattr(
                self,
                "_active_router_stop_flags",
                {},
            )
            use_stratum_comm = active_flags.get(
                "use_stratum_comm",
                self.router_tab.stratum_comm_checkbox.isChecked(),
            )
            use_dhcp_out = active_flags.get(
                "use_dhcp_out",
                self.router_tab.dhcp_out_checkbox.isChecked(),
            )
            use_dhcp_in = active_flags.get(
                "use_dhcp_in",
                self.router_tab.dhcp_in_checkbox.isChecked(),
            )
            use_static = active_flags.get(
                "use_static",
                self.router_tab.use_static_checkbox.isChecked(),
            )
            use_hyperv = active_flags.get(
                "use_hyperv",
                self.router_tab.use_hyperv_checkbox.isChecked(),
            )
            use_netroute = active_flags.get(
                "use_netroute",
                self.router_tab.use_netroute_checkbox.isChecked(),
            )
            nat_os = active_flags.get(
                "nat_os",
                self.router_tab.nat_os_checkbox.isChecked(),
            )
            self.router_logger.log_message(
                f"[GUI] stop_router flags: "
                f"stratum={use_stratum_comm}, "
                f"dhcp_out={use_dhcp_out}, "
                f"dhcp_in={use_dhcp_in}, "
                f"static={use_static}, "
                f"hyperv={use_hyperv}"
            )
            use_ollama = active_flags.get(
                "use_ollama",
                self.router_tab.ollama_checkbox.isChecked(),
            )
            self.helper.router_manager.stop_routing(
                use_dhcp_out,
                use_dhcp_in,
                use_static,
                use_hyperv,
                use_stratum_comm,
                use_netroute,
                nat_os,
                use_ollama,
            )

            self.router_tab.start_router_button.setEnabled(True)
            self.router_tab.stop_router_button.setEnabled(False)
            self._active_router_stop_flags = {}

        except Exception as e:
            self.router_logger.log_message(f"[GUI] Exception during router stop: {e}")
            self.router_tab.stop_router_button.setEnabled(True)

    def closeEvent(self, event):
        """Ensures all worker threads are cleanly shut down on application exit."""
        self.gui_logger.log_message("[GUI] Closing. Signaling all services to shut down...")
        try:
            if getattr(self, "router_tab", None):
                self.router_tab.shutdown_logging()
        except Exception:
            pass
        # 1. Signal the main application's async loop to stop
        if self.main_worker_stop_event:
            self.main_worker_stop_event.set()
            self.gui_logger.log_message("[GUI] Main application stop event signaled.")

        # 2. Stop Packet Sending System threads
        if self.packet_sending_thread and self.packet_sending_thread.is_alive():
            self.packet_request_queue.put((None, None))  # Send sentinel to stop the blocking thread
            self.packet_sending_thread.join(timeout=5)
            if self.packet_sending_thread.is_alive():
                self.gui_logger.log_message("[GUI] Packet sending thread did not terminate gracefully.")
        if self.packet_sender_qthread and self.packet_sender_qthread.isRunning():
            self.packet_sender_qthread.quit()
            self.packet_sender_qthread.wait(5000)
            if self.packet_sender_qthread.isRunning():
                self.gui_logger.log_message("[GUI] Packet sender QThread did not terminate gracefully.")

        # 3. Stop Gemini Chat worker thread
        if self.gemini_chat_tab.worker_thread and self.gemini_chat_tab.worker_thread.isRunning():
            self.gemini_chat_tab.worker_thread.quit()
            self.gemini_chat_tab.worker_thread.wait(5000)
            if self.gemini_chat_tab.worker_thread.isRunning():
                self.gui_logger.log_message("[GUI] Gemini Chat worker thread did not terminate gracefully.")

        # 4. Stop Nmap scan if running
        if self.nmap_tab and self.nmap_tab.nmap_manager:
            self.nmap_tab.nmap_manager.stop_scan()
            self.gui_logger.log_message("[GUI] Nmap scan stop requested.")

        # 5. Stop Gobuster scan if running
        if self.gobuster_tab and self.gobuster_tab.gobuster_manager:
            self.gobuster_tab.gobuster_manager.stop_scan()
            self.gui_logger.log_message("[GUI] Gobuster scan stop requested.")

        if self.scraping_tab and self.scraping_tab.scraping_manager:
            self.scraping_tab.scraping_manager.stop_scrape()
            self.gui_logger.log_message("[GUI] Scraping scan stop requested.")

        # 6. Wait for the main background thread (AsyncWorker) to finish
        if self.background_thread and self.background_thread.isRunning():
            self.background_thread.wait(5000)
            if self.background_thread.isRunning():
                self.gui_logger.log_message("[GUI] Main application background thread did not terminate gracefully.")

        try:
            if getattr(self, "ollama_model_tab", None):
                self.ollama_model_tab.shutdown()
        except Exception as e:
            self.gui_logger.log_message(f"[GUI] Ollama tab shutdown error: {e}")

        self.gui_logger.log_message("[GUI] All GUI-managed threads cleanup attempted.")
        event.accept()


