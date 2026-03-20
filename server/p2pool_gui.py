import ctypes
import queue
import threading
import asyncio

from PyQt5.QtWidgets import QMainWindow, QTabWidget
from PyQt5.QtCore import QObject, pyqtSignal, QThread
from p2pool_gui_elements import P2PoolTab, WiresharkTab, RouterTab, PacketSenderTab, AsyncWorker, PacketSendingThread, \
    PacketSenderWorker, GeminiChatTab, NmapTab, GobusterTab, ScrapingTab


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
        self.tabs.addTab(self.p2pool_tab, "P2Pool")
        self.tabs.addTab(self.wireshark_tab, "Wireshark Capture")
        self.tabs.addTab(self.packet_sender_tab, "Send Packets")
        self.tabs.addTab(self.router_tab, "Router")
        self.tabs.addTab(self.gemini_chat_tab, "Gemini Chat")
        self.tabs.addTab(self.nmap_tab, "Nmap Scan")
        self.tabs.addTab(self.gobuster_tab, "Gobuster Scan")
        self.tabs.addTab(self.scraping_tab, "Scraping")

    def connect_signals(self):
        """Connects signals from UI elements to backend logic."""
        self.gui_logger.message_signal.connect(self.p2pool_tab.log_message) # General console messages to P2Pool tab (or a dedicated general console tab)
        self.wireshark_logger.message_signal.connect(self.wireshark_tab.log_message)
        self.packet_logger.message_signal.connect(self.packet_sender_tab.log_message)
        self.gemini_logger.message_signal.connect(self.gemini_chat_tab.log_message)
        self.nmap_logger.message_signal.connect(self.nmap_tab.log_message)
        self.gobuster_logger.message_signal.connect(self.gobuster_tab.log_message) # Connect Gobuster logger to its tab's log
        self.scraping_logger.message_signal.connect(self.scraping_tab.log_message)
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
        """
        self.p2pool_tab.start_p2pool_button.setEnabled(True)
        self.wireshark_tab.start_wireshark_button.setEnabled(True)
        self.router_tab.start_router_button.setEnabled(True)

        # Check for admin privileges for packet sending
        if is_admin():
            self.packet_logger.log_message("[+] Running with Administrator privileges. Packet sender enabled.")
            self.packet_sender_tab.send_ping_button.setEnabled(True)
            self.packet_sender_tab.send_tcp_button.setEnabled(True)
            self.packet_sender_tab.send_udp_button.setEnabled(True)
            self.packet_sender_tab.send_dns_button.setEnabled(True)
        else:
            self.packet_logger.log_message("=" * 60)
            self.packet_logger.log_message("WARNING: Application not running as Administrator.")
            self.packet_logger.log_message(
                "Packet sending functionality has been disabled to prevent crashes.")
            self.packet_logger.log_message(
                "Please restart the application with 'Run as Administrator' to use this tab.")
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

    def start_router(self):
        self.router_logger.log_message("[GUI] Requesting to start Router...")

        if not self.helper.router_manager:
            self.router_logger.log_message("[GUI] Router manager not available.")
            return

        ipc_emit_host = self.router_tab.ipc_host_input.text().strip()
        p2pool_server_ip = self.router_tab.p2pool_server_ip_input.text().strip()

        use_stratum_comm = self.router_tab.stratum_comm_checkbox.isChecked()
        use_blocknet = self.router_tab.blocknet_checkbox.isChecked()
        use_peer_to_peer = self.router_tab.peer_to_peer_checkbox.isChecked()

        use_dhcp_out = self.router_tab.dhcp_out_checkbox.isChecked()
        use_dhcp_in = self.router_tab.dhcp_in_checkbox.isChecked()
        use_static = self.router_tab.use_static_checkbox.isChecked()
        use_hyperv = self.router_tab.use_hyperv_checkbox.isChecked()
        use_netroute = self.router_tab.use_netroute_checkbox.isChecked()
        lan_ip = self.router_tab.router_ip_out_input.text().strip()
        netmask_out = self.router_tab.router_netmask_out_input.text().strip()

        blocknet_relay = self.router_tab.blocknet_relay_input.text().strip()
        blocknet_token = self.router_tab.blocknet_token_input.text().strip()

        if use_blocknet and not blocknet_relay:
            self.router_logger.log_message("[RouterTab] ❌ BlockNet enabled but BlockNet Relay is empty.")
            return

        try:
            self.helper.router_manager.start_routing(
                use_dhcp_out=use_dhcp_out,
                use_dhcp_in=use_dhcp_in,
                router_ip_out=lan_ip,
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
            )
        except Exception as e:
            self.router_logger.log_message(f"[RouterTab] ❌ Exception during router start: {e}")
            return

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
            use_stratum_comm = self.router_tab.stratum_comm_checkbox.isChecked()
            use_dhcp_out = self.router_tab.dhcp_out_checkbox.isChecked()
            use_dhcp_in = self.router_tab.dhcp_in_checkbox.isChecked()
            use_static = self.router_tab.use_static_checkbox.isChecked()
            use_hyperv = self.router_tab.use_hyperv_checkbox.isChecked()
            use_netroute = self.router_tab.use_netroute_checkbox.isChecked()

            self.router_logger.log_message(
                f"[GUI] stop_router flags: "
                f"stratum={use_stratum_comm}, "
                f"dhcp_out={use_dhcp_out}, "
                f"dhcp_in={use_dhcp_in}, "
                f"static={use_static}, "
                f"hyperv={use_hyperv}"
            )

            self.helper.router_manager.stop_routing(
                use_dhcp_out,
                use_dhcp_in,
                use_static,
                use_hyperv,
                use_stratum_comm,
                use_netroute,
            )

            self.router_tab.start_router_button.setEnabled(True)
            self.router_tab.stop_router_button.setEnabled(False)

        except Exception as e:
            self.router_logger.log_message(f"[GUI] Exception during router stop: {e}")
            self.router_tab.stop_router_button.setEnabled(True)

    def closeEvent(self, event):
        """Ensures all worker threads are cleanly shut down on application exit."""
        self.gui_logger.log_message("[GUI] Closing. Signaling all services to shut down...")

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


        self.gui_logger.log_message("[GUI] All GUI-managed threads cleanup attempted.")
        event.accept()
