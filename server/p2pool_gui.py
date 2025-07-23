import ctypes
import queue
import threading
import asyncio
from PyQt5.QtWidgets import QMainWindow, QTabWidget
from PyQt5.QtCore import QObject, pyqtSignal, QThread
from p2pool_gui_elements import P2PoolTab, WiresharkTab, RouterTab, PacketSenderTab, AsyncWorker, PacketSendingThread, \
    PacketSenderWorker

def is_admin():
    """Checks if the script is running with administrator privileges on Windows."""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
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
    """A dedicated logger for PythonRouterManager operations."""
    message_signal = pyqtSignal(str)

    def log_message(self, msg): self.message_signal.emit(str(msg).rstrip())


class P2PoolGUI(QMainWindow):
    # Signals to trigger the worker thread's slots
    trigger_send_ping = pyqtSignal(str, str, str, int)
    trigger_send_tcp_syn = pyqtSignal(str, int, str, str, int)
    trigger_send_udp_packet = pyqtSignal(str, int, bytes, str, str, int)
    trigger_send_dns_query = pyqtSignal(str, str, str, str, str, int)

    def __init__(self, logger, wireshark_logger, packet_logger, router_logger, application_main_loop, p2pool_helper):
        super().__init__()
        # --- Core Components ---
        self.logger = logger
        self.wireshark_logger = wireshark_logger
        self.packet_logger = packet_logger
        self.router_logger = router_logger
        self.helper = p2pool_helper
        self.packet_manager = self.helper.packet_manager
        self.application_main_loop = application_main_loop

        # --- Threading and Workers ---
        self.main_worker_stop_event = None
        self.background_thread = None
        self.async_worker = None

        # New packet sending infrastructure
        self.packet_request_queue = queue.Queue()
        self.packet_sender_qthread = None  # QThread for the bridge worker
        self.packet_sender_worker = None  # The QObject bridge
        self.packet_sending_thread = None  # The dedicated sending thread

        # --- UI Setup ---
        self.setWindowTitle("Nate's Server")
        self.setGeometry(100, 100, 1000, 700)
        self.setStyleSheet(DARK_STYLESHEET)
        self.create_tabs()
        self.connect_signals()

        # --- Start Services ---
        self._start_packet_sender_system()
        self._start_main_application_worker()  # Start the main backend logic
        self.on_services_started()

        # --- Initial Log Messages ---
        self.logger.log_message("[GUI] P2Pool Log Initialized.")
        self.wireshark_logger.log_message("[GUI] Wireshark Log Initialized.")
        self.packet_logger.log_message("[GUI] Packet Sender Log Initialized.")
        self.router_logger.log_message("[GUI] Router Log Initialized.")

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
        self.logger.log_message("[GUI] Main application background thread started.")

    def create_tabs(self):
        """Creates the main tab widget and adds the modular tab widgets."""
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)
        self.p2pool_tab = P2PoolTab()
        self.wireshark_tab = WiresharkTab()
        self.packet_sender_tab = PacketSenderTab()
        self.router_tab = RouterTab()
        self.tabs.addTab(self.p2pool_tab, "P2Pool")
        self.tabs.addTab(self.wireshark_tab, "Wireshark Capture")
        self.tabs.addTab(self.packet_sender_tab, "Send Packets")
        self.tabs.addTab(self.router_tab, "Router")

    def connect_signals(self):
        """Connects signals from UI elements to backend logic."""
        self.logger.message_signal.connect(self.p2pool_tab.log_message)
        self.wireshark_logger.message_signal.connect(self.wireshark_tab.log_message)
        self.packet_logger.message_signal.connect(self.packet_sender_tab.log_message)
        self.router_logger.message_signal.connect(self.router_tab.log_message)
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
        # 1. Start the dedicated thread that does the blocking work
        self.packet_sending_thread = PacketSendingThread(self.packet_request_queue, self.packet_manager,
                                                         self.packet_logger)
        self.packet_sending_thread.start()

        # 2. Start the QThread/QObject bridge that listens to GUI signals
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

        if is_admin():
            self.packet_logger.log_message("[+] Running with Administrator privileges. Packet sender enabled.")
            self.packet_sender_tab.send_ping_button.setEnabled(True)
            self.packet_sender_tab.send_tcp_button.setEnabled(True)
            self.packet_sender_tab.send_udp_button.setEnabled(True)
            self.packet_sender_tab.send_dns_button.setEnabled(True)
        else:
            self.packet_logger.log_message("=" * 60)
            self.packet_logger.log_message("WARNING: Application not running as Administrator.")
            self.packet_logger.log_message("Packet sending functionality has been disabled to prevent crashes.")
            self.packet_logger.log_message(
                "Please restart the application with 'Run as Administrator' to use this tab.")
            self.packet_logger.log_message("=" * 60)
            self.packet_sender_tab.send_ping_button.setEnabled(False)
            self.packet_sender_tab.send_tcp_button.setEnabled(False)
            self.packet_sender_tab.send_udp_button.setEnabled(False)
            self.packet_sender_tab.send_dns_button.setEnabled(False)

    def start_p2pool(self):
        self.logger.log_message("[GUI] Requesting to start P2Pool...")
        if self.helper.asyncio_main_loop and self.helper.processor:
            asyncio.run_coroutine_threadsafe(self.helper.processor.start_p2pool(), self.helper.asyncio_main_loop)
            self.p2pool_tab.start_p2pool_button.setEnabled(False)
            self.p2pool_tab.stop_p2pool_button.setEnabled(True)
        else:
            self.logger.log_message("[GUI] P2Pool service is not ready.")

    def stop_p2pool(self):
        self.logger.log_message("[GUI] Requesting to stop P2Pool...")
        if self.helper.asyncio_main_loop and self.helper.processor:
            asyncio.run_coroutine_threadsafe(self.helper.processor.stop_p2pool(), self.helper.asyncio_main_loop)
            self.p2pool_tab.start_p2pool_button.setEnabled(True)
            self.p2pool_tab.stop_p2pool_button.setEnabled(False)
        else:
            self.logger.log_message("[GUI] P2Pool service is not ready.")

    def start_wireshark(self):
        self.wireshark_logger.log_message("[GUI] Requesting to start Wireshark capture...")
        if self.helper.wireshark_manager:
            if self.helper.wireshark_manager.start_capture(main_interface_name='Wi-Fi'):
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
        if self.helper.router_manager:
            self.helper.router_manager.start_routing()
            self.router_tab.start_router_button.setEnabled(False)
            self.router_tab.stop_router_button.setEnabled(True)
        else:
            self.router_logger.log_message("[GUI] Router manager not available.")

    def stop_router(self):
        self.router_logger.log_message("[GUI] Requesting to stop Router...")
        if self.helper.router_manager:
            self.helper.router_manager.stop_routing()
            self.router_tab.start_router_button.setEnabled(True)
            self.router_tab.stop_router_button.setEnabled(False)
        else:
            self.router_logger.log_message("[GUI] Router manager not available.")

    def closeEvent(self, event):
        """Ensures all worker threads are cleaned up on exit."""
        self.logger.log_message("[GUI] Closing. Signaling all services to shut down...")

        # Stop main background worker
        if self.main_worker_stop_event:
            self.main_worker_stop_event.set()

        # Stop packet sending system
        if self.packet_sending_thread:
            self.packet_request_queue.put((None, None))  # Send sentinel to stop the thread
            self.packet_sending_thread.join(timeout=2)
        if self.packet_sender_qthread:
            self.packet_sender_qthread.quit()
            self.packet_sender_qthread.wait()

        # Wait for main background thread to finish
        if self.background_thread and self.background_thread.isRunning():
            self.background_thread.wait()

        event.accept()