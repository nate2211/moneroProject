import sys
import threading
import asyncio
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QPlainTextEdit, \
    QTabWidget, QLineEdit, QLabel, QComboBox, QGroupBox, QFormLayout
from PyQt5.QtCore import QObject, pyqtSignal, QThread, pyqtSlot

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
    #start_button, #start_wireshark_button, #start_router_button { /* Added #start_router_button */
        color: #a9f5a9;
    }
    #start_button:hover, #start_wireshark_button:hover, #start_router_button:hover { /* Added #start_router_button */
        background-color: #38761d;
    }
    #stop_button, #stop_wireshark_button, #stop_router_button { /* Added #stop_router_button */
        color: #ff9999;
    }
    #stop_button:hover, #stop_wireshark_button:hover, #stop_router_button:hover { /* Added #stop_router_button */
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


# NEW: RouterLogger class
class RouterLogger(QObject):
    """A dedicated logger for PythonRouterManager operations."""
    message_signal = pyqtSignal(str)

    def log_message(self, msg): self.message_signal.emit(str(msg).rstrip())


class AsyncWorker(QObject):
    finished = pyqtSignal()
    started = pyqtSignal()

    def __init__(self, stop_event, main_loop):
        super().__init__()
        self.stop_event = stop_event
        self.main_loop = main_loop

    def run(self):
        self.started.emit()
        try:
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            loop.run_until_complete(self.main_loop(self.stop_event))
        except Exception as e:
            print(f"CRITICAL ERROR in application thread: {e}")
        finally:
            self.finished.emit()


# PacketSenderWorker (unchanged)
class PacketSenderWorker(QObject):
    ping_finished = pyqtSignal(bool)
    tcp_syn_finished = pyqtSignal(bool)
    udp_finished = pyqtSignal(bool)
    dns_finished = pyqtSignal(bool)

    def __init__(self, packet_manager):
        super().__init__()
        self.packet_manager = packet_manager

    @pyqtSlot(str, int, int)
    def do_send_ping(self, target_ip, count, timeout):
        success = self.packet_manager.send_ping(target_ip, count, timeout)
        self.ping_finished.emit(success)

    @pyqtSlot(str, int, int, int)
    def do_send_tcp_syn(self, target_ip, target_port, src_port, timeout):
        success = self.packet_manager.send_tcp_syn(target_ip, target_port, src_port, timeout)
        self.tcp_syn_finished.emit(success)

    @pyqtSlot(str, int, bytes, int, int)
    def do_send_udp_packet(self, target_ip, target_port, payload, src_port, timeout):
        success = self.packet_manager.send_udp_packet(target_ip, target_port, payload, src_port, timeout)
        self.udp_finished.emit(success)

    @pyqtSlot(str, str, str, int)
    def do_send_dns_query(self, target_dns_server, domain, record_type, timeout):
        success = self.packet_manager.send_dns_query(target_dns_server, domain, record_type, timeout)
        self.dns_finished.emit(success)


class P2PoolGUI(QMainWindow):
    # Signals to trigger PacketSenderWorker methods from GUI thread (unchanged)
    trigger_send_ping = pyqtSignal(str, int, int)
    trigger_send_tcp_syn = pyqtSignal(str, int, int, int)
    trigger_send_udp_packet = pyqtSignal(str, int, bytes, int, int)
    trigger_send_dns_query = pyqtSignal(str, str, str, int)

    def __init__(self, logger, wireshark_logger, packet_logger, router_logger, application_main_loop,
                 p2pool_helper):  # ADD router_logger
        super().__init__()
        self.services_thread = None
        self.services_worker = None
        self.services_stop_event = threading.Event()

        self.packet_sender_thread = None
        self.packet_sender_worker = None

        self.raw_log_thread = None
        self.event_processor_thread = None

        self.logger = logger
        self.wireshark_logger = wireshark_logger
        self.packet_logger = packet_logger
        self.router_logger = router_logger  # ADD router_logger
        self.application_main_loop = application_main_loop
        self.helper = p2pool_helper

        self.setWindowTitle("Nate's Server")
        self.setGeometry(100, 100, 1000, 700)

        self.create_widgets()
        self.setStyleSheet(DARK_STYLESHEET)

        self.logger.message_signal.connect(self.route_log_message)
        self.wireshark_logger.message_signal.connect(self.log_to_wireshark_console)
        self.packet_logger.message_signal.connect(self.log_to_packet_console)
        self.router_logger.message_signal.connect(self.log_to_router_console)  # Connect router_logger

        sys.stdout = self.logger
        sys.stderr = self.logger

        self.logger.log_message("GUI Initialized. Starting background services...")
        self._start_background_services()
        self._start_packet_sender_worker()

    def _start_background_services(self):
        self.services_stop_event.clear()
        self.services_thread = QThread()
        self.services_worker = AsyncWorker(self.services_stop_event, self.application_main_loop)
        self.services_worker.moveToThread(self.services_thread)
        self.services_worker.started.connect(self.on_services_started)
        self.services_worker.finished.connect(self.on_services_stopped)
        self.services_thread.started.connect(self.services_worker.run)
        self.services_thread.start()

    def _start_packet_sender_worker(self):
        self.packet_sender_thread = QThread()
        self.packet_sender_worker = PacketSenderWorker(self.helper.packet_manager)
        self.packet_sender_worker.moveToThread(self.packet_sender_thread)

        self.trigger_send_ping.connect(self.packet_sender_worker.do_send_ping)
        self.trigger_send_tcp_syn.connect(self.packet_sender_worker.do_send_tcp_syn)
        self.trigger_send_udp_packet.connect(self.packet_sender_worker.do_send_udp_packet)
        self.trigger_send_dns_query.connect(self.packet_sender_worker.do_send_dns_query)

        self.packet_sender_worker.ping_finished.connect(
            lambda s: self.packet_logger.log_message(f"[PacketSender] Ping finished: {'Success' if s else 'Failure'}"))
        self.packet_sender_worker.tcp_syn_finished.connect(lambda s: self.packet_logger.log_message(
            f"[PacketSender] TCP SYN finished: {'Success' if s else 'Failure'}"))
        self.packet_sender_worker.udp_finished.connect(lambda s: self.packet_logger.log_message(
            f"[PacketSender] UDP send finished: {'Success' if s else 'Failure'}"))
        self.packet_sender_worker.dns_finished.connect(lambda s: self.packet_logger.log_message(
            f"[PacketSender] DNS query finished: {'Success' if s else 'Failure'}"))

        self.packet_sender_thread.start()
        self.logger.log_message("Packet sender worker thread started.")

    def create_widgets(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # --- P2Pool Tab (unchanged) ---
        p2pool_tab = QWidget()
        p2pool_layout = QVBoxLayout(p2pool_tab)
        p2pool_control_layout = QHBoxLayout()
        self.start_p2pool_button = QPushButton("Start P2Pool")
        self.start_p2pool_button.setObjectName("start_button")
        self.start_p2pool_button.clicked.connect(self.start_p2pool)
        self.start_p2pool_button.setEnabled(False)
        p2pool_control_layout.addWidget(self.start_p2pool_button)
        self.stop_p2pool_button = QPushButton("Stop P2Pool")
        self.stop_p2pool_button.setObjectName("stop_button")
        self.stop_p2pool_button.clicked.connect(self.stop_p2pool)
        self.stop_p2pool_button.setEnabled(False)
        p2pool_control_layout.addWidget(self.stop_p2pool_button)
        p2pool_control_layout.addStretch(1)
        p2pool_layout.addLayout(p2pool_control_layout)
        self.console_log = QPlainTextEdit()
        self.console_log.setReadOnly(True)
        p2pool_layout.addWidget(self.console_log)
        self.tabs.addTab(p2pool_tab, "P2Pool")

        # --- Wireshark Capture Tab (unchanged, except log console name) ---
        wireshark_tab = QWidget()
        wireshark_layout = QVBoxLayout(wireshark_tab)
        wireshark_control_layout = QHBoxLayout()
        self.start_wireshark_button = QPushButton("Start Wireshark Capture")
        self.start_wireshark_button.setObjectName("start_wireshark_button")
        self.start_wireshark_button.clicked.connect(self.start_wireshark)
        self.start_wireshark_button.setEnabled(False)
        wireshark_control_layout.addWidget(self.start_wireshark_button)
        self.stop_wireshark_button = QPushButton("Stop Wireshark Capture")
        self.stop_wireshark_button.setObjectName("stop_wireshark_button")
        self.stop_wireshark_button.clicked.connect(self.stop_wireshark)
        self.stop_wireshark_button.setEnabled(False)
        wireshark_control_layout.addWidget(self.stop_wireshark_button)
        wireshark_control_layout.addStretch(1)
        wireshark_layout.addLayout(wireshark_control_layout)
        self.wireshark_log = QPlainTextEdit()
        self.wireshark_log.setReadOnly(True)
        wireshark_layout.addWidget(self.wireshark_log)
        self.tabs.addTab(wireshark_tab, "Wireshark Capture")

        # --- Packet Sending Tab (unchanged) ---
        packet_sender_tab = QWidget()
        packet_sender_layout = QVBoxLayout(packet_sender_tab)
        packet_sender_group = QGroupBox("Send Custom Packets")
        packet_sender_group_layout = QVBoxLayout(packet_sender_group)
        ping_layout = QFormLayout()
        self.ping_ip_input = QLineEdit("127.0.0.1")
        self.send_ping_button = QPushButton("Send Ping (ICMP Echo)")
        self.send_ping_button.clicked.connect(self.send_ping_packet)
        self.send_ping_button.setEnabled(False)
        ping_layout.addRow(QLabel("Target IP:"), self.ping_ip_input)
        ping_layout.addRow(self.send_ping_button)
        packet_sender_group_layout.addLayout(ping_layout)
        packet_sender_group_layout.addSpacing(10)
        tcp_layout = QFormLayout()
        self.tcp_ip_input = QLineEdit("127.0.0.1")
        self.tcp_port_input = QLineEdit("80")
        self.send_tcp_button = QPushButton("Send TCP SYN")
        self.send_tcp_button.clicked.connect(self.send_tcp_syn_packet)
        self.send_tcp_button.setEnabled(False)
        tcp_layout.addRow(QLabel("Target IP:"), self.tcp_ip_input)
        tcp_layout.addRow(QLabel("Target Port:"), self.tcp_port_input)
        tcp_layout.addRow(self.send_tcp_button)
        packet_sender_group_layout.addLayout(tcp_layout)
        packet_sender_group_layout.addSpacing(10)
        udp_layout = QFormLayout()
        self.udp_ip_input = QLineEdit("127.0.0.1")
        self.udp_port_input = QLineEdit("53")
        self.udp_payload_input = QLineEdit("HelloUDP")
        self.send_udp_button = QPushButton("Send UDP Packet")
        self.send_udp_button.clicked.connect(self.send_udp_packet)
        self.send_udp_button.setEnabled(False)
        udp_layout.addRow(QLabel("Target IP:"), self.udp_ip_input)
        udp_layout.addRow(QLabel("Target Port:"), self.udp_port_input)
        udp_layout.addRow(QLabel("Payload (UTF-8):"), self.udp_payload_input)
        udp_layout.addRow(self.send_udp_button)
        packet_sender_group_layout.addLayout(udp_layout)
        packet_sender_group_layout.addSpacing(10)
        dns_layout = QFormLayout()
        self.dns_server_input = QLineEdit("8.8.8.8")
        self.dns_domain_input = QLineEdit("google.com")
        self.dns_type_combo = QComboBox()
        self.dns_type_combo.addItems(["A", "AAAA", "MX", "NS", "PTR", "TXT"])
        self.send_dns_button = QPushButton("Send DNS Query")
        self.send_dns_button.clicked.connect(self.send_dns_query_packet)
        self.send_dns_button.setEnabled(False)
        dns_layout.addRow(QLabel("DNS Server:"), self.dns_server_input)
        dns_layout.addRow(QLabel("Domain Name:"), self.dns_domain_input)
        dns_layout.addRow(QLabel("Record Type:"), self.dns_type_combo)
        dns_layout.addRow(self.send_dns_button)
        packet_sender_group_layout.addLayout(dns_layout)
        packet_sender_layout.addWidget(packet_sender_group)
        self.packet_log = QPlainTextEdit()
        self.packet_log.setReadOnly(True)
        packet_sender_layout.addWidget(self.packet_log)
        self.tabs.addTab(packet_sender_tab, "Send Packets")

        # --- NEW: Router Tab ---
        router_tab = QWidget()
        router_layout = QVBoxLayout(router_tab)

        router_control_layout = QHBoxLayout()
        self.start_router_button = QPushButton("Start Router")
        self.start_router_button.setObjectName("start_router_button")
        self.start_router_button.clicked.connect(self.start_router)
        self.start_router_button.setEnabled(True)
        router_control_layout.addWidget(self.start_router_button)

        self.stop_router_button = QPushButton("Stop Router")
        self.stop_router_button.setObjectName("stop_router_button")
        self.stop_router_button.clicked.connect(self.stop_router)
        self.stop_router_button.setEnabled(False)
        router_control_layout.addWidget(self.stop_router_button)
        router_control_layout.addStretch(1)
        router_layout.addLayout(router_control_layout)

        self.router_log = QPlainTextEdit()
        self.router_log.setReadOnly(True)
        router_layout.addWidget(self.router_log)
        self.tabs.addTab(router_tab, "Router")

    def start_p2pool(self):
        self.logger.log_message("--- Starting P2Pool and log processors ---")
        if self.helper.asyncio_main_loop:
            self.helper.p2pool_stop_event.clear()
            self.raw_log_thread = threading.Thread(target=self.helper.raw_log_processor.run_in_background, daemon=True)
            self.event_processor_thread = threading.Thread(target=self.helper.event_processor.run_in_background,
                                                           daemon=True)
            self.raw_log_thread.start()
            self.event_processor_thread.start()
            asyncio.run_coroutine_threadsafe(self.helper.processor.start_p2pool(), self.helper.asyncio_main_loop)
            self.start_p2pool_button.setEnabled(False)
            self.stop_p2pool_button.setEnabled(True)
        else:
            self.logger.log_message("[!] Cannot start P2Pool: background services not ready.")

    def stop_p2pool(self):
        self.logger.log_message("--- Stopping P2Pool and log processors ---")
        if self.helper.asyncio_main_loop:
            asyncio.run_coroutine_threadsafe(self.helper.processor.stop_p2pool(), self.helper.asyncio_main_loop)
            self.helper.p2pool_stop_event.set()
            self.start_p2pool_button.setEnabled(True)
            self.stop_p2pool_button.setEnabled(False)
        else:
            self.logger.log_message("[!] Cannot stop P2Pool: background services not ready.")

    def start_wireshark(self):
        selected_interface_name = 'Wi-Fi'
        capture_started = self.helper.wireshark_manager.start_capture(main_interface_name=selected_interface_name)

        if capture_started:
            self.start_wireshark_button.setEnabled(False)
            self.stop_wireshark_button.setEnabled(True)
        else:
            self.logger.log_message("[Wireshark] Failed to start Wireshark capture. Check tshark path and permissions.")

    def stop_wireshark(self):
        self.helper.wireshark_manager.stop_capture()
        self.start_wireshark_button.setEnabled(True)
        self.stop_wireshark_button.setEnabled(False)

    # --- Methods connected to GUI buttons (now emit signals to worker) ---
    def send_ping_packet(self):
        target_ip = self.ping_ip_input.text().strip()
        if not target_ip:
            self.packet_logger.log_message("[PacketSender] Please enter a target IP for Ping.")
            return
        self.packet_logger.log_message(f"[PacketSender] Requesting Ping to {target_ip}...")
        self.trigger_send_ping.emit(target_ip, 1, 2)

    def send_tcp_syn_packet(self):
        target_ip = self.tcp_ip_input.text().strip()
        target_port_str = self.tcp_port_input.text().strip()
        if not target_ip or not target_port_str.isdigit():
            self.packet_logger.log_message("[PacketSender] Please enter a valid target IP and port for TCP SYN.")
            return
        target_port = int(target_port_str)
        self.packet_logger.log_message(f"[PacketSender] Requesting TCP SYN to {target_ip}:{target_port}...")
        self.trigger_send_tcp_syn.emit(target_ip, target_port, 12345, 2)

    def send_udp_packet(self):
        target_ip = self.udp_ip_input.text().strip()
        target_port_str = self.udp_port_input.text().strip()
        payload_str = self.udp_payload_input.text().strip()
        payload_bytes = payload_str.encode('utf-8')

        if not target_ip or not target_port_str.isdigit():
            self.packet_logger.log_message("[PacketSender] Please enter a valid target IP and port for UDP.")
            return
        target_port = int(target_port_str)
        self.packet_logger.log_message(f"[PacketSender] Requesting UDP packet to {target_ip}:{target_port}...")
        self.trigger_send_udp_packet.emit(target_ip, target_port, payload_bytes, 54321,
                                          2)

    def send_dns_query_packet(self):
        dns_server = self.dns_server_input.text().strip()
        domain = self.dns_domain_input.text().strip()
        record_type = self.dns_type_combo.currentText()

        if not dns_server or not domain:
            self.packet_logger.log_message("[PacketSender] Please enter a DNS server and domain for DNS query.")
            return
        self.packet_logger.log_message(f"[PacketSender] Requesting DNS query for '{domain}' to {dns_server}...")
        self.trigger_send_dns_query.emit(dns_server, domain, record_type, 2)

    # --- NEW: Router Control Methods in P2PoolGUI ---
    def start_router(self):
        if self.helper.router_manager:
            self.helper.router_manager.start_routing()
            self.start_router_button.setEnabled(False)
            self.stop_router_button.setEnabled(True)
        else:
            self.logger.log_message("[RouterUI] Router Manager not initialized.")

    def stop_router(self):
        if self.helper.router_manager:
            self.helper.router_manager.stop_routing()
            self.start_router_button.setEnabled(True)
            self.stop_router_button.setEnabled(False)
        else:
            self.logger.log_message("[RouterUI] Router Manager not initialized.")

    def on_services_started(self):
        self.logger.log_message("Background services started. All controls are now active.")
        self.start_p2pool_button.setEnabled(True)
        self.start_wireshark_button.setEnabled(True)
        self.send_ping_button.setEnabled(True)
        self.send_tcp_button.setEnabled(True)
        self.send_udp_button.setEnabled(True)
        self.send_dns_button.setEnabled(True)
        self.start_router_button.setEnabled(True)
        self.stop_router_button.setEnabled(True)

    def on_services_stopped(self):
        self.logger.log_message("\n--- Background Services Stopped ---")
        self.start_p2pool_button.setEnabled(False)
        self.stop_p2pool_button.setEnabled(False)
        self.start_wireshark_button.setEnabled(False)
        self.stop_wireshark_button.setEnabled(False)
        self.send_ping_button.setEnabled(False)
        self.send_tcp_button.setEnabled(False)
        self.send_udp_button.setEnabled(False)
        self.send_dns_button.setEnabled(False)

        if self.services_thread:
            self.services_thread.quit()
            self.services_thread.wait()
        self.services_thread = None
        self.services_worker = None

        if self.packet_sender_thread:
            self.packet_sender_thread.quit()
            self.packet_sender_thread.wait()
            self.packet_sender_thread = None
            self.packet_sender_worker = None

        # Ensure router manager is stopped and cleaned up on full app shutdown
        if self.helper.router_manager:
            self.helper.router_manager.stop_routing()  # This calls cleanup_all_network_changes internally

    def route_log_message(self, text):
        if text.startswith("[NetTrace-") or text.startswith("[HTTP-") or \
                text.startswith("[TLS-") or text.startswith("[DNS-") or \
                text.startswith("[StreamData-") or text.startswith("[Wireshark") or \
                text.startswith("[GeoIP"):
            self.wireshark_logger.log_message(text)
        elif text.startswith("[PacketSender]"):
            self.packet_logger.log_message(text)
        elif text.startswith("[RouterManager]") or text.startswith("[Netsh]") or text.startswith(
                "[ARP]"):  # ADDED ROUTER LOGS
            self.router_logger.log_message(text)
        else:
            self.console_log.appendPlainText(text)

    def log_to_wireshark_console(self, text):
        self.wireshark_log.appendPlainText(text)

    def log_to_packet_console(self, text):
        self.packet_log.appendPlainText(text)

    # NEW: Router log console method
    def log_to_router_console(self, text):
        self.router_log.appendPlainText(text)

    def closeEvent(self, event):
        self.logger.log_message("Closing application window...")
        if self.services_thread and self.services_thread.isRunning():
            self.logger.log_message("Sending shutdown signal to background services...")
            self.services_stop_event.set()
            self.services_thread.quit()
            self.services_thread.wait(3000)
            if self.services_thread.isRunning():
                self.services_thread.terminate()

        if self.packet_sender_thread and self.packet_sender_thread.isRunning():
            self.logger.log_message("Stopping packet sender worker thread...")
            self.packet_sender_thread.quit()
            self.packet_sender_thread.wait(3000)
            if self.packet_sender_thread.isRunning():
                self.packet_sender_thread.terminate()

        # Ensure router manager is stopped and cleaned up on full app shutdown
        if self.helper.router_manager:
            self.helper.router_manager.stop_routing()  # This calls cleanup_all_network_changes internally

        event.accept()