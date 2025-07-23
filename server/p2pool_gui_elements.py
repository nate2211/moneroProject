from typing import List
import queue
import threading
import asyncio
from PyQt5.QtWidgets import  QWidget, QLineEdit, QLabel, QComboBox, QGroupBox, QFormLayout
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot
from p2pool_managers import PacketManager


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


class PacketSenderWorker(QObject):
    """
    This QObject worker now acts as a bridge. It receives signals from the GUI
    and puts the request onto a queue to be processed by a dedicated thread.
    """
    def __init__(self, request_queue: queue.Queue):
        super().__init__()
        self.request_queue = request_queue

    @pyqtSlot(str, str, str, int)
    def do_send_ping(self, target_ip, iface, src_ip, timeout):
        self.request_queue.put(('ping', (target_ip, iface, src_ip, timeout)))

    @pyqtSlot(str, int, str, str, int)
    def do_send_tcp_syn(self, target_ip, target_port, iface, src_ip, timeout):
        self.request_queue.put(('tcp_syn', (target_ip, target_port, iface, src_ip, timeout)))

    @pyqtSlot(str, int, bytes, str, str, int)
    def do_send_udp_packet(self, target_ip, target_port, payload, iface, src_ip, timeout):
        self.request_queue.put(('udp', (target_ip, target_port, payload, iface, src_ip, timeout)))

    @pyqtSlot(str, str, str, str, str, int)
    def do_send_dns_query(self, dns_server, domain, record_type, iface, src_ip, timeout):
        self.request_queue.put(('dns', (dns_server, domain, record_type, iface, src_ip, timeout)))


class PacketSendingThread(threading.Thread):
    """
    This dedicated thread handles the actual (blocking) packet sending,
    completely isolated from the Qt event loop.
    """

    def __init__(self, request_queue: queue.Queue, packet_manager: PacketManager, logger):
        super().__init__(daemon=True)
        self.request_queue = request_queue
        self.packet_manager = packet_manager
        self.logger = logger

    def run(self):
        self.logger.log_message("[PacketSenderThread] Worker thread started.")
        while True:
            try:
                # Block until a request is available
                request_type, args = self.request_queue.get()

                # A sentinel value (None) is used to signal the thread to exit
                if request_type is None:
                    break

                if request_type == 'ping':
                    status, _ = self.packet_manager.send_ping(*args)
                    self.logger.log_message(f"[Result] Ping to {args[0]}: {status}")
                elif request_type == 'tcp_syn':
                    status, _ = self.packet_manager.send_tcp_syn(*args)
                    self.logger.log_message(f"[Result] TCP SYN to {args[0]}:{args[1]}: {status}")
                elif request_type == 'udp':
                    status, _ = self.packet_manager.send_udp_packet(*args)
                    self.logger.log_message(f"[Result] UDP to {args[0]}:{args[1]}: {status}")
                elif request_type == 'dns':
                    status, answers = self.packet_manager.send_dns_query(*args)
                    self.logger.log_message(f"[Result] DNS for {args[1]}: {status} -> {answers}")

            except Exception as e:
                self.logger.log_message(f"[PacketSenderThread] CRITICAL ERROR: {e}")

        self.logger.log_message("[PacketSenderThread] Worker thread stopped.")



class P2PoolTab(QWidget):
    """
    A QWidget that encapsulates all UI elements and logic for the P2Pool tab.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_widgets()
        self._configure_layout()

    def _create_widgets(self):
        """Creates all the widgets for the tab."""
        self.start_p2pool_button = QPushButton("Start P2Pool")
        self.start_p2pool_button.setObjectName("start_button")
        self.start_p2pool_button.setEnabled(False)

        self.stop_p2pool_button = QPushButton("Stop P2Pool")
        self.stop_p2pool_button.setObjectName("stop_button")
        self.stop_p2pool_button.setEnabled(False)

        self.console_log = QPlainTextEdit()
        self.console_log.setReadOnly(True)

    def _configure_layout(self):
        """Sets up the layout for the tab."""
        layout = QVBoxLayout(self)
        control_layout = QHBoxLayout()

        control_layout.addWidget(self.start_p2pool_button)
        control_layout.addWidget(self.stop_p2pool_button)
        control_layout.addStretch(1)

        layout.addLayout(control_layout)
        layout.addWidget(self.console_log)

    @pyqtSlot(str)
    def log_message(self, message: str):
        """Appends a message to the P2Pool console log."""
        self.console_log.appendPlainText(message)

class WiresharkTab(QWidget):
    """
    A QWidget that encapsulates all UI elements and logic for the Wireshark Capture tab.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_widgets()
        self._configure_layout()

    def _create_widgets(self):
        """Creates all the widgets for the tab."""
        self.start_wireshark_button = QPushButton("Start Wireshark Capture")
        self.start_wireshark_button.setObjectName("start_wireshark_button")
        self.start_wireshark_button.setEnabled(False)

        self.stop_wireshark_button = QPushButton("Stop Wireshark Capture")
        self.stop_wireshark_button.setObjectName("stop_wireshark_button")
        self.stop_wireshark_button.setEnabled(False)

        self.wireshark_log = QPlainTextEdit()
        self.wireshark_log.setReadOnly(True)

    def _configure_layout(self):
        """Sets up the layout for the tab."""
        layout = QVBoxLayout(self)
        control_layout = QHBoxLayout()

        control_layout.addWidget(self.start_wireshark_button)
        control_layout.addWidget(self.stop_wireshark_button)
        control_layout.addStretch(1)

        layout.addLayout(control_layout)
        layout.addWidget(self.wireshark_log)

    @pyqtSlot(str)
    def log_message(self, message: str):
        """Appends a message to the Wireshark console log."""
        self.wireshark_log.appendPlainText(message)

from PyQt5.QtWidgets import QWidget, QVBoxLayout, QHBoxLayout, QPushButton, QPlainTextEdit
from PyQt5.QtCore import pyqtSlot

class RouterTab(QWidget):
    """
    A QWidget that encapsulates all UI elements and logic for the Router tab.
    """
    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_widgets()
        self._configure_layout()

    def _create_widgets(self):
        """Creates all the widgets for the tab."""
        self.start_router_button = QPushButton("Start Router")
        self.start_router_button.setObjectName("start_router_button")
        self.start_router_button.setEnabled(True)

        self.stop_router_button = QPushButton("Stop Router")
        self.stop_router_button.setObjectName("stop_router_button")
        self.stop_router_button.setEnabled(False)

        self.router_log = QPlainTextEdit()
        self.router_log.setReadOnly(True)

    def _configure_layout(self):
        """Sets up the layout for the tab."""
        layout = QVBoxLayout(self)
        control_layout = QHBoxLayout()

        control_layout.addWidget(self.start_router_button)
        control_layout.addWidget(self.stop_router_button)
        control_layout.addStretch(1)

        layout.addLayout(control_layout)
        layout.addWidget(self.router_log)

    @pyqtSlot(str)
    def log_message(self, message: str):
        """Appends a message to the router console log."""
        self.router_log.appendPlainText(message)


class PacketSenderTab(QWidget):
    """
    A QWidget that encapsulates all UI elements for the Packet Sending tab.
    It emits signals with the necessary data for the worker to send packets.
    """
    # Signals that will be emitted when a send button is clicked
    send_ping_requested = pyqtSignal(str, str, str, int)
    send_tcp_syn_requested = pyqtSignal(str, int, str, str, int)
    send_udp_requested = pyqtSignal(str, int, bytes, str, str, int)
    send_dns_requested = pyqtSignal(str, str, str, str, str, int)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_widgets()
        self._configure_layout()
        self._connect_signals()

    def _create_widgets(self):
        """Creates all the widgets for the tab."""
        self.iface_combo = QComboBox()

        self.ping_ip_input = QLineEdit("8.8.8.8")
        self.send_ping_button = QPushButton("Send Ping")

        self.tcp_ip_input = QLineEdit("example.com")
        self.tcp_port_input = QLineEdit("443")
        self.send_tcp_button = QPushButton("Send TCP SYN")

        self.udp_ip_input = QLineEdit("8.8.8.8")
        self.udp_port_input = QLineEdit("53")
        self.udp_payload_input = QLineEdit("HelloUDP")
        self.send_udp_button = QPushButton("Send UDP Packet")

        self.dns_server_input = QLineEdit("8.8.8.8")
        self.dns_domain_input = QLineEdit("google.com")
        self.dns_type_combo = QComboBox()
        self.dns_type_combo.addItems(["A", "AAAA", "MX", "NS", "TXT"])
        self.send_dns_button = QPushButton("Send DNS Query")

        self.packet_log = QPlainTextEdit()
        self.packet_log.setReadOnly(True)

        # Initially disable buttons until services are ready
        self.send_ping_button.setEnabled(False)
        self.send_tcp_button.setEnabled(False)
        self.send_udp_button.setEnabled(False)
        self.send_dns_button.setEnabled(False)

    def _configure_layout(self):
        """Sets up the layout for the tab."""
        main_layout = QVBoxLayout(self)
        group_box = QGroupBox("Send Custom Packets")
        group_layout = QVBoxLayout(group_box)

        # Interface Selector
        iface_layout = QFormLayout()
        iface_layout.addRow(QLabel("Send From Interface:"), self.iface_combo)
        group_layout.addLayout(iface_layout)
        group_layout.addSpacing(15)

        # Ping
        ping_layout = QFormLayout()
        ping_layout.addRow(QLabel("Target IP:"), self.ping_ip_input)
        ping_layout.addRow(self.send_ping_button)
        group_layout.addLayout(ping_layout)
        group_layout.addSpacing(10)

        # TCP
        tcp_layout = QFormLayout()
        tcp_layout.addRow(QLabel("Target IP:"), self.tcp_ip_input)
        tcp_layout.addRow(QLabel("Target Port:"), self.tcp_port_input)
        tcp_layout.addRow(self.send_tcp_button)
        group_layout.addLayout(tcp_layout)
        group_layout.addSpacing(10)

        # UDP
        udp_layout = QFormLayout()
        udp_layout.addRow(QLabel("Target IP:"), self.udp_ip_input)
        udp_layout.addRow(QLabel("Target Port:"), self.udp_port_input)
        udp_layout.addRow(QLabel("Payload (UTF-8):"), self.udp_payload_input)
        udp_layout.addRow(self.send_udp_button)
        group_layout.addLayout(udp_layout)
        group_layout.addSpacing(10)

        # DNS
        dns_layout = QFormLayout()
        dns_layout.addRow(QLabel("DNS Server:"), self.dns_server_input)
        dns_layout.addRow(QLabel("Domain Name:"), self.dns_domain_input)
        dns_layout.addRow(QLabel("Record Type:"), self.dns_type_combo)
        dns_layout.addRow(self.send_dns_button)
        group_layout.addLayout(dns_layout)

        main_layout.addWidget(group_box)
        main_layout.addWidget(self.packet_log)

    def _connect_signals(self):
        """Connects button clicks to handler methods that emit signals."""
        self.send_ping_button.clicked.connect(self._on_send_ping)
        self.send_tcp_button.clicked.connect(self._on_send_tcp_syn)
        self.send_udp_button.clicked.connect(self._on_send_udp)
        self.send_dns_button.clicked.connect(self._on_send_dns)

    def _get_selected_interface(self) -> str:
        """Returns the full name of the selected interface."""
        iface = self.iface_combo.currentData()
        if not iface:
            self.log_message("[GUI Error] Please select a valid interface.")
        return iface

    @pyqtSlot()
    def _on_send_ping(self):
        iface = self._get_selected_interface()
        if iface and self.ping_ip_input.text():
            self.send_ping_requested.emit(self.ping_ip_input.text().strip(), iface, None, 2)

    @pyqtSlot()
    def _on_send_tcp_syn(self):
        iface = self._get_selected_interface()
        if iface and self.tcp_ip_input.text() and self.tcp_port_input.text().isdigit():
            self.send_tcp_syn_requested.emit(self.tcp_ip_input.text().strip(), int(self.tcp_port_input.text()), iface,
                                             None, 2)

    @pyqtSlot()
    def _on_send_udp(self):
        iface = self._get_selected_interface()
        if iface and self.udp_ip_input.text() and self.udp_port_input.text().isdigit():
            payload = self.udp_payload_input.text().encode('utf-8')
            self.send_udp_requested.emit(self.udp_ip_input.text().strip(), int(self.udp_port_input.text()), payload,
                                         iface, None, 2)

    @pyqtSlot()
    def _on_send_dns(self):
        iface = self._get_selected_interface()
        if iface and self.dns_server_input.text() and self.dns_domain_input.text():
            self.send_dns_requested.emit(self.dns_server_input.text().strip(), self.dns_domain_input.text().strip(),
                                         self.dns_type_combo.currentText(), iface, None, 2)

    @pyqtSlot(list)
    def populate_interfaces(self, interfaces: List[dict]):
        """Populates the interface dropdown."""
        self.iface_combo.clear()
        if not interfaces:
            self.iface_combo.addItem("No interfaces found")
            self.iface_combo.setEnabled(False)
            return

        for iface in interfaces:
            self.iface_combo.addItem(iface['friendly_name'], userData=iface['full_name'])
        self.iface_combo.setEnabled(True)

    @pyqtSlot(str)
    def log_message(self, message: str):
        """Appends a message to the packet console log."""
        self.packet_log.appendPlainText(message)