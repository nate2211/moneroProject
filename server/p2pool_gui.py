import sys
import threading
import asyncio
from PyQt5.QtWidgets import QApplication, QMainWindow, QPushButton, QVBoxLayout, QHBoxLayout, QWidget, QPlainTextEdit, \
    QTabWidget
from PyQt5.QtCore import QObject, pyqtSignal, QThread

# Centralized stylesheet for a sleek, dark theme
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
    #start_button, #start_wireshark_button {
        color: #a9f5a9;
    }
    #start_button:hover, #start_wireshark_button:hover {
        background-color: #38761d;
    }
    #stop_button, #stop_wireshark_button {
        color: #ff9999;
    }
    #stop_button:hover, #stop_wireshark_button:hover {
        background-color: #990000;
    }
"""


class ConsoleLogger(QObject):
    message_signal = pyqtSignal(str)

    def log_message(self, msg): self.message_signal.emit(str(msg).rstrip())

    def write(self, msg):
        if msg.strip(): self.log_message(msg)

    def flush(self): pass


class NetworkLogger(QObject):
    """A dedicated logger for network-related messages."""
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


class P2PoolGUI(QMainWindow):
    def __init__(self, logger, network_logger, application_main_loop, p2pool_helper):
        super().__init__()
        self.services_thread = None
        self.services_worker = None
        self.services_stop_event = threading.Event()

        self.raw_log_thread = None
        self.event_processor_thread = None

        self.logger = logger
        self.network_logger = network_logger  # Create the new network logger
        self.application_main_loop = application_main_loop
        self.helper = p2pool_helper

        self.setWindowTitle("Nate's Server")
        self.setGeometry(100, 100, 900, 600)

        self.create_widgets()
        self.setStyleSheet(DARK_STYLESHEET)

        self.logger.message_signal.connect(self.route_log_message)
        self.network_logger.message_signal.connect(self.log_to_network_console)
        sys.stdout = self.logger
        sys.stderr = self.logger

        self.logger.log_message("GUI Initialized. Starting background services...")
        self._start_background_services()

    def _start_background_services(self):
        self.services_stop_event.clear()
        self.services_thread = QThread()
        self.services_worker = AsyncWorker(self.services_stop_event, self.application_main_loop)
        self.services_worker.moveToThread(self.services_thread)
        self.services_worker.started.connect(self.on_services_started)
        self.services_worker.finished.connect(self.on_services_stopped)
        self.services_thread.started.connect(self.services_worker.run)
        self.services_thread.start()

    def create_widgets(self):
        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # --- P2Pool Tab ---
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

        # --- Network Tab ---
        network_tab = QWidget()
        network_layout = QVBoxLayout(network_tab)

        network_control_layout = QHBoxLayout()
        self.start_wireshark_button = QPushButton("Start Wireshark")
        self.start_wireshark_button.setObjectName("start_wireshark_button")
        self.start_wireshark_button.clicked.connect(self.start_wireshark)
        self.start_wireshark_button.setEnabled(False)
        network_control_layout.addWidget(self.start_wireshark_button)

        self.stop_wireshark_button = QPushButton("Stop Wireshark")
        self.stop_wireshark_button.setObjectName("stop_wireshark_button")
        self.stop_wireshark_button.clicked.connect(self.stop_wireshark)
        self.stop_wireshark_button.setEnabled(False)
        network_control_layout.addWidget(self.stop_wireshark_button)
        network_control_layout.addStretch(1)

        network_layout.addLayout(network_control_layout)
        self.network_log = QPlainTextEdit()
        self.network_log.setReadOnly(True)
        network_layout.addWidget(self.network_log)
        self.tabs.addTab(network_tab, "Network")

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
        if self.helper.wireshark_manager.start_capture():
            self.start_wireshark_button.setEnabled(False)
            self.stop_wireshark_button.setEnabled(True)

    def stop_wireshark(self):
        self.helper.wireshark_manager.stop_capture()
        self.start_wireshark_button.setEnabled(True)
        self.stop_wireshark_button.setEnabled(False)

    def on_services_started(self):
        self.logger.log_message("Background services started. All controls are now active.")
        self.start_p2pool_button.setEnabled(True)
        self.start_wireshark_button.setEnabled(True)

    def on_services_stopped(self):
        self.logger.log_message("\n--- Background Services Stopped ---")
        self.start_p2pool_button.setEnabled(False)
        self.stop_p2pool_button.setEnabled(False)
        self.start_wireshark_button.setEnabled(False)
        self.stop_wireshark_button.setEnabled(False)
        if self.services_thread:
            self.services_thread.quit()
            self.services_thread.wait()
        self.services_thread = None
        self.services_worker = None

    def route_log_message(self, text):
        """Directs log messages to the correct text box based on a prefix."""
        if text.startswith("[Net]"):
            self.network_logger.log_message(text[6:])  # Strip prefix and send to network logger
        else:
            self.console_log.appendPlainText(text)

    def log_to_network_console(self, text):
        """Appends a message to the network log text box."""
        self.network_log.appendPlainText(text)

    def closeEvent(self, event):
        self.logger.log_message("Closing application window...")
        if self.services_thread and self.services_thread.isRunning():
            self.logger.log_message("Sending shutdown signal to background services...")
            self.services_stop_event.set()
            self.services_thread.wait(3000)
        event.accept()
