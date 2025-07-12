import asyncio
import os
import subprocess
import sys
import shutil
import textwrap

import psutil
import tempfile

import aiohttp

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QPlainTextEdit, QLabel, QFormLayout,
                             QFrame, QToolButton, QSizePolicy, QSpacerItem, QProgressDialog, QMessageBox)
from PyQt5.QtCore import QObject, pyqtSignal, QThread, pyqtSlot, QParallelAnimationGroup, QPropertyAnimation, \
    QAbstractAnimation, Qt
from PyQt5.QtGui import QIcon


# Note: The XmrigData and XmrigMiner classes are imported by main.py and
# instances are passed into this GUI class.

# ==============================================================================
# PYQT5 & ASYNCIO INTEGRATION COMPONENTS
# ==============================================================================

class ConsoleLogger(QObject):
    """
    A QObject that provides a thread-safe way to log messages to the GUI's
    console widget by emitting a PyQt signal.
    """
    message_signal = pyqtSignal(str)

    def log_message(self, msg):
        """Emits a signal containing the log message."""
        self.message_signal.emit(str(msg))


class AsyncWorker(QThread):
    """
    A dedicated QThread to run the asyncio event loop. This prevents background
    tasks like mining and network requests from freezing the GUI.
    """

    def __init__(self, coro, parent=None):
        super().__init__(parent)
        self.coro = coro
        self.loop = None

    def run(self):
        """Initializes and runs the asyncio event loop for all background tasks."""
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        # The main async task (run_async_tasks) is run until it completes.
        self.loop.run_until_complete(self.coro)
        self.loop.close()


# ==============================================================================
# NEW & UPDATED GUI WIDGETS
# ==============================================================================

class CollapsibleBox(QWidget):
    """A collapsible box widget."""

    def __init__(self, title="", parent=None, start_expanded=False):
        super(CollapsibleBox, self).__init__(parent)

        self.toggle_button = QToolButton(text=title, checkable=True, checked=start_expanded)
        self.toggle_button.setStyleSheet("QToolButton { border: none; font-weight: bold; font-size: 14px; }")
        self.toggle_button.setToolButtonStyle(3)  # Qt.ToolButtonTextBesideIcon
        self.toggle_button.setArrowType(1 if start_expanded else 2)  # Set initial arrow direction

        self.content_area = QWidget()
        self.content_area.setMaximumHeight(0)
        self.content_area.setMinimumHeight(0)
        self.content_area_layout = QVBoxLayout(self.content_area)

        self.toggle_animation = QParallelAnimationGroup(self)

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.toggle_button)
        main_layout.addWidget(self.content_area)

        self.toggle_button.clicked.connect(self.toggle)

    @pyqtSlot(bool)
    def toggle(self, checked):
        self.toggle_button.setArrowType(1 if checked else 2)  # DownArrow or RightArrow
        self.toggle_animation.setDirection(QAbstractAnimation.Forward if checked else QAbstractAnimation.Backward)
        self.toggle_animation.start()

    def setContentLayout(self, layout):
        self.content_area_layout.addLayout(layout)

        collapsed_height = self.toggle_button.sizeHint().height()
        # Use a fixed height to ensure it's predictable on startup
        content_height = 200

        for i in range(self.toggle_animation.animationCount()):
            self.toggle_animation.removeAnimation(self.toggle_animation.animationAt(0))

        self.toggle_animation.addAnimation(QPropertyAnimation(self, b"minimumHeight"))
        self.toggle_animation.addAnimation(QPropertyAnimation(self, b"maximumHeight"))
        self.toggle_animation.addAnimation(QPropertyAnimation(self.content_area, b"maximumHeight"))

        for i in range(self.toggle_animation.animationCount()):
            animation = self.toggle_animation.animationAt(i)
            animation.setDuration(300)
            animation.setStartValue(collapsed_height)
            animation.setEndValue(collapsed_height + content_height)

        content_animation = self.toggle_animation.animationAt(2)
        content_animation.setStartValue(0)
        content_animation.setEndValue(content_height)

        # Set initial state without animation
        if self.toggle_button.isChecked():
            self.content_area.setMaximumHeight(content_height)
        else:
            self.content_area.setMaximumHeight(0)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)


class StatsDisplay(QWidget):
    """A widget to display real-time miner statistics."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QFormLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        self.hashrate_label = QLabel("N/A")
        self.cpu_temp_label = QLabel("N/A")
        self.gpu_temp_label = QLabel("N/A")
        self.power_draw_label = QLabel("N/A")
        self.cpu_shares_label = QLabel("0")
        self.gpu_shares_label = QLabel("0")

        layout.addRow("<b>Hashrate:</b>", self.hashrate_label)
        layout.addRow("<b>CPU Temp:</b>", self.cpu_temp_label)
        layout.addRow("<b>GPU Temp / Fan:</b>", self.gpu_temp_label)
        layout.addRow("<b>Power Draw:</b>", self.power_draw_label)
        layout.addRow("<b>CPU Shares:</b>", self.cpu_shares_label)
        layout.addRow("<b>GPU Shares:</b>", self.gpu_shares_label)

    @pyqtSlot(dict)
    def update_stats(self, stats_payload):
        """Updates the labels with new data from the stats payload."""
        self.hashrate_label.setText(f"{stats_payload.get('hashrate', 0.0):.2f} H/s")
        self.cpu_temp_label.setText(stats_payload.get('cpu_temp', "N/A"))
        self.gpu_temp_label.setText(f"{stats_payload.get('gpu_temp', 'N/A')} / {stats_payload.get('gpu_fan', 'N/A')}")
        self.power_draw_label.setText(str(stats_payload.get('power_draw', "N/A")))
        self.cpu_shares_label.setText(str(stats_payload.get('cpu_accepted_shares', 0)))
        self.gpu_shares_label.setText(str(stats_payload.get('nvidia_accepted_shares', 0)))


class MinerGui(QWidget):
    """The main GUI window for the application."""
    # New signal to safely update stats on the GUI thread
    stats_update_signal = pyqtSignal(dict)
    force_update_signal = pyqtSignal(str)
    def __init__(self, xmrig_data, xmrig_miner, logger):
        super().__init__()
        # --- Initialize Core Components ---
        self.xmrig_data = xmrig_data
        self.xmrig_miner = xmrig_miner
        self.logger = logger
        self.async_worker = None

        # --- Build the UI ---
        self.init_ui()
        self.connect_signals()
        self.logger.log_message("Welcome! Please enter server details and click 'Connect'.")

    def init_ui(self):
        """Sets up all the widgets and layouts in the window."""
        self.setWindowTitle("Nate's Mining Client")
        self.setGeometry(100, 100, 1000, 700)
        self.resize(1000, 700)
        # --- Apply High-Contrast Black and White Stylesheet ---
        stylesheet = """
            /* Main Window and General Widget Styling */
            QWidget {
                background-color: #0D0D0D;  /* deep black */
                color: #FFFFFF;             /* white text */
                font-family: Segoe UI, sans-serif;
                font-size: 10pt;
            }

            /* Labels */
            QLabel {
                color: #FFFFFF;  /* white */
            }

            /* Buttons */
            QPushButton {
                background-color: #8B0000;  /* dark red */
                color: #FFFFFF;
                border: 1px solid #FF4C4C;  /* bright red border */
                padding: 8px 16px;
                border-radius: 4px;
                font-weight: bold;
            }
            QPushButton:hover {
                background-color: #B22222;  /* firebrick */
                border: 1px solid #FF6666;
            }
            QPushButton:pressed {
                background-color: #660000;  /* darker red */
            }
            QPushButton:disabled {
                background-color: #2A2A2A;
                color: #888888;
                border: 1px solid #444444;
            }

            /* Input Fields */
            QLineEdit, QPlainTextEdit {
                background-color: #1A1A1A;
                border: 1px solid #555555;
                padding: 6px;
                border-radius: 4px;
                color: #FFFFFF;
            }

            /* Frames and Separators */
            QFrame {
                border: 1px solid #2E2E2E;
            }

            /* Collapsible Box Headers */
            QToolButton {
                color: #FF4C4C;  /* bright red */
                font-size: 12pt;
                font-weight: bold;
            }

            /* Form Layout Label Styling */
            QFormLayout QLabel {
                font-weight: bold;
                color: #FFFFFF;
            }

            /* Console Title */
            #consoleTitle {
                font-size: 11pt;
                font-weight: bold;
                padding-top: 10px;
                color: #FF4C4C;
            }

            /* Scrollbar (optional for better visual consistency) */
            QScrollBar:vertical {
                border: none;
                background: #1A1A1A;
                width: 8px;
                margin: 0px 0px 0px 0px;
            }
            QScrollBar::handle:vertical {
                background: #FF4C4C;
                min-height: 20px;
                border-radius: 4px;
            }
        """
        self.setStyleSheet(stylesheet)

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)

        # --- Stats Display ---
        main_layout.addWidget(QLabel("<b>Live Statistics</b>"))
        self.stats_display = StatsDisplay()
        main_layout.addWidget(self.stats_display)
        main_layout.addWidget(QFrame(self, frameShape=QFrame.HLine, frameShadow=QFrame.Sunken))

        # --- Collapsible Connection Box ---
        connection_box = CollapsibleBox("Connection Settings", start_expanded=True)
        connection_form = QFormLayout()
        self.server_url_input = QLineEdit("http://192.168.0.10:5000")
        self.client_id_input = QLineEdit("Nate's Miner")
        self.connect_button = QPushButton("Connect to Server")
        connection_form.addRow("Server URL:", self.server_url_input)
        connection_form.addRow("Client ID:", self.client_id_input)
        connection_form.addRow(self.connect_button)
        connection_box.setContentLayout(connection_form)
        main_layout.addWidget(connection_box)

        # --- Collapsible Mining Box ---
        mining_box = CollapsibleBox("Mining Configuration", start_expanded=True)
        mining_form = QFormLayout()
        self.pool_ip_input = QLineEdit("192.168.0.10:3333")
        self.thread_count_input = QLineEdit("4")
        self.mine_button = QPushButton("Start Mining")
        self.stop_button = QPushButton("Stop Mining")
        self.mine_button.setEnabled(False)
        self.stop_button.setEnabled(False)
        mining_form.addRow("Pool Address:", self.pool_ip_input)
        mining_form.addRow("CPU Threads:", self.thread_count_input)
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.mine_button)
        button_layout.addWidget(self.stop_button)
        mining_form.addRow(button_layout)
        mining_box.setContentLayout(mining_form)
        main_layout.addWidget(mining_box)

        # --- Console Output ---
        console_label = QLabel("<b>Console Output:</b>")
        console_label.setObjectName("consoleTitle")
        console_label.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Fixed)  # Keep label small but flexible
        main_layout.addWidget(console_label)

        self.console_output = QPlainTextEdit()
        self.console_output.setReadOnly(True)
        self.console_output.setMinimumHeight(150) # Set fixed height for the console box
        self.console_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        main_layout.addWidget(self.console_output)

        # Add a spacer at the end to push everything up
        main_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

        # Set stretch factors to give more space to the console
        main_layout.setStretch(6, 1)  # Console

    def connect_signals(self):
        """Connects button clicks and logger signals to their handler methods."""
        self.connect_button.clicked.connect(self.handle_connect)
        self.mine_button.clicked.connect(self.handle_start_mining)
        self.stop_button.clicked.connect(self.handle_stop_mining)
        self.logger.message_signal.connect(self.update_console)
        self.stats_update_signal.connect(self.stats_display.update_stats)
        self.force_update_signal.connect(self.handle_force_update)
    @pyqtSlot(str)
    def update_console(self, message):
        """Appends a message to the console widget in a thread-safe way."""
        self.console_output.appendPlainText(message)
    @pyqtSlot(str)
    def handle_force_update(self, download_url):
        """Handles a forced update command from the server, skipping the user prompt."""
        self.logger.log_message("[UPDATE] Forced update triggered by server.")
        self.progress_dialog = QProgressDialog("Downloading forced update...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("Downloading Update")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.show()
        # Start the download process
        asyncio.run_coroutine_threadsafe(self.download_update(self.xmrig_data.aiohttp_client_session, download_url), self.async_worker.loop)
    def handle_connect(self):
        """Handles the 'Connect' button click by starting the async worker."""
        server_url = self.server_url_input.text().strip()
        client_id = self.client_id_input.text().strip()
        if not (server_url and client_id):
            self.logger.log_message("[!] Please provide both Server URL and Client ID.")
            return

        self.xmrig_data.FLASK_SERVER_URL = server_url
        self.xmrig_data.client_id = client_id

        if not self.async_worker or not self.async_worker.isRunning():
            self.logger.log_message("[+] Starting background services...")
            self.async_worker = AsyncWorker(self.run_async_tasks())
            self.async_worker.start()

            self.connect_button.setEnabled(False)
            self.server_url_input.setDisabled(True)
            self.client_id_input.setDisabled(True)
            self.mine_button.setEnabled(True)
            self.stop_button.setEnabled(True)

    def handle_start_mining(self):
        """Validates inputs and schedules the start_miner coroutine."""
        try:
            threads = int(self.thread_count_input.text().strip())
            pool = self.pool_ip_input.text().strip()
            if threads <= 0 or not pool: raise ValueError
        except ValueError:
            self.logger.log_message("[!] Invalid thread count or pool address.")
            return

        if self.async_worker and self.async_worker.isRunning():
            asyncio.run_coroutine_threadsafe(
                self.xmrig_miner.start_miner(pool, threads),
                self.async_worker.loop
            )

    def handle_stop_mining(self):
        """Schedules the stop_miner coroutine."""
        if self.async_worker and self.async_worker.isRunning():
            asyncio.run_coroutine_threadsafe(
                self.xmrig_miner.stop_miner(),
                self.async_worker.loop
            )

    async def run_async_tasks(self):
        """The main async function that orchestrates all background tasks."""
        self.logger.log_message(f"[+] Connecting to {self.xmrig_data.FLASK_SERVER_URL} as {self.xmrig_data.client_id}")
        self.xmrig_data.aiohttp_client_session = aiohttp.ClientSession()

        polling_task = asyncio.create_task(self.xmrig_miner.poll_server(self.xmrig_data.aiohttp_client_session, self.force_update_signal))
        reporter_task = asyncio.create_task(
            self.xmrig_miner.periodic_reporter(self.xmrig_data.aiohttp_client_session, self.stats_update_signal))

        self.logger.log_message("[+] Background services running. Ready to mine.")
        await asyncio.gather(polling_task, reporter_task)

    def closeEvent(self, event):
        """Ensures a clean shutdown when the window is closed."""
        self.logger.log_message("[!] Shutting down application...")
        if self.async_worker and self.async_worker.isRunning():
            self.handle_stop_mining()
            if self.xmrig_data.aiohttp_client_session:
                future = asyncio.run_coroutine_threadsafe(
                    self.xmrig_data.aiohttp_client_session.close(),
                    self.async_worker.loop
                )
                try:
                    future.result(timeout=5)
                except (asyncio.TimeoutError, Exception) as e:
                    self.logger.log_message(f"[!] Error closing session: {e}")

            self.async_worker.loop.call_soon_threadsafe(self.async_worker.loop.stop)
            self.async_worker.wait(5000)
        event.accept()

    def create_and_run_updater_script(self, new_exe_path: str) -> None:
        """
        Creates and runs a Windows batch script to replace the current executable with a new one.
        """
        self.logger.log_message("[+] Started updater script")

        current_exe = os.path.basename(sys.executable)
        base_dir = os.path.dirname(sys.executable)
        new_exe = os.path.basename(new_exe_path)

        # Create a .bat script
        script_content = textwrap.dedent(f"""\
            @echo off
            echo Waiting for application to close...
            timeout /t 2 /nobreak >nul

            echo Killing process {current_exe}...
            taskkill /f /im "{current_exe}" >nul 2>&1

            echo Waiting for file to unlock...
            ping 127.0.0.1 -n 4 >nul

            echo Replacing executable...
            del "{current_exe}" >nul 2>&1
            move /Y "{new_exe}" "{current_exe}"

            echo Relaunching application...
            start "" "{current_exe}"

            echo Cleaning up updater...
            del "%~f0"
        """)

        # Save the .bat file in the same directory as the EXE
        with tempfile.NamedTemporaryFile(delete=False, suffix=".bat", dir=base_dir, mode='w', encoding='utf-8') as tmp:
            tmp.write(script_content)
            updater_bat_path = os.path.normpath(tmp.name)

        # Copy the downloaded new exe into the base directory (if not already there)
        if os.path.dirname(new_exe_path) != base_dir:
            shutil.copy2(new_exe_path, os.path.join(base_dir, new_exe))

        # Run the updater script
        self.logger.log_message(f"[+] Running updater batch file: {updater_bat_path}")
        subprocess.Popen(
            ["cmd.exe", "/c", updater_bat_path],
            cwd=base_dir,
            creationflags=subprocess.CREATE_NEW_CONSOLE
        )

        self.logger.log_message("[+] Exiting current process for updater...")
        os._exit(0)

    async def download_update(self, session, url):
        try:
            async with session.get(url) as response:
                response.raise_for_status()
                total_size = int(response.headers.get('content-length', 0))
                downloaded_size = 0

                base_dir = os.path.dirname(sys.executable)  # ✅ FIX
                save_path = os.path.join(base_dir, "client_new.exe")

                with open(save_path, 'wb') as f:
                    async for chunk in response.content.iter_chunked(8192):
                        f.write(chunk)
                        downloaded_size += len(chunk)
                        self.logger.log_message(f"[+] Downloaded {downloaded_size} bytes / {total_size} bytes")

                self.logger.log_message(f"[+] Download complete: {save_path}")
                self.create_and_run_updater_script(save_path)

        except Exception as e:
            self.logger.log_message(f"[!] Download failed: {e}")
            if self.progress_dialog:
                self.progress_dialog.setValue(0)
                self.progress_dialog.setLabelText("Download Failed!")
                QMessageBox.critical(self, "Error", f"Failed to download update: {e}")