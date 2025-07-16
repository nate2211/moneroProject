import asyncio
import os
import subprocess
import sys
import shutil
import textwrap
import json
import time

import psutil
import tempfile

import aiohttp

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QPlainTextEdit, QLabel, QFormLayout,
                             QFrame, QToolButton, QSizePolicy, QSpacerItem, QProgressDialog, QMessageBox,
                             QSystemTrayIcon, QMenu, QAction, QApplication, QDialogButtonBox, QListWidget, QDialog,
                             QInputDialog)
from PyQt5.QtCore import QObject, pyqtSignal, QThread, pyqtSlot, QParallelAnimationGroup, QPropertyAnimation, \
    QAbstractAnimation, Qt
from PyQt5.QtGui import QIcon, QPixmap


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
class SettingsDialog(QDialog):
    """A dialog window to select a settings profile from a list."""

    def __init__(self, profiles, parent=None):
        super().__init__(parent)
        self.setWindowTitle("Load Settings Profile")
        self.setMinimumWidth(350)

        self.profiles = profiles
        layout = QVBoxLayout(self)

        # Instruction Label
        layout.addWidget(QLabel("Select a profile to load:"))

        # List Widget
        self.list_widget = QListWidget()
        for profile in self.profiles:
            self.list_widget.addItem(profile.get("name", "Unnamed Profile"))

        # Auto-select the first item
        if self.list_widget.count() > 0:
            self.list_widget.setCurrentRow(0)

        layout.addWidget(self.list_widget)

        # Dialog Buttons (OK/Cancel)
        button_box = QDialogButtonBox(QDialogButtonBox.Ok | QDialogButtonBox.Cancel)
        button_box.accepted.connect(self.accept)
        button_box.rejected.connect(self.reject)
        layout.addWidget(button_box)

    def get_selected_profile(self):
        """Returns the full dictionary of the selected profile."""
        current_row = self.list_widget.currentRow()
        if current_row >= 0:
            return self.profiles[current_row]
        return None
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
    stats_update_signal = pyqtSignal(dict)
    force_update_signal = pyqtSignal(str)

    def __init__(self, xmrig_data, xmrig_miner, logger):
        super().__init__()
        self.xmrig_data = xmrig_data
        self.xmrig_miner = xmrig_miner
        self.logger = logger
        self.async_worker = None
        self.gui_settings_path = os.path.join(os.path.dirname(sys.executable), "gui_settings.json")

        self.init_ui()
        self.init_tray_icon()
        self.connect_signals()
        self.load_initial_settings()
        self.show()
        self.logger.log_message("Welcome! GUI Initialized. Please connect to the server.")

    def init_ui(self):
        self.setWindowTitle("Nate's Mining Client")
        self.setGeometry(100, 100, 1000, 700)
        stylesheet = """
            QWidget { background-color: #0D0D0D; color: #FFFFFF; font-family: Segoe UI, sans-serif; font-size: 10pt; }
            QLabel { color: #FFFFFF; background-color: transparent; }
            QPushButton { background-color: #8B0000; color: #FFFFFF; border-top: 1px solid #B22222; border-left: 1px solid #B22222; border-bottom: 1px solid #660000; border-right: 1px solid #660000; padding: 8px 16px; border-radius: 4px; font-weight: bold; }
            QPushButton:hover { background-color: #9B111E; border-top: 1px solid #C83C3C; border-left: 1px solid #C83C3C; border-bottom: 1px solid #7C0A0A; border-right: 1px solid #7C0A0A; }
            QPushButton:pressed { background-color: #660000; border-top: 1px solid #550000; border-left: 1px solid #550000; border-bottom: 1px solid #B22222; border-right: 1px solid #B22222; padding-top: 9px; padding-left: 17px; }
            QPushButton:disabled { background-color: #2A2A2A; color: #888888; border: 1px solid #444444; }
            QLineEdit, QPlainTextEdit { background-color: #1A1A1A; padding: 6px; border-radius: 4px; color: #FFFFFF; border-top: 1px solid #000000; border-left: 1px solid #000000; border-bottom: 1px solid #2E2E2E; border-right: 1px solid #2E2E2E; }
            QFrame { border: 1px solid #252525; }
            QToolButton { color: #FF4C4C; font-size: 12pt; font-weight: bold; background-color: transparent; border: none; }
            QFormLayout QLabel { font-weight: bold; color: #FFFFFF; }
            #consoleTitle { font-size: 11pt; font-weight: bold; padding-top: 10px; color: #FF4C4C; }
            QScrollBar:vertical { border: none; background: #1A1A1A; width: 8px; margin: 0px; }
            QScrollBar::handle:vertical { background: #FF4C4C; min-height: 20px; border-radius: 4px; }
        """
        self.setStyleSheet(stylesheet)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(15)
        main_layout.addWidget(QLabel("<b>Live Statistics</b>"))
        self.stats_display = StatsDisplay()
        main_layout.addWidget(self.stats_display)
        main_layout.addWidget(QFrame(self, frameShape=QFrame.HLine, frameShadow=QFrame.Sunken))
        connection_box = CollapsibleBox("Connection Settings", start_expanded=True)
        connection_form = QFormLayout()
        self.server_url_input = QLineEdit()
        self.client_id_input = QLineEdit()
        self.connect_button = QPushButton("Connect to Server")
        self.save_button = QPushButton("Save Settings")
        self.load_button = QPushButton("Load Settings")
        connection_form.addRow("Server URL:", self.server_url_input)
        connection_form.addRow("Client ID:", self.client_id_input)
        conn_button_layout = QHBoxLayout()
        conn_button_layout.addWidget(self.connect_button)
        conn_button_layout.addWidget(self.save_button)
        conn_button_layout.addWidget(self.load_button)
        connection_form.addRow(conn_button_layout)
        connection_box.setContentLayout(connection_form)
        main_layout.addWidget(connection_box)
        mining_box = CollapsibleBox("Mining Configuration", start_expanded=True)
        mining_form = QFormLayout()
        self.pool_ip_input = QLineEdit()
        self.thread_count_input = QLineEdit()
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
        console_label = QLabel("<b>Console Output:</b>")
        console_label.setObjectName("consoleTitle")
        main_layout.addWidget(console_label)
        # --- CONSOLE WIDGET SETUP ---
        self.console_output = QPlainTextEdit()
        self.console_output.setReadOnly(True)
        # The Expanding size policy is still good practice.
        self.console_output.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        # THE FIX: Add the console widget with a stretch factor of 1.
        # This tells the layout to give all available vertical space to the console.
        main_layout.addWidget(self.console_output, 1)
        main_layout.addSpacerItem(QSpacerItem(20, 40, QSizePolicy.Minimum, QSizePolicy.Expanding))

    def connect_signals(self):
        self.connect_button.clicked.connect(lambda: self.handle_connect(start_mining_on_success=False))
        self.save_button.clicked.connect(self.save_settings)
        self.load_button.clicked.connect(self.load_settings)
        self.mine_button.clicked.connect(self.handle_start_mining)
        self.stop_button.clicked.connect(self.handle_stop_mining)
        self.logger.message_signal.connect(self.update_console)
        self.stats_update_signal.connect(self.stats_display.update_stats)
        self.force_update_signal.connect(self.handle_force_update)
    def resource_path(self, relative_path):
        """ Get absolute path to resource, works for dev and for PyInstaller """
        try:
            # PyInstaller creates a temp folder and stores path in _MEIPASS
            base_path = sys._MEIPASS
        except Exception:
            base_path = os.path.abspath(".")
        return os.path.join(base_path, relative_path)
    def init_tray_icon(self):
        self.tray_icon = QSystemTrayIcon(self)

        icon_path = self.resource_path("icons/icon.png")
        if os.path.exists(icon_path):
            self.tray_icon.setIcon(QIcon(icon_path))
        else:
            self.logger.log_message("[!] icon.png not found. Using default fallback icon.")
            pixmap = QPixmap(32, 32)
            pixmap.fill(Qt.transparent)
            from PyQt5.QtGui import QPainter, QBrush
            painter = QPainter(pixmap)
            painter.setRenderHint(QPainter.Antialiasing)
            painter.setBrush(QBrush(Qt.red))
            painter.setPen(Qt.NoPen)
            painter.drawEllipse(0, 0, 32, 32)
            painter.end()
            self.tray_icon.setIcon(QIcon(pixmap))

        self.tray_icon.setToolTip("Nate's Mining Client")
        tray_menu = QMenu()
        self.show_action = QAction("Show Window", self)
        self.show_action.triggered.connect(self.show_window)
        tray_menu.addAction(self.show_action)
        tray_menu.addSeparator()
        self.start_action = QAction("Start Mining", self)
        self.start_action.triggered.connect(self.handle_start_mining)
        tray_menu.addAction(self.start_action)
        self.stop_action = QAction("Stop Mining", self)
        self.stop_action.triggered.connect(self.handle_stop_mining)
        tray_menu.addAction(self.stop_action)
        tray_menu.addSeparator()
        self.exit_action = QAction("Exit", self)
        self.exit_action.triggered.connect(self.quit_application)
        tray_menu.addAction(self.exit_action)
        self.tray_icon.setContextMenu(tray_menu)
        self.tray_icon.show()
        self.tray_icon.activated.connect(self.handle_tray_activated)
    def handle_tray_activated(self, reason):
        if reason == QSystemTrayIcon.Trigger:
            self.show_window()

    def _get_profiles(self):
        """Helper to safely load profiles from the JSON file."""
        if not os.path.exists(self.gui_settings_path):
            return []
        try:
            with open(self.gui_settings_path, 'r') as f:
                data = json.load(f)
                return data if isinstance(data, list) else []
        except (IOError, json.JSONDecodeError):
            return []

    def save_settings(self):
        """Saves the current GUI settings as a named profile."""
        profile_name, ok = QInputDialog.getText(self, "Save Profile", "Enter a name for this profile:")
        if not (ok and profile_name):
            self.logger.log_message("[!] Save cancelled.")
            return

        current_settings = {
            "server_url": self.server_url_input.text(),
            "client_id": self.client_id_input.text(),
            "pool_ip": self.pool_ip_input.text(),
            "thread_count": self.thread_count_input.text()
        }

        new_profile = {"name": profile_name, "settings": current_settings}
        profiles = self._get_profiles()

        # Check if profile with the same name exists and ask to overwrite
        existing_index = -1
        for i, p in enumerate(profiles):
            if p.get("name") == profile_name:
                existing_index = i
                break

        if existing_index != -1:
            reply = QMessageBox.question(self, 'Overwrite Profile?',
                                         f"A profile named '{profile_name}' already exists. Do you want to overwrite it?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No:
                self.logger.log_message("[!] Overwrite cancelled.")
                return
            profiles[existing_index] = new_profile
        else:
            profiles.append(new_profile)

        try:
            with open(self.gui_settings_path, 'w') as f:
                json.dump(profiles, f, indent=4)
            self.logger.log_message(f"[+] Profile '{profile_name}' saved successfully.")
        except IOError as e:
            self.logger.log_message(f"[!] Error saving profiles: {e}")
            QMessageBox.critical(self, "Error", f"Failed to save settings file: {e}")

    def load_settings(self):
        """Opens a dialog to load a chosen settings profile."""
        profiles = self._get_profiles()
        if not profiles:
            QMessageBox.information(self, "No Profiles", "There are no saved setting profiles to load.")
            return

        dialog = SettingsDialog(profiles, self)
        if dialog.exec_() == QDialog.Accepted:
            selected_profile = dialog.get_selected_profile()
            if selected_profile:
                self.apply_settings(selected_profile["settings"])
                self.logger.log_message(f"[+] Loaded profile: '{selected_profile.get('name')}'.")

    def load_initial_settings(self):
        """Loads the first profile on startup or sets defaults."""
        profiles = self._get_profiles()
        if profiles:
            self.logger.log_message("[+] Loading first saved profile on startup.")
            self.apply_settings(profiles[0]["settings"])
        else:
            self.logger.log_message("[+] No settings file found, using default values.")
            defaults = {
                "server_url": "http://192.168.0.101:5000",
                "client_id": "DefaultMiner",
                "pool_ip": "192.168.0.10:3333",
                "thread_count": "8"
            }
            self.apply_settings(defaults)

    def apply_settings(self, settings):
        """Applies a settings dictionary to the GUI inputs."""
        self.server_url_input.setText(settings.get("server_url", ""))
        self.client_id_input.setText(settings.get("client_id", ""))
        self.pool_ip_input.setText(settings.get("pool_ip", ""))
        self.thread_count_input.setText(settings.get("thread_count", ""))
    def show_window(self):
        self.show()
        self.raise_()
        self.activateWindow()

    @pyqtSlot(str)
    def update_console(self, message):
        self.console_output.appendPlainText(message)

    @pyqtSlot(str)
    def handle_force_update(self, download_url):
        self.logger.log_message(f"[UPDATE] Forced update triggered by server from URL: {download_url}")
        self.progress_dialog = QProgressDialog("Downloading forced update...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("Downloading Update")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.show()
        asyncio.run_coroutine_threadsafe(self.download_update(self.xmrig_data.aiohttp_client_session, download_url),
                                         self.async_worker.loop)

    def handle_connect(self, start_mining_on_success=False):
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
        try:
            threads = int(self.thread_count_input.text().strip())
            pool = self.pool_ip_input.text().strip()
            if threads <= 0 or not pool: raise ValueError
        except ValueError:
            self.logger.log_message("[!] Invalid thread count or pool address.")
            return
        if self.async_worker and self.async_worker.isRunning():
            self.logger.log_message("[+] Start mining command issued from GUI.")
            asyncio.run_coroutine_threadsafe(self.xmrig_miner.start_miner(pool, threads), self.async_worker.loop)

    def handle_stop_mining(self):
        if self.async_worker and self.async_worker.isRunning():
            self.logger.log_message("[+] Stop mining command issued from GUI.")
            asyncio.run_coroutine_threadsafe(self.xmrig_miner.stop_miner(), self.async_worker.loop)

    async def run_async_tasks(self):
        self.logger.log_message(f"[+] Connecting to {self.xmrig_data.FLASK_SERVER_URL} as {self.xmrig_data.client_id}")
        async with aiohttp.ClientSession() as session:
            self.xmrig_data.aiohttp_client_session = session
            polling_task = asyncio.create_task(self.xmrig_miner.server_poller.run(self.force_update_signal, session))
            reporter_task = asyncio.create_task(self.xmrig_miner.periodic_reporter.run(self.stats_update_signal, session))
            self.logger.log_message("[+] Background services running.")
            await asyncio.gather(polling_task, reporter_task)

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "Still Running",
            "The mining client is still running in the background.",
            QSystemTrayIcon.Information,
            2000
        )

    def quit_application(self):
        self.logger.log_message("[!] Exiting application from tray menu...")
        self.tray_icon.hide()
        if self.async_worker and self.async_worker.isRunning():
            self.handle_stop_mining()
            if self.xmrig_data.aiohttp_client_session and not self.xmrig_data.aiohttp_client_session.closed:
                future = asyncio.run_coroutine_threadsafe(self.xmrig_data.aiohttp_client_session.close(),
                                                          self.async_worker.loop)
                try:
                    future.result(timeout=2)
                except (asyncio.TimeoutError, Exception) as e:
                    self.logger.log_message(f"[!] Error closing session: {e}")
            if self.async_worker.loop.is_running():
                self.async_worker.loop.call_soon_threadsafe(self.async_worker.loop.stop)
            self.async_worker.wait(3000)
        QApplication.instance().quit()

    def create_and_run_updater_script(self, new_exe_path: str) -> None:
        self.logger.log_message("[+] Initializing application update process...")
        try:
            current_exe = os.path.basename(sys.executable)
            base_dir = os.path.dirname(sys.executable)
            new_exe_name = "client_new.exe"
            new_exe_temp_path = os.path.join(base_dir, new_exe_name)

            if not os.path.exists(new_exe_path):
                self.logger.log_message(f"[!] CRITICAL: Downloaded update file not found at {new_exe_path}. Aborting.")
                return

            if os.path.normpath(new_exe_path) != os.path.normpath(new_exe_temp_path):
                self.logger.log_message(f"[+] Staging update file to {new_exe_temp_path}...")
                shutil.copy2(new_exe_path, new_exe_temp_path)

            if not os.path.exists(new_exe_temp_path):
                self.logger.log_message(f"[!] ERROR: File {new_exe_temp_path} missing after copy.")
                return

            # === Create .bat script ===
            script_content = textwrap.dedent(f"""\
                @echo off
                title Application Updater
                echo =================================================
                echo.
                echo       THIS SCRIPT IS UPDATING THE APPLICATION
                echo.
                echo =================================================
                echo.
                echo [+] Waiting for the main application to close (3 seconds)...
                %SystemRoot%\\System32\\timeout.exe /t 3 /nobreak >nul
                echo.
                echo [STEP 1] Terminating the running application: {current_exe}
                %SystemRoot%\\System32\\taskkill.exe /f /im "{current_exe}"
                echo      Result Code: %errorlevel% (0=Success, 128=Not Found)
                echo.
                echo [+] Waiting for file locks to be released (5 seconds)...
                %SystemRoot%\\System32\\timeout.exe /t 5 /nobreak >nul
                echo.
                echo [STEP 2] Deleting the old executable...
                del /F /Q "{current_exe}"
                echo      Result Code: %errorlevel% (0=Success)
                echo.
                echo [STEP 3] Verifying new update file exists...
                if not exist "{new_exe_name}" (
                    echo [!!!] ERROR: New update file '{new_exe_name}' not found!
                    goto:fail
                )
                echo      Update file found.
                echo.
                echo [STEP 4] Renaming new version to '{current_exe}'...
                move /Y "{new_exe_name}" "{current_exe}"
                echo      Result Code: %errorlevel% (0=Success)
                echo.
                echo [STEP 5] Relaunching the application...
                start "" "{os.path.join(base_dir, current_exe)}"
                echo.
                echo =================================================
                echo  UPDATE COMPLETE! This window will self-destruct.
                echo =================================================
                goto:end
                :fail
                echo.
                echo [!!!] UPDATE FAILED! Please report the error codes above.
                pause
                :end
                (goto) 2>nul & del "%~f0"
            """)

            updater_bat_path = os.path.join(base_dir, "updater.bat")
            with open(updater_bat_path, "w", encoding="utf-8") as f:
                f.write(script_content)
            self.logger.log_message(f"[+] Updater script created at: {updater_bat_path}")

            self.logger.log_message("[+] Attempting to launch updater via os.startfile...")
            os.startfile(updater_bat_path)

            self.logger.log_message("[+] Exiting current process to allow the update to proceed.")
            time.sleep(1.5)
            if self.xmrig_data.hardware_monitor:
                self.xmrig_data.hardware_monitor.deinitialize()
            sys.exit(0)

        except Exception as e:
            self.logger.log_message(f"[!] CRITICAL: Failed to create or run updater script: {e}")
            QMessageBox.critical(self, "Update Error",
                                 f"Could not create the updater script: {e}\n\nPlease check logs and antivirus settings.")

    # ========================
    # DOWNLOAD AND TRIGGER UPDATE
    # ========================
    async def download_update(self, session, url):
        if self.xmrig_data.client_status == "Started":
            await self.xmrig_miner.stop_miner()

        save_path = os.path.join(os.path.dirname(sys.executable), "client_new.exe")

        try:
            self.logger.log_message(f"[+] Starting download from {url}...")
            async with session.get(url) as response:
                response.raise_for_status()
                total_size = int(response.headers.get('content-length', 0))
                downloaded_size = 0
                with open(save_path, 'wb') as f:
                    async for chunk in response.content.iter_chunked(8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                            if hasattr(self, 'progress_dialog'):
                                progress = int((downloaded_size / total_size) * 100) if total_size > 0 else 0
                                self.progress_dialog.setValue(progress)

            self.logger.log_message(f"[+] Download complete: {save_path}")
            if hasattr(self, 'progress_dialog'):
                self.progress_dialog.setLabelText("Download complete. Starting update...")

            self.create_and_run_updater_script(save_path)

            # Do not delete save_path after calling updater!
            return

        except aiohttp.ClientError as e:
            self.logger.log_message(f"[!] Network error during download: {e}")
            if hasattr(self, 'progress_dialog'): self.progress_dialog.close()
            QMessageBox.critical(self, "Download Error",
                                 f"Could not download the update.\nCheck connection and server URL.\n\nError: {e}")
        except IOError as e:
            self.logger.log_message(f"[!] File error saving update: {e}. Check permissions.")
            if hasattr(self, 'progress_dialog'): self.progress_dialog.close()
            QMessageBox.critical(self, "File Error",
                                 f"Could not save the update file.\nCheck write permissions.\n\nError: {e}")
        except Exception as e:
            self.logger.log_message(f"[!] An unexpected error occurred during update: {e}")
            if hasattr(self, 'progress_dialog'): self.progress_dialog.close()
            QMessageBox.critical(self, "Update Failed", f"An unexpected error occurred: {e}")
