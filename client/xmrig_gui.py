import asyncio
import os

import sys
import shutil
import textwrap
import json
import time

import aiohttp

from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QPlainTextEdit, QLabel,
                             QProgressDialog, QMessageBox,
                             QSystemTrayIcon, QMenu, QAction, QApplication, QDialog,
                             QInputDialog, QStackedWidget)
from PyQt5.QtCore import QObject, pyqtSignal, QThread, pyqtSlot, Qt
from PyQt5.QtGui import QIcon, QPixmap

from xmrig_managers import AsyncTSharkManager, AsyncLinuxManager
from xmrig_gui_elements import StatsDisplay, ConnectionSettingsBox, CollapsibleBox, MiningConfigBox, NetworkPage, \
    SettingsDialog, LinuxPage


# Note: The XmrigData and XmrigMiner classes are imported by main.py and
# instances are passed into this GUI class.

# ==============================================================================
# PYQT5 & ASYNCIO INTEGRATION COMPONENTS
# ==============================================================================

class LinuxLogger(QObject):
    """Logs command output from the WSL Linux environment."""
    message_signal = pyqtSignal(str)

    def log_message(self, msg): self.message_signal.emit(str(msg))


class ConsoleLogger(QObject):
    """
    A QObject that provides a thread-safe way to log messages to the GUI's
    console widget by emitting a PyQt signal.
    """
    message_signal = pyqtSignal(str)

    def log_message(self, msg):
        """Emits a signal containing the log message."""
        self.message_signal.emit(str(msg))


class NetworkLogger(QObject):
    """
    A dedicated logger for network-related messages to keep them
    separate from the main application/miner console.
    """
    message_signal = pyqtSignal(str)

    def log_message(self, msg):
        """Emits a signal containing the network log message."""
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
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)

        try:
            self.loop.run_until_complete(self.coro)
        except Exception as e:
            print(f"[!] AsyncWorker exception: {e}")
        finally:
            pending = asyncio.all_tasks(self.loop)
            for task in pending:
                task.cancel()
            self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            self.loop.close()


class MinerGui(QWidget):
    stats_update_signal = pyqtSignal(dict)
    force_update_signal = pyqtSignal(str)

    def __init__(self, xmrig_data, xmrig_miner, logger, network_logger, linux_logger):
        super().__init__()
        self.xmrig_data = xmrig_data
        self.xmrig_miner = xmrig_miner
        self.logger = logger
        self.network_logger = network_logger
        self.linux_logger = linux_logger
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
        self.setGeometry(100, 100, 800, 750)
        self.setStyleSheet("""
                QWidget { 
                    background-color: #121212; 
                    color: #E0E0E0; 
                    font-family: Segoe UI, sans-serif; 
                    font-size: 10pt; 
                }
                QLabel { 
                    color: #E0E0E0; 
                    background-color: transparent; 
                }

                /* --- THE FIX IS HERE --- */
                QLineEdit, QComboBox {
                    min-height: 32px; /* Set a taller minimum height */
                    background-color: #212121; 
                    padding-left: 10px; /* Add some left padding for text */
                    border-radius: 4px; 
                    border: 1px solid #333333;
                }

                QPushButton { 
                    min-height: 32px; /* Make buttons the same height as inputs */
                    background-color: #B71C1C; 
                    color: #FFFFFF; 
                    border: none; 
                    padding: 0 20px; /* Adjust horizontal padding */
                    border-radius: 4px; 
                    font-weight: bold; 
                }
                /* --- END OF FIX --- */

                QPushButton:hover { background-color: #C62828; } 
                QPushButton:pressed { background-color: #A61A1A; }
                QPushButton:disabled { background-color: #333333; color: #888888; }

                QComboBox::drop-down { border: none; } 
                QComboBox::down-arrow { image: url(no_img); } /* Hides default arrow */

                QPlainTextEdit {
                    background-color: #212121; 
                    padding: 6px; 
                    border-radius: 4px; 
                    color: #E0E0E0; 
                    border: 1px solid #333333;
                }

                QFrame[frameShape="4"] { border-top: 1px solid #333333; }

                QToolButton#collapsibleHeader { 
                    color: #E53935; 
                    font-size: 12pt; 
                    font-weight: bold; 
                    background-color: transparent; 
                    border: none; 
                    text-align: left; 
                    padding: 8px 4px; /* Added more padding for spacing */
                    border-bottom: 1px solid #333333;
                }
                QFormLayout QLabel { font-weight: bold; }

                #consoleTitle, QLabel#sectionHeader { 
                    font-size: 11pt; 
                    font-weight: bold; 
                    color: #CCCCCC; 
                    padding-top: 10px; 
                    padding-bottom: 4px; 
                    margin-bottom: 4px; 
                    border-bottom: 1px solid #333333;
                }
            """)
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)

        # --- Page Navigation ---
        page_nav_layout = QHBoxLayout()
        self.miner_page_button = QPushButton("Miner");
        self.miner_page_button.setObjectName("pageButton");
        self.miner_page_button.setCheckable(True);
        self.miner_page_button.setChecked(True)
        self.network_page_button = QPushButton("Network");
        self.network_page_button.setObjectName("pageButton");
        self.network_page_button.setCheckable(True)
        self.linux_page_button = QPushButton("Linux (WSL)");
        self.linux_page_button.setObjectName("pageButton");
        self.linux_page_button.setCheckable(True)
        page_nav_layout.addWidget(self.miner_page_button);
        page_nav_layout.addWidget(self.network_page_button);
        page_nav_layout.addWidget(self.linux_page_button);
        page_nav_layout.addStretch()
        main_layout.addLayout(page_nav_layout)

        # Main Content Stack
        self.main_stack = QStackedWidget()

        # --- Miner Page ---
        miner_page_widget = QWidget()
        miner_page_layout = QVBoxLayout(miner_page_widget)
        stats_header = QLabel("Live Statistics");
        stats_header.setObjectName("sectionHeader");
        miner_page_layout.addWidget(stats_header)
        self.stats_display = StatsDisplay();
        miner_page_layout.addWidget(self.stats_display)
        self.connection_box = ConnectionSettingsBox()
        connection_collapsible = CollapsibleBox("Connection Settings", start_expanded=True);
        connection_collapsible.setContentWidget(self.connection_box);
        miner_page_layout.addWidget(connection_collapsible)
        self.mining_box = MiningConfigBox(self.xmrig_data)
        mining_collapsible = CollapsibleBox("Mining Configuration", start_expanded=True);
        mining_collapsible.setContentWidget(self.mining_box);
        miner_page_layout.addWidget(mining_collapsible)
        miner_page_layout.addWidget(QLabel("<b>Main Console</b>"))
        self.console_output = QPlainTextEdit();
        self.console_output.setReadOnly(True)
        miner_page_layout.addWidget(self.console_output, 1)

        # --- Network Page ---
        self.network_page = NetworkPage()

        # --- Linux Page ---
        self.linux_page = LinuxPage()

        self.main_stack.addWidget(miner_page_widget)
        self.main_stack.addWidget(self.network_page)
        self.main_stack.addWidget(self.linux_page)
        main_layout.addWidget(self.main_stack, 1)

    def connect_signals(self):
        # ---------------- existing wiring (unchanged) ----------------
        self.connection_box.connect_clicked.connect(self.handle_connect)
        self.mining_box.start_mining_clicked.connect(self.handle_start_mining)
        self.mining_box.stop_mining_clicked.connect(self.handle_stop_mining)
        self.connection_box.save_button.clicked.connect(self.save_settings)
        self.connection_box.load_button.clicked.connect(self.load_settings)
        self.logger.message_signal.connect(self.update_console)
        self.network_logger.message_signal.connect(self.update_network_console)
        self.linux_logger.message_signal.connect(self.update_linux_console)
        self.stats_update_signal.connect(self.stats_display.update_stats)
        self.force_update_signal.connect(self.handle_force_update)

        # ---------------- page‑switch buttons ------------------------
        self.miner_page_button.clicked.connect(lambda: self.switch_main_page(0))
        self.network_page_button.clicked.connect(lambda: self.switch_main_page(1))
        self.linux_page_button.clicked.connect(lambda: self.switch_main_page(2))

        # ---------------- NetworkPage actions ------------------------
        self.network_page.scan_button.clicked.connect(self.handle_scan_button_toggled)

        # ---------------- LinuxPage actions (mirrors Network) --------
        self.linux_page.initialize_wsl_clicked.connect(self.handle_wsl_initialize)
        self.linux_page.shutdown_wsl_clicked.connect(self.handle_wsl_shutdown)
        self.linux_page.command_entered.connect(self.handle_linux_command)

    def switch_main_page(self, index):
        self.main_stack.setCurrentIndex(index)
        self.miner_page_button.setChecked(index == 0)
        self.network_page_button.setChecked(index == 1)
        self.linux_page_button.setChecked(index == 2)

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
        if not os.path.exists(self.gui_settings_path): return []
        try:
            with open(self.gui_settings_path, 'r') as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return []

    def save_settings(self):
        profile_name, ok = QInputDialog.getText(self, "Save Profile", "Enter a name for this profile:")
        if not (ok and profile_name): return
        profiles = self._get_profiles()
        current_settings = {**self.connection_box.get_settings(), **self.mining_box.get_settings()}
        new_profile = {"name": profile_name, "settings": current_settings}
        existing_indices = [i for i, p in enumerate(profiles) if p.get("name") == profile_name]
        if existing_indices:
            reply = QMessageBox.question(self, 'Overwrite Profile?',
                                         f"A profile named '{profile_name}' already exists. Overwrite?",
                                         QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No: return
            profiles[existing_indices[0]] = new_profile
        else:
            profiles.append(new_profile)
        try:
            with open(self.gui_settings_path, 'w') as f:
                json.dump(profiles, f, indent=4)
            self.logger.log_message(f"[+] Profile '{profile_name}' saved successfully.")
        except IOError as e:
            self.logger.log_message(f"[!] Error saving profiles: {e}")

    def load_settings(self):
        profiles = self._get_profiles()
        if not profiles:
            QMessageBox.information(self, "No Profiles", "No saved profiles found.");
            return
        dialog = SettingsDialog(profiles, self)
        if dialog.exec_() == QDialog.Accepted:
            selected = dialog.get_selected_profile()
            if selected: self.apply_settings(selected["settings"]); self.logger.log_message(
                f"[+] Loaded profile: '{selected.get('name')}'.")

    def load_initial_settings(self):
        profiles = self._get_profiles()
        if profiles:
            self.apply_settings(profiles[0]["settings"]); self.logger.log_message(
                "[+] Loaded first saved profile on startup.")
        else:
            self.apply_settings({}); self.logger.log_message("[+] No settings file found, using default values.")

    def apply_settings(self, settings):
        self.connection_box.apply_settings(settings)
        self.mining_box.apply_settings(settings)

    def show_window(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def handle_wsl_initialize(self):

        async def task():

            if self.xmrig_data.linux_manager == None:
                self.xmrig_data.linux_manager = AsyncLinuxManager(self.linux_logger)
                await self.xmrig_data.linux_manager.initialize()
                self.linux_page.set_controls_enabled(self.xmrig_data.linux_manager.is_initialized)
        if self.async_worker and self.async_worker.isRunning():
            asyncio.run_coroutine_threadsafe(task(), self.async_worker.loop)

    def handle_wsl_shutdown(self):
        async def task():
            if self.xmrig_data.linux_manager and self.xmrig_data.linux_manager.is_initialized:
                await self.xmrig_data.linux_manager.close()
                self.xmrig_data.linux_manager.is_initialized = False
                self.linux_page.set_controls_enabled(False)
                self.xmrig_data.linux_manager = None

        if self.async_worker and self.async_worker.isRunning():
            asyncio.run_coroutine_threadsafe(task(), self.async_worker.loop)

    def handle_linux_command(self, command: str):
        async def task():
            if self.xmrig_data.linux_manager and self.xmrig_data.linux_manager.is_initialized:
                await self.xmrig_data.linux_manager.run_command(command)
            else:
                self.linux_logger.log_message(
                    "❌ Cannot execute command: Linux Manager not initialized or WSL requires restart.")

        if self.async_worker and self.async_worker.isRunning():
            asyncio.run_coroutine_threadsafe(task(), self.async_worker.loop)

    @pyqtSlot(str)
    def update_linux_console(self, message):
        self.linux_page.add_output(message)

    @pyqtSlot(str)
    def update_network_console(self, message):
        self.network_page.network_console_output.appendPlainText(message)

    @pyqtSlot(str)
    def update_console(self, message):
        self.console_output.appendPlainText(message)

    def handle_scan_button_toggled(self, checked):
        # This async wrapper is needed because the slot itself cannot be async
        async def task():
            if checked:
                # Ensure the manager exists and is initialized
                if not hasattr(self.xmrig_data, 'tshark_manager') or self.xmrig_data.tshark_manager is None:
                    self.network_logger.log_message("[!] No tshark manager found creating one.")
                    from xmrig_managers import AsyncTSharkManager  # Lazy import
                    self.xmrig_data.tshark_manager = AsyncTSharkManager(
                        self.network_logger,
                        self.connection_box.server_url_input.text().strip(),
                        self.mining_box.pool_ip_input.text().strip()
                    )
                    await self.xmrig_data.tshark_manager.initialize()
                    self.network_logger.log_message("[!] Initialized tshark manager.")
                # Update URLs in case they changed
                self.xmrig_data.tshark_manager.flask_server_url = self.connection_box.server_url_input.text().strip()
                self.xmrig_data.tshark_manager.pool_url = self.mining_box.pool_ip_input.text().strip()
                self.xmrig_data.tshark_manager._known_hosts = self.xmrig_data.tshark_manager._get_known_hosts()

                self.network_logger.log_message("[!] Starting Security scan.")
                self.network_page.scan_button.setText("Stop Security Scan")
                await self.xmrig_data.tshark_manager.start_comprehensive_scan()
            else:
                self.network_page.scan_button.setText("Start Security Scan")
                if hasattr(self.xmrig_data, 'tshark_manager') and self.xmrig_data.tshark_manager:
                    await self.xmrig_data.tshark_manager.stop_all_captures()

        if self.async_worker and self.async_worker.isRunning():
            asyncio.run_coroutine_threadsafe(task(), self.async_worker.loop)

    @pyqtSlot(str)
    def handle_force_update(self, download_url):
        self.logger.log_message(f"[UPDATE] Forced update triggered by server from URL: {download_url}")
        self.progress_dialog = QProgressDialog("Downloading forced update...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("Downloading Update")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.show()
        asyncio.run_coroutine_threadsafe(self.download_update(self.xmrig_data.aiohttp_client_session, download_url),
                                         self.async_worker.loop)

    @pyqtSlot(str, str)
    def handle_connect(self, server_url, client_id):
        if not (server_url and client_id): self.logger.log_message(
            "[!] Please provide both Server URL and Client ID."); return
        self.xmrig_data.FLASK_SERVER_URL, self.xmrig_data.client_id = server_url, client_id
        if not self.async_worker or not self.async_worker.isRunning():
            self.logger.log_message("[+] Starting background services...")
            self.async_worker = AsyncWorker(self.run_async_tasks())
            self.async_worker.start()
            self.connection_box.set_enabled(False)
            self.mining_box.mine_button.setEnabled(True)
            self.mining_box.stop_button.setEnabled(True)

    def handle_start_mining(self):
        try:

            params = self.mining_box.get_values()

            if params["threads"] <= 0 or not params["pool"]: raise ValueError
        except ValueError:
            self.logger.log_message("[!] Invalid thread count or pool address.")
            return
        if self.async_worker and self.async_worker.isRunning():
            self.logger.log_message("[+] Start mining command issued from GUI.")
            self.xmrig_miner.priority = params["high_priority"]
            self.xmrig_miner.cpu_priority = params["cpu_priority"]
            self.xmrig_miner.cpu_yield = params["cpu_yield"]
            self.xmrig_miner.cpu_affinity = params["cpu_affinity"]
            self.xmrig_miner.io_priority = params["io_priority"]
            self.xmrig_miner.memory_usage_min = max(256, params["memory_usage"] * 0.25)
            self.xmrig_miner.memory_usage_max = params["memory_usage"]
            self.xmrig_miner.priority_boost = params["priority_boost"]
            self.xmrig_miner.pl1_pl2 = params["pl1_pl2"]
            self.xmrig_miner.xmrig_msr = params["xmrig_msr"]
            asyncio.run_coroutine_threadsafe(self.xmrig_miner.start_miner(params["pool"], params["threads"]),
                                             self.async_worker.loop)

    def handle_stop_mining(self):
        if self.async_worker and self.async_worker.isRunning():
            self.logger.log_message("[+] Stop mining command issued from GUI.")
            asyncio.run_coroutine_threadsafe(self.xmrig_miner.stop_miner(), self.async_worker.loop)

    async def run_async_tasks(self):
        self.logger.log_message(f"[+] Connecting to {self.xmrig_data.FLASK_SERVER_URL} as {self.xmrig_data.client_id}")
        async with aiohttp.ClientSession() as session:
            self.xmrig_data.aiohttp_client_session = session
            polling_task = asyncio.create_task(self.xmrig_miner.server_poller.run(self.force_update_signal, session))
            reporter_task = asyncio.create_task(
                self.xmrig_miner.periodic_reporter.run(self.stats_update_signal, session))
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

        # --- Start the cleanup process ---
        # Shut down the asyncio worker thread and its tasks
        if self.async_worker and self.async_worker.isRunning():
            # Schedule the async cleanup coroutine to run on the loop
            future = asyncio.run_coroutine_threadsafe(self.async_cleanup(), self.async_worker.loop)
            try:
                # Wait for all async cleanup to finish
                future.result(timeout=5)
            except (asyncio.TimeoutError, Exception) as e:
                self.logger.log_message(f"[!] Error during async cleanup: {e}")

            # Now that async tasks are done, stop the loop and thread
            if self.async_worker.loop.is_running():
                self.async_worker.loop.call_soon_threadsafe(self.async_worker.loop.stop)
            self.async_worker.wait(3000)

        # --- Shut down synchronous components ---
        if self.xmrig_data.hardware_monitor and self.xmrig_data.hardware_monitor.is_alive():
            self.xmrig_data.hardware_monitor.deinitialize()

        if self.xmrig_data.winring_manager and self.xmrig_data.winring_manager.initialized:
            self.xmrig_data.winring_manager.cleanup()

        # Finally, quit the application
        QApplication.instance().quit()

    async def async_cleanup(self):
        """
        A dedicated coroutine to handle the shutdown of all async components.
        """
        self.logger.log_message("   - Stopping async components...")

        # 1. Stop TShark captures first
        if self.xmrig_data.tshark_manager and self.xmrig_data.tshark_manager.is_scanning:
            await self.xmrig_data.tshark_manager.stop_all_captures()

        # 2. Stop the miner
        await self.xmrig_miner.stop_miner()

        # 3. Close the aiohttp session
        if self.xmrig_data.aiohttp_client_session and not self.xmrig_data.aiohttp_client_session.closed:
            await self.xmrig_data.aiohttp_client_session.close()

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
