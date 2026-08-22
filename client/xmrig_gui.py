import asyncio
import json
import os
import shutil
import sys
import textwrap
import time

import aiohttp
from PyQt5.QtCore import QObject, QThread, Qt, pyqtSignal, pyqtSlot
from PyQt5.QtGui import QIcon, QPixmap
from PyQt5.QtWidgets import (
    QAction,
    QApplication,
    QDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QMenu,
    QMessageBox,
    QPlainTextEdit,
    QProgressDialog,
    QPushButton,
    QStackedWidget,
    QSystemTrayIcon,
    QVBoxLayout,
    QWidget,
)

from xmrig_gui_elements import (
    CollapsibleBox,
    ConnectionSettingsBox,
    LinuxPage,
    MiningConfigBox,
    NetworkPage,
    SettingsDialog,
    StatsDisplay,
)
from xmrig_managers import AsyncLinuxManager, AsyncTSharkManager


class LinuxLogger(QObject):
    message_signal = pyqtSignal(str)

    def log_message(self, msg):
        self.message_signal.emit(str(msg))


class ConsoleLogger(QObject):
    message_signal = pyqtSignal(str)

    def log_message(self, msg):
        self.message_signal.emit(str(msg))


class NetworkLogger(QObject):
    message_signal = pyqtSignal(str)

    def log_message(self, msg):
        self.message_signal.emit(str(msg))


class AsyncWorker(QThread):
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
            try:
                pending = asyncio.all_tasks(self.loop)
                for task in pending:
                    task.cancel()
                if pending:
                    self.loop.run_until_complete(asyncio.gather(*pending, return_exceptions=True))
            finally:
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
        self._shutdown_requested = False
        self._active_session = None
        self._polling_task = None
        self._reporter_task = None
        self.progress_dialog = None

        self.gui_settings_path = os.path.join(self._settings_base_dir(), "gui_settings.json")

        self.init_ui()
        self.init_tray_icon()
        self.connect_signals()
        self.load_initial_settings()
        self.show()
        self.logger.log_message("Welcome! GUI Initialized. Please connect to the server.")

    def _settings_base_dir(self):
        if getattr(sys, "frozen", False):
            return os.path.dirname(sys.executable)
        return os.path.abspath(os.path.dirname(__file__))

    def init_ui(self):
        self.setWindowTitle("Nate's Mining Client")
        self.setGeometry(100, 100, 800, 750)
        self.setStyleSheet(
            """
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
                QLineEdit, QComboBox {
                    min-height: 32px;
                    background-color: #212121;
                    padding-left: 10px;
                    border-radius: 4px;
                    border: 1px solid #333333;
                }
                QPushButton {
                    min-height: 32px;
                    background-color: #B71C1C;
                    color: #FFFFFF;
                    border: none;
                    padding: 0 20px;
                    border-radius: 4px;
                    font-weight: bold;
                }
                QPushButton:hover { background-color: #C62828; }
                QPushButton:pressed { background-color: #A61A1A; }
                QPushButton:disabled { background-color: #333333; color: #888888; }
                QComboBox::drop-down { border: none; }
                QComboBox::down-arrow { image: url(no_img); }
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
                    padding: 8px 4px;
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
            """
        )

        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(15, 15, 15, 15)
        main_layout.setSpacing(10)

        page_nav_layout = QHBoxLayout()
        self.miner_page_button = QPushButton("Miner")
        self.miner_page_button.setObjectName("pageButton")
        self.miner_page_button.setCheckable(True)
        self.miner_page_button.setChecked(True)

        self.network_page_button = QPushButton("Network")
        self.network_page_button.setObjectName("pageButton")
        self.network_page_button.setCheckable(True)

        self.linux_page_button = QPushButton("Linux (WSL)")
        self.linux_page_button.setObjectName("pageButton")
        self.linux_page_button.setCheckable(True)

        page_nav_layout.addWidget(self.miner_page_button)
        page_nav_layout.addWidget(self.network_page_button)
        page_nav_layout.addWidget(self.linux_page_button)
        page_nav_layout.addStretch()
        main_layout.addLayout(page_nav_layout)

        self.main_stack = QStackedWidget()

        miner_page_widget = QWidget()
        miner_page_layout = QVBoxLayout(miner_page_widget)
        stats_header = QLabel("Live Statistics")
        stats_header.setObjectName("sectionHeader")
        miner_page_layout.addWidget(stats_header)

        self.stats_display = StatsDisplay()
        miner_page_layout.addWidget(self.stats_display)

        self.connection_box = ConnectionSettingsBox()
        connection_collapsible = CollapsibleBox("Connection Settings", start_expanded=True)
        connection_collapsible.setContentWidget(self.connection_box)
        miner_page_layout.addWidget(connection_collapsible)

        self.mining_box = MiningConfigBox(self.xmrig_data)
        mining_collapsible = CollapsibleBox("Mining Configuration", start_expanded=True)
        mining_collapsible.setContentWidget(self.mining_box)
        miner_page_layout.addWidget(mining_collapsible)

        miner_page_layout.addWidget(QLabel("<b>Main Console</b>"))
        self.console_output = QPlainTextEdit()
        self.console_output.setReadOnly(True)
        miner_page_layout.addWidget(self.console_output, 1)

        self.network_page = NetworkPage()
        self.linux_page = LinuxPage()

        self.main_stack.addWidget(miner_page_widget)
        self.main_stack.addWidget(self.network_page)
        self.main_stack.addWidget(self.linux_page)
        main_layout.addWidget(self.main_stack, 1)

    def connect_signals(self):
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

        self.miner_page_button.clicked.connect(lambda: self.switch_main_page(0))
        self.network_page_button.clicked.connect(lambda: self.switch_main_page(1))
        self.linux_page_button.clicked.connect(lambda: self.switch_main_page(2))

        self.network_page.scan_button.clicked.connect(self.handle_scan_button_toggled)
        self.linux_page.initialize_wsl_clicked.connect(self.handle_wsl_initialize)
        self.linux_page.shutdown_wsl_clicked.connect(self.handle_wsl_shutdown)
        self.linux_page.command_entered.connect(self.handle_linux_command)

    def switch_main_page(self, index):
        self.main_stack.setCurrentIndex(index)
        self.miner_page_button.setChecked(index == 0)
        self.network_page_button.setChecked(index == 1)
        self.linux_page_button.setChecked(index == 2)

    def resource_path(self, relative_path):
        try:
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
            from PyQt5.QtGui import QBrush, QPainter
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
        if not os.path.exists(self.gui_settings_path):
            return []
        try:
            with open(self.gui_settings_path, "r", encoding="utf-8") as f:
                return json.load(f)
        except (IOError, json.JSONDecodeError):
            return []

    def save_settings(self):
        profile_name, ok = QInputDialog.getText(self, "Save Profile", "Enter a name for this profile:")
        if not (ok and profile_name):
            return

        profiles = self._get_profiles()
        current_settings = {**self.connection_box.get_settings(), **self.mining_box.get_settings()}
        new_profile = {"name": profile_name, "settings": current_settings}

        existing_indices = [i for i, p in enumerate(profiles) if p.get("name") == profile_name]
        if existing_indices:
            reply = QMessageBox.question(
                self,
                "Overwrite Profile?",
                f"A profile named '{profile_name}' already exists. Overwrite?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if reply == QMessageBox.No:
                return
            profiles[existing_indices[0]] = new_profile
        else:
            profiles.append(new_profile)

        try:
            with open(self.gui_settings_path, "w", encoding="utf-8") as f:
                json.dump(profiles, f, indent=4)
            self.logger.log_message(f"[+] Profile '{profile_name}' saved successfully.")
        except IOError as e:
            self.logger.log_message(f"[!] Error saving profiles: {e}")

    def load_settings(self):
        profiles = self._get_profiles()
        if not profiles:
            QMessageBox.information(self, "No Profiles", "No saved profiles found.")
            return

        dialog = SettingsDialog(profiles, self)
        if dialog.exec_() == QDialog.Accepted:
            selected = dialog.get_selected_profile()
            if selected:
                self.apply_settings(selected["settings"])
                self.logger.log_message(f"[+] Loaded profile: '{selected.get('name')}'.")

    def load_initial_settings(self):
        profiles = self._get_profiles()
        if profiles:
            self.apply_settings(profiles[0]["settings"])
            self.logger.log_message("[+] Loaded first saved profile on startup.")
        else:
            self.apply_settings({})
            self.logger.log_message("[+] No settings file found, using default values.")

    def apply_settings(self, settings):
        self.connection_box.apply_settings(settings)
        self.mining_box.apply_settings(settings)

    def show_window(self):
        self.show()
        self.raise_()
        self.activateWindow()

    def _build_http_session(self):
        timeout = aiohttp.ClientTimeout(total=30, connect=10, sock_connect=10, sock_read=20)
        connector = aiohttp.TCPConnector(
            limit=20,
            limit_per_host=10,
            ttl_dns_cache=300,
            enable_cleanup_closed=True,
            force_close=False,
        )
        return aiohttp.ClientSession(timeout=timeout, connector=connector)

    def _submit_async(self, coro):
        if self.async_worker and self.async_worker.isRunning() and self.async_worker.loop:
            return asyncio.run_coroutine_threadsafe(coro, self.async_worker.loop)
        self.logger.log_message("[!] Background async worker is not running.")
        return None

    def handle_wsl_initialize(self):
        async def task():
            if self.xmrig_data.linux_manager is None:
                self.xmrig_data.linux_manager = AsyncLinuxManager(self.linux_logger)
                await self.xmrig_data.linux_manager.initialize()
                self.linux_page.set_controls_enabled(self.xmrig_data.linux_manager.is_initialized)

        self._submit_async(task())

    def handle_wsl_shutdown(self):
        async def task():
            if self.xmrig_data.linux_manager and self.xmrig_data.linux_manager.is_initialized:
                await self.xmrig_data.linux_manager.close()
                self.xmrig_data.linux_manager.is_initialized = False
                self.linux_page.set_controls_enabled(False)
                self.xmrig_data.linux_manager = None

        self._submit_async(task())

    def handle_linux_command(self, command: str):
        async def task():
            if self.xmrig_data.linux_manager and self.xmrig_data.linux_manager.is_initialized:
                await self.xmrig_data.linux_manager.run_command(command)
            else:
                self.linux_logger.log_message(
                    "❌ Cannot execute command: Linux Manager not initialized or WSL requires restart."
                )

        self._submit_async(task())

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
        async def task():
            if checked:
                if not getattr(self.xmrig_data, "tshark_manager", None):
                    self.network_logger.log_message("[!] No tshark manager found creating one.")
                    self.xmrig_data.tshark_manager = AsyncTSharkManager(
                        self.network_logger,
                        self.connection_box.server_url_input.text().strip(),
                        self.mining_box.pool_ip_input.text().strip(),
                    )
                    await self.xmrig_data.tshark_manager.initialize()
                    self.network_logger.log_message("[!] Initialized tshark manager.")

                self.xmrig_data.tshark_manager.flask_server_url = self.connection_box.server_url_input.text().strip()
                self.xmrig_data.tshark_manager.pool_url = self.mining_box.pool_ip_input.text().strip()
                self.xmrig_data.tshark_manager._known_hosts = self.xmrig_data.tshark_manager._get_known_hosts()

                self.network_logger.log_message("[!] Starting Security scan.")
                self.network_page.scan_button.setText("Stop Security Scan")
                await self.xmrig_data.tshark_manager.start_comprehensive_scan()
            else:
                self.network_page.scan_button.setText("Start Security Scan")
                if getattr(self.xmrig_data, "tshark_manager", None):
                    await self.xmrig_data.tshark_manager.stop_all_captures()

        self._submit_async(task())

    @pyqtSlot(str)
    def handle_force_update(self, download_url):
        self.logger.log_message(f"[UPDATE] Forced update triggered by server from URL: {download_url}")
        self.progress_dialog = QProgressDialog("Downloading forced update...", "Cancel", 0, 100, self)
        self.progress_dialog.setWindowTitle("Downloading Update")
        self.progress_dialog.setWindowModality(Qt.WindowModal)
        self.progress_dialog.show()
        self._submit_async(self.download_update(self.xmrig_data.aiohttp_client_session, download_url))

    @pyqtSlot(str, str)
    def handle_connect(self, server_url, client_id):
        server_url = (server_url or "").strip()
        client_id = (client_id or "").strip()

        if not (server_url and client_id):
            self.logger.log_message("[!] Please provide both Server URL and Client ID.")
            return

        self.xmrig_data.FLASK_SERVER_URL = server_url
        self.xmrig_data.client_id = client_id

        if not self.async_worker or not self.async_worker.isRunning():
            self.logger.log_message("[+] Starting background services...")
            self._shutdown_requested = False
            self.async_worker = AsyncWorker(self.run_async_tasks())
            self.async_worker.start()
            self.connection_box.set_enabled(False)
            self.mining_box.mine_button.setEnabled(True)
            self.mining_box.stop_button.setEnabled(True)
        else:
            self.logger.log_message(
                "[+] Updated server connection settings. Background services will reuse them automatically."
            )

    def handle_start_mining(self):
        try:
            params = self.mining_box.get_values()
            if params["threads"] <= 0 or not params["pool"]:
                raise ValueError
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
            self.xmrig_miner.gpu_preset = params["gpu_preset"]
            self.xmrig_miner.cuda_enabled = params["cuda_enabled"]
            self.xmrig_miner.opencl_enabled = params["opencl_enabled"]
            self.xmrig_miner.gpu_threads = params["gpu_threads"]
            self.xmrig_miner.gpu_blocks = params["gpu_blocks"]
            self.xmrig_miner.gpu_bfactor = params["gpu_bfactor"]
            self.xmrig_miner.gpu_bsleep = params["gpu_bsleep"]
            self.xmrig_miner.gpu_dataset_host = params["gpu_dataset_host"]
            self._submit_async(self.xmrig_miner.start_miner(params["pool"], params["threads"]))

    def handle_stop_mining(self):
        if self.async_worker and self.async_worker.isRunning():
            self.logger.log_message("[+] Stop mining command issued from GUI.")
            self._submit_async(self.xmrig_miner.stop_miner())

    async def run_async_tasks(self):
        self.logger.log_message(
            f"[+] Connecting to {self.xmrig_data.FLASK_SERVER_URL} as {self.xmrig_data.client_id}"
        )

        backoff = 1

        while not self._shutdown_requested:
            session = None
            self._polling_task = None
            self._reporter_task = None

            try:
                session = self._build_http_session()
                self._active_session = session
                self.xmrig_data.aiohttp_client_session = session

                self._polling_task = asyncio.create_task(
                    self.xmrig_miner.server_poller.run(self.force_update_signal, session)
                )
                self._reporter_task = asyncio.create_task(
                    self.xmrig_miner.periodic_reporter.run(self.stats_update_signal, session)
                )

                self.logger.log_message("[+] Background services running.")
                backoff = 1

                done, pending = await asyncio.wait(
                    {self._polling_task, self._reporter_task},
                    return_when=asyncio.FIRST_EXCEPTION,
                )

                for task in pending:
                    task.cancel()
                if pending:
                    await asyncio.gather(*pending, return_exceptions=True)

                for task in done:
                    exc = task.exception()
                    if exc is not None:
                        raise exc

                if not self._shutdown_requested:
                    raise RuntimeError("A background task exited unexpectedly.")

            except asyncio.CancelledError:
                break

            except Exception as e:
                if self._shutdown_requested:
                    break
                self.logger.log_message(f"[!] Background service loop interrupted: {e}")
                self.logger.log_message(
                    f"[!] Remote control/reporting will retry automatically in {backoff}s."
                )
                await asyncio.sleep(backoff)
                backoff = min(30, backoff * 2)

            finally:
                tasks = [t for t in (self._polling_task, self._reporter_task) if t is not None]
                for task in tasks:
                    if not task.done():
                        task.cancel()
                if tasks:
                    await asyncio.gather(*tasks, return_exceptions=True)

                self._polling_task = None
                self._reporter_task = None

                if session is not None and not session.closed:
                    await session.close()
                if self.xmrig_data.aiohttp_client_session is session:
                    self.xmrig_data.aiohttp_client_session = None
                if self._active_session is session:
                    self._active_session = None

    def closeEvent(self, event):
        event.ignore()
        self.hide()
        self.tray_icon.showMessage(
            "Still Running",
            "The mining client is still running in the background.",
            QSystemTrayIcon.Information,
            2000,
        )

    def quit_application(self):
        self.logger.log_message("[!] Exiting application from tray menu...")
        self.tray_icon.hide()
        self._shutdown_requested = True

        if self.async_worker and self.async_worker.isRunning():
            future = asyncio.run_coroutine_threadsafe(self.async_cleanup(), self.async_worker.loop)
            try:
                future.result(timeout=10)
            except (asyncio.TimeoutError, Exception) as e:
                self.logger.log_message(f"[!] Error during async cleanup: {e}")
            self.async_worker.wait(5000)
            if self.async_worker.isRunning() and self.async_worker.loop and self.async_worker.loop.is_running():
                self.async_worker.loop.call_soon_threadsafe(self.async_worker.loop.stop)
                self.async_worker.wait(3000)

        if self.xmrig_data.hardware_monitor and self.xmrig_data.hardware_monitor.is_alive():
            self.xmrig_data.hardware_monitor.deinitialize()

        if self.xmrig_data.winring_manager and self.xmrig_data.winring_manager.initialized:
            self.xmrig_data.winring_manager.cleanup()

        QApplication.instance().quit()

    async def async_cleanup(self):
        self.logger.log_message("   - Stopping async components...")

        if self.xmrig_data.tshark_manager and self.xmrig_data.tshark_manager.is_scanning:
            await self.xmrig_data.tshark_manager.stop_all_captures()

        if self.xmrig_data.linux_manager and self.xmrig_data.linux_manager.is_initialized:
            await self.xmrig_data.linux_manager.close()
            self.xmrig_data.linux_manager.is_initialized = False

        if hasattr(self.xmrig_miner, "close"):
            await self.xmrig_miner.close()
        else:
            await self.xmrig_miner.stop_miner()

        tasks = [t for t in (self._polling_task, self._reporter_task) if t is not None]
        for task in tasks:
            if not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

        if self.xmrig_data.aiohttp_client_session and not self.xmrig_data.aiohttp_client_session.closed:
            await self.xmrig_data.aiohttp_client_session.close()
            self.xmrig_data.aiohttp_client_session = None

    def create_and_run_updater_script(self, new_exe_path: str) -> None:
        self.logger.log_message("[+] Initializing application update process...")
        try:
            current_exe = os.path.basename(sys.executable)
            base_dir = os.path.dirname(sys.executable)
            new_exe_name = "client_new.exe"
            new_exe_temp_path = os.path.join(base_dir, new_exe_name)

            if not os.path.exists(new_exe_path):
                self.logger.log_message(
                    f"[!] CRITICAL: Downloaded update file not found at {new_exe_path}. Aborting."
                )
                return

            if os.path.normpath(new_exe_path) != os.path.normpath(new_exe_temp_path):
                self.logger.log_message(f"[+] Staging update file to {new_exe_temp_path}...")
                shutil.copy2(new_exe_path, new_exe_temp_path)

            if not os.path.exists(new_exe_temp_path):
                self.logger.log_message(f"[!] ERROR: File {new_exe_temp_path} missing after copy.")
                return

            script_content = textwrap.dedent(
                f"""\
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
                """
            )

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
            QMessageBox.critical(
                self,
                "Update Error",
                f"Could not create the updater script: {e}\n\nPlease check logs and antivirus settings.",
            )

    async def download_update(self, session, url):
        if self.xmrig_data.client_status == "Started":
            await self.xmrig_miner.stop_miner()

        save_path = os.path.join(os.path.dirname(sys.executable), "client_new.exe")
        owned_session = False

        try:
            if session is None or session.closed:
                session = self._build_http_session()
                owned_session = True

            self.logger.log_message(f"[+] Starting download from {url}...")
            async with session.get(url) as response:
                response.raise_for_status()
                total_size = int(response.headers.get("content-length", 0))
                downloaded_size = 0

                with open(save_path, "wb") as f:
                    async for chunk in response.content.iter_chunked(8192):
                        if chunk:
                            f.write(chunk)
                            downloaded_size += len(chunk)
                            if self.progress_dialog is not None:
                                progress = int((downloaded_size / total_size) * 100) if total_size > 0 else 0
                                self.progress_dialog.setValue(progress)

            self.logger.log_message(f"[+] Download complete: {save_path}")
            if self.progress_dialog is not None:
                self.progress_dialog.setLabelText("Download complete. Starting update...")

            self.create_and_run_updater_script(save_path)
            return

        except aiohttp.ClientError as e:
            self.logger.log_message(f"[!] Network error during download: {e}")
            if self.progress_dialog is not None:
                self.progress_dialog.close()
            QMessageBox.critical(
                self,
                "Download Error",
                f"Could not download the update.\nCheck connection and server URL.\n\nError: {e}",
            )

        except IOError as e:
            self.logger.log_message(f"[!] File error saving update: {e}. Check permissions.")
            if self.progress_dialog is not None:
                self.progress_dialog.close()
            QMessageBox.critical(
                self,
                "File Error",
                f"Could not save the update file.\nCheck write permissions.\n\nError: {e}",
            )

        except Exception as e:
            self.logger.log_message(f"[!] An unexpected error occurred during update: {e}")
            if self.progress_dialog is not None:
                self.progress_dialog.close()
            QMessageBox.critical(self, "Update Failed", f"An unexpected error occurred: {e}")

        finally:
            if owned_session and session is not None and not session.closed:
                await session.close()
