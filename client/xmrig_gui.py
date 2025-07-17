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
                             QInputDialog, QCheckBox, QGridLayout, QComboBox, QSlider)
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
        self.toggle_button.setObjectName("collapsibleHeader") # Use stylesheet for styling
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

        collapsed_height = self.toggle_button.sizeHint().height() + 10
        # Use a fixed height to ensure it's predictable on startup
        content_height = 250

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

    def setContentWidget(self, widget: QWidget):
        # Clear old layout
        for i in reversed(range(self.content_area_layout.count())):
            old_widget = self.content_area_layout.itemAt(i).widget()
            if old_widget:
                old_widget.setParent(None)
            self.content_area_layout.removeItem(self.content_area_layout.itemAt(i))

        self.content_area_layout.addWidget(widget)

        collapsed_height = self.toggle_button.sizeHint().height() + 10
        content_height = widget.sizeHint().height() + 20

        # Remove existing animations
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

        # Set initial state
        if self.toggle_button.isChecked():
            self.content_area.setMaximumHeight(content_height)
        else:
            self.content_area.setMaximumHeight(0)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Maximum)

class ConnectionSettingsBox(QWidget):
    """A widget for managing connection settings."""
    # Signal emitted when the connect button is clicked
    connect_clicked = pyqtSignal(str, str)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QFormLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setVerticalSpacing(15)

        # Create widgets
        self.server_url_input = QLineEdit()
        self.client_id_input = QLineEdit()
        self.connect_button = QPushButton("Connect to Server")
        self.save_button = QPushButton("Save Settings")
        self.load_button = QPushButton("Load Settings")

        # Connect internal signal
        self.connect_button.clicked.connect(self._on_connect)

        # Layout
        layout.addRow("Server URL:", self.server_url_input)
        layout.addRow("Client ID:", self.client_id_input)

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.connect_button)
        button_layout.addWidget(self.save_button)
        button_layout.addWidget(self.load_button)
        layout.addRow(button_layout)

    def _on_connect(self):
        """Internal handler to gather data and emit the public signal."""
        server_url = self.server_url_input.text().strip()
        client_id = self.client_id_input.text().strip()
        self.connect_clicked.emit(server_url, client_id)

    def get_settings(self):
        """Returns the current settings from this widget as a dict."""
        return {
            "server_url": self.server_url_input.text(),
            "client_id": self.client_id_input.text(),
        }

    def apply_settings(self, settings):
        """Applies a settings dictionary to this widget."""
        self.server_url_input.setText(settings.get("server_url", ""))
        self.client_id_input.setText(settings.get("client_id", ""))

    def set_enabled(self, enabled):
        """Disables or enables input widgets after connection."""
        self.server_url_input.setEnabled(enabled)
        self.client_id_input.setEnabled(enabled)
        self.connect_button.setEnabled(enabled)


class MiningConfigBox(QWidget):
    """A widget for managing mining configuration using a grid layout."""
    start_mining_clicked = pyqtSignal()
    stop_mining_clicked = pyqtSignal()

    def __init__(self, parent=None):
        super().__init__(parent)
        # Use QGridLayout for more control over rows and columns
        layout = QGridLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setVerticalSpacing(15)

        # --- Create Widgets ---
        self.pool_ip_input = QLineEdit()
        self.thread_count_input = QLineEdit()

        # --- ADD THIS WIDGET ---
        self.high_priority_checkbox = QCheckBox("Run as High Priority Process")
        self.high_priority_checkbox.setToolTip("Gives the miner process higher priority in the OS scheduler.\nCan make the system less responsive.")
        self.high_priority_checkbox.setChecked(False) # Default to OFF for safety

        self._total_logical_cpus = psutil.cpu_count(logical=True) or 1
        self.cpu_affinity_slider = QSlider(Qt.Horizontal)
        self.cpu_affinity_slider.setMinimum(1)
        self.cpu_affinity_slider.setMaximum(self._total_logical_cpus)
        self.cpu_affinity_slider.setValue(self._total_logical_cpus)  # default: all CPUs
        self.cpu_affinity_slider.setTickPosition(QSlider.TicksBelow)
        self.cpu_affinity_slider.setTickInterval(1)

        self.cpu_affinity_label = QLabel()
        self.cpu_affinity_label.setText(f"Use {self.cpu_affinity_slider.value()} / {self._total_logical_cpus} CPUs")
        self.cpu_affinity_slider.valueChanged.connect(
            lambda v, lbl=self.cpu_affinity_label, total=self._total_logical_cpus:
            lbl.setText(f"Use {v} / {total} CPUs")
        )

        self.cpu_priority = QComboBox()
        self.cpu_priority.addItem("Idle (1)", 1)
        self.cpu_priority.addItem("Normal (2)", 2)
        self.cpu_priority.addItem("High (3)", 3)
        self.cpu_priority.addItem("Higher (4)", 4)
        self.cpu_priority.addItem("Realtime (5)", 5)
        self.cpu_priority.setCurrentIndex(1)

        # ---- Yield checkbox ----
        self.yield_checkbox = QCheckBox("Yield CPU to other processes")
        self.yield_checkbox.setToolTip("Recommended. Improves system responsiveness.")
        self.yield_checkbox.setChecked(True)

        # ---- Buttons ----
        self.mine_button = QPushButton("Start Mining")
        self.stop_button = QPushButton("Stop Mining")
        self.mine_button.setEnabled(False)
        self.stop_button.setEnabled(False)

        self.mine_button.clicked.connect(self.start_mining_clicked.emit)
        self.stop_button.clicked.connect(self.stop_mining_clicked.emit)

        # --- Layout rows ---

        # Row 0: Pool
        layout.addWidget(QLabel("Pool Address:"), 0, 0)
        layout.addWidget(self.pool_ip_input, 0, 1)

        # Row 1: Threads
        layout.addWidget(QLabel("CPU Threads:"), 1, 0)
        layout.addWidget(self.thread_count_input, 1, 1)

        # Row 2: CPU Affinity slider
        layout.addWidget(QLabel("CPU Affinity:"), 2, 0)
        affinity_row = QHBoxLayout()
        affinity_row.addWidget(self.cpu_affinity_slider, stretch=1)
        affinity_row.addWidget(self.cpu_affinity_label)
        layout.addLayout(affinity_row, 2, 1)

        # Row 3: Internal miner CPU priority
        layout.addWidget(QLabel("CPU Priority:"), 3, 0)
        layout.addWidget(self.cpu_priority, 3, 1)

        # Row 4: OS process priority
        layout.addWidget(QLabel("OS Priority:"), 4, 0)
        layout.addWidget(self.high_priority_checkbox, 4, 1)

        # Row 5: Yield
        layout.addWidget(QLabel("CPU Yield:"), 5, 0)
        layout.addWidget(self.yield_checkbox, 5, 1)

        # Row 6: Buttons
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.mine_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout, 6, 1)

    def get_values(self):
        """Returns all mining parameters in a dictionary."""
        try:
            return {
                "pool": self.pool_ip_input.text().strip(),
                "threads": int(self.thread_count_input.text().strip()),
                "cpu_priority": self.cpu_priority.currentData(),
                "cpu_yield": self.yield_checkbox.isChecked(),
                "high_priority": self.high_priority_checkbox.isChecked(),
                "cpu_affinity":self.cpu_affinity_slider.value(),
            }
        except (ValueError, TypeError):
            return None  # Indicates invalid input

    def get_settings(self):
        """Returns the current settings from this widget as a dict."""
        values = self.get_values()
        return {
            "pool_ip": values.get("pool") if values else "",
            "thread_count": str(values.get("threads")) if values else "",
            "priority_index": self.cpu_priority.currentIndex(),
            "yield_cpu": self.yield_checkbox.isChecked(),
            "high_priority": self.high_priority_checkbox.isChecked(),
            "cpu_affinity": self.cpu_affinity_slider.value(),
        }

    def apply_settings(self, settings):
        """Applies a settings dictionary to this widget."""
        self.pool_ip_input.setText(settings.get("pool_ip", "192.168.0.10:3333"))
        self.thread_count_input.setText(settings.get("thread_count", "8"))
        self.cpu_priority.setCurrentIndex(settings.get("priority_index", 1))
        self.yield_checkbox.setChecked(settings.get("yield_cpu", True))
        self.high_priority_checkbox.setChecked(settings.get("high_priority", True))
        self.cpu_affinity_slider.setValue(settings.get("cpu_affinity", self._total_logical_cpus))

class StatsDisplay(QWidget):
    """A widget to display real-time miner statistics in columns."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QGridLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setHorizontalSpacing(30)

        # Labels
        self.hashrate_label = QLabel("N/A")
        self.cpu_temp_label = QLabel("N/A")
        self.cpu_shares_label = QLabel("0")
        self.gpu_temp_label = QLabel("N/A")
        self.gpu_shares_label = QLabel("0")
        self.power_draw_label = QLabel("N/A")

        # --- Column 1 (CPU + General) ---
        layout.addWidget(QLabel("<b>Hashrate:</b>"), 0, 0)
        layout.addWidget(self.hashrate_label, 0, 1)

        layout.addWidget(QLabel("<b>CPU Temp:</b>"), 1, 0)
        layout.addWidget(self.cpu_temp_label, 1, 1)

        layout.addWidget(QLabel("<b>CPU Shares:</b>"), 2, 0)
        layout.addWidget(self.cpu_shares_label, 2, 1)

        # --- Column 2 (GPU) ---
        layout.addWidget(QLabel("<b>GPU Temp / Fan:</b>"), 0, 2)
        layout.addWidget(self.gpu_temp_label, 0, 3)

        layout.addWidget(QLabel("<b>GPU Shares:</b>"), 1, 2)
        layout.addWidget(self.gpu_shares_label, 1, 3)

        layout.addWidget(QLabel("<b>Power Draw:</b>"), 2, 2)
        layout.addWidget(self.power_draw_label, 2, 3)

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

        stats_header = QLabel("Live Statistics");
        stats_header.setObjectName("sectionHeader")
        main_layout.addWidget(stats_header)
        self.stats_display = StatsDisplay()
        main_layout.addWidget(self.stats_display)

        # --- Create and add the new self-contained widgets ---
        self.connection_box = ConnectionSettingsBox()
        connection_collapsible = CollapsibleBox("Connection Settings", start_expanded=True)
        connection_collapsible.setContentWidget(self.connection_box)
        main_layout.addWidget(connection_collapsible)

        self.mining_box = MiningConfigBox()
        mining_collapsible = CollapsibleBox("Mining Configuration", start_expanded=True)
        mining_collapsible.setContentWidget(self.mining_box)
        main_layout.addWidget(mining_collapsible)

        console_label = QLabel("Console Output");
        console_label.setObjectName("consoleTitle")
        main_layout.addWidget(console_label)
        self.console_output = QPlainTextEdit()
        self.console_output.setReadOnly(True)
        main_layout.addWidget(self.console_output, 1)  # Add stretch factor

    def connect_signals(self):
        self.connection_box.connect_clicked.connect(self.handle_connect)
        self.mining_box.start_mining_clicked.connect(self.handle_start_mining)
        self.mining_box.stop_mining_clicked.connect(self.handle_stop_mining)
        self.connection_box.save_button.clicked.connect(self.save_settings)
        self.connection_box.load_button.clicked.connect(self.load_settings)
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
        if not os.path.exists(self.gui_settings_path): return []
        try:
            with open(self.gui_settings_path, 'r') as f: return json.load(f)
        except (IOError, json.JSONDecodeError): return []

    def save_settings(self):
        profile_name, ok = QInputDialog.getText(self, "Save Profile", "Enter a name for this profile:")
        if not (ok and profile_name): return
        profiles = self._get_profiles()
        current_settings = {**self.connection_box.get_settings(), **self.mining_box.get_settings()}
        new_profile = {"name": profile_name, "settings": current_settings}
        existing_indices = [i for i, p in enumerate(profiles) if p.get("name") == profile_name]
        if existing_indices:
            reply = QMessageBox.question(self, 'Overwrite Profile?', f"A profile named '{profile_name}' already exists. Overwrite?", QMessageBox.Yes | QMessageBox.No, QMessageBox.No)
            if reply == QMessageBox.No: return
            profiles[existing_indices[0]] = new_profile
        else: profiles.append(new_profile)
        try:
            with open(self.gui_settings_path, 'w') as f: json.dump(profiles, f, indent=4)
            self.logger.log_message(f"[+] Profile '{profile_name}' saved successfully.")
        except IOError as e: self.logger.log_message(f"[!] Error saving profiles: {e}")

    def load_settings(self):
        profiles = self._get_profiles()
        if not profiles:
            QMessageBox.information(self, "No Profiles", "No saved profiles found."); return
        dialog = SettingsDialog(profiles, self)
        if dialog.exec_() == QDialog.Accepted:
            selected = dialog.get_selected_profile()
            if selected: self.apply_settings(selected["settings"]); self.logger.log_message(f"[+] Loaded profile: '{selected.get('name')}'.")

    def load_initial_settings(self):
        profiles = self._get_profiles()
        if profiles: self.apply_settings(profiles[0]["settings"]); self.logger.log_message("[+] Loaded first saved profile on startup.")
        else: self.apply_settings({}); self.logger.log_message("[+] No settings file found, using default values.")

    def apply_settings(self, settings):
        self.connection_box.apply_settings(settings)
        self.mining_box.apply_settings(settings)
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
            asyncio.run_coroutine_threadsafe(self.xmrig_miner.start_miner(params["pool"], params["threads"]), self.async_worker.loop)

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

        # Shut down the asyncio worker thread
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

        # --- ADD THIS BLOCK ---
        # Gracefully shut down the hardware monitor thread before exiting
        if self.xmrig_data.hardware_monitor and self.xmrig_data.hardware_monitor.is_alive():
            self.xmrig_data.hardware_monitor.deinitialize()
        # ----------------------

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
