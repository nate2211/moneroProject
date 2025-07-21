import psutil


from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QLabel, QFormLayout,
                             QToolButton, QSizePolicy,
                             QDialogButtonBox, QListWidget, QDialog,
                             QCheckBox, QGridLayout, QComboBox, QSlider, QPlainTextEdit)
from PyQt5.QtCore import  pyqtSignal,  pyqtSlot, QParallelAnimationGroup, QPropertyAnimation, \
    QAbstractAnimation, Qt


class LinuxPage(QWidget):
    """
    A very small terminal‑style page modelled on NetworkPage.
    • One toggle button (Initialize / Shutdown WSL)
    • Read‑only console for log output
    • Hidden command bar that pops up after WSL is ready
    """
    initialize_wsl_clicked = pyqtSignal()
    shutdown_wsl_clicked   = pyqtSignal()
    command_entered        = pyqtSignal(str)

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setSpacing(15)


        btn_bar   = QHBoxLayout()
        self.wsl_btn = QPushButton("Initialize WSL")
        self.wsl_btn.setCheckable(True)
        btn_bar.addWidget(self.wsl_btn)
        btn_bar.addStretch()
        layout.addLayout(btn_bar)


        layout.addWidget(QLabel("<b>Linux Console</b>"))
        self.console = QPlainTextEdit()
        self.console.setReadOnly(True)
        layout.addWidget(self.console, 1)


        self.cmd_bar  = QHBoxLayout()
        self.cmd_edit = QLineEdit()
        self.cmd_edit.setPlaceholderText("Enter Linux command and press Enter…")
        self.run_btn  = QPushButton("Run")
        self.cmd_bar.addWidget(self.cmd_edit, 1)
        self.cmd_bar.addWidget(self.run_btn)
        layout.addLayout(self.cmd_bar)

        # signal ↔ slot
        self.wsl_btn.toggled.connect(self._toggle_wsl_state)
        self.cmd_edit.returnPressed.connect(self._emit_command)
        self.run_btn.clicked.connect(self._emit_command)

    # --------------------------- public api ------------------------------
    def add_output(self, text: str):
        """Append text to console and autoscroll."""
        if text:
            self.console.appendPlainText(text)
            self.console.verticalScrollBar().setValue(self.console.verticalScrollBar().maximum())

    def set_controls_enabled(self, enabled: bool):
        """Enable command bar & change toggle label after WSL init."""
        self.cmd_bar.parent().setVisible(enabled)
        self.cmd_edit.setEnabled(enabled)
        self.run_btn.setEnabled(enabled)
        self.wsl_btn.setChecked(enabled)             # keep state in sync

    # --------------------------- internals -------------------------------
    def _toggle_wsl_state(self, checked: bool):
        # checked == True → WSL running, so button means “Shutdown”
        if checked:
            self.wsl_btn.setText("Shutdown WSL")
            self.initialize_wsl_clicked.emit()
        else:
            self.wsl_btn.setText("Initialize WSL")
            self.shutdown_wsl_clicked.emit()

    def _emit_command(self):
        cmd = self.cmd_edit.text().strip()
        if cmd:
            self.command_entered.emit(cmd)
            self.cmd_edit.clear()
class NetworkPage(QWidget):
    """A dedicated page for network diagnostics and scanning."""

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self);
        layout.setContentsMargins(10, 10, 10, 10);
        layout.setSpacing(15)

        controls_layout = QHBoxLayout()
        self.scan_button = QPushButton("Start Security Scan");
        self.scan_button.setCheckable(True)
        controls_layout.addWidget(self.scan_button)
        layout.addLayout(controls_layout)

        layout.addWidget(QLabel("<b>Network Console</b>"))
        self.network_console_output = QPlainTextEdit();
        self.network_console_output.setReadOnly(True)
        layout.addWidget(self.network_console_output, 1)


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
        self.server_url_input.setText(settings.get("server_url", "http://192.168.0.10:5000"))
        self.client_id_input.setText(settings.get("client_id", "Home"))

    def set_enabled(self, enabled):
        """Disables or enables input widgets after connection."""
        self.server_url_input.setEnabled(enabled)
        self.client_id_input.setEnabled(enabled)
        self.connect_button.setEnabled(enabled)


class MiningConfigBox(QWidget):
    """A widget for managing mining configuration using a grid layout."""
    start_mining_clicked = pyqtSignal()
    stop_mining_clicked = pyqtSignal()

    def __init__(self, xmrig_data, parent=None):
        super().__init__(parent)
        self.xmrig_data = xmrig_data
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


        self.memory_usage_slider = QSlider(Qt.Horizontal)
        self.memory_usage_slider.setMinimum(1)
        self.memory_usage_slider.setMaximum(self.xmrig_data.process_manager.recommend_max_memory())
        self.memory_usage_slider.setValue(self.xmrig_data.process_manager.recommend_max_memory())  # default: all CPUs
        self.memory_usage_slider.setTickPosition(QSlider.TicksBelow)
        self.memory_usage_slider.setTickInterval(1)
        self.memory_usage_label = QLabel()
        self.memory_usage_label.setText(f"Use {self.memory_usage_slider.value()} / {self.xmrig_data.process_manager.recommend_max_memory()} Memory")
        self.memory_usage_slider.valueChanged.connect(
            lambda v, lbl=self.memory_usage_label, total=self.xmrig_data.process_manager.recommend_max_memory():
            lbl.setText(f"Use {v} / {total} Memory")
        )

        self.io_priority = QComboBox()
        self.io_priority.addItem("Very Low", psutil.IOPRIO_VERYLOW)
        self.io_priority.addItem("Low", psutil.IOPRIO_LOW)
        self.io_priority.addItem("Normal", psutil.IOPRIO_NORMAL)


        self.cpu_priority = QComboBox()
        self.cpu_priority.addItem("Idle (1)", 1)
        self.cpu_priority.addItem("Normal (2)", 2)
        self.cpu_priority.addItem("High (3)", 3)
        self.cpu_priority.addItem("Higher (4)", 4)
        self.cpu_priority.addItem("Realtime (5)", 5)

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

        # ---- Priority Boost checkbox ----
        self.priority_boost_checkbox = QCheckBox("Priority Boost")
        self.priority_boost_checkbox.setToolTip(
            "Allows the OS to give threads temporary priority boosts to improve responsiveness.\n"
            "This is ideal for desktop apps but not recommended for background tasks like mining."
        )
        self.priority_boost_checkbox.setChecked(False)

        # ---- Xmrig MSR checkbox ----
        self.xmrig_msr_checkbox = QCheckBox("Xmrig MSR")
        self.xmrig_msr_checkbox.setToolTip(
            "Set the config for xmrig to use or not use MSR Presets."
        )
        self.xmrig_msr_checkbox.setChecked(False)

        # --- NEW WIDGET: Intel Power Limit (PL1/PL2) Slider ---
        self.power_limit_desc_label = QLabel("Power Limit (PL1/PL2):")
        self.power_limit_slider = QSlider(Qt.Horizontal)
        self.power_limit_slider.setMinimum(15)
        self.power_limit_slider.setMaximum(self.xmrig_data.hardware_monitor.get_max_power_draw())
        self.power_limit_slider.setValue(45)
        self.power_limit_slider.setToolTip("Sets CPU power limits (PL1/PL2) in Watts.\nRequires admin/root privileges.")
        self.power_limit_value_label = QLabel(f"{self.power_limit_slider.value()} W")
        self.power_limit_slider.valueChanged.connect(
            lambda v: self.power_limit_value_label.setText(f"{v} W")
        )


        # --- Layout rows ---

        # Row 0: Pool Address + CPU Threads
        layout.addWidget(QLabel("Pool Address:"), 0, 0)
        layout.addWidget(self.pool_ip_input, 0, 1)
        layout.addWidget(QLabel("CPU Threads:"), 0, 2)
        layout.addWidget(self.thread_count_input, 0, 3)

        # Row 1: CPU Affinity + CPU Priority
        layout.addWidget(QLabel("CPU Affinity:"), 1, 0)
        affinity_layout = QHBoxLayout()
        affinity_layout.addWidget(self.cpu_affinity_slider)
        affinity_layout.addWidget(self.cpu_affinity_label)
        layout.addLayout(affinity_layout, 1, 1)

        layout.addWidget(QLabel("CPU Priority:"), 1, 2)
        layout.addWidget(self.cpu_priority, 1, 3)

        # Row 2: OS Priority + CPU Yield
        layout.addWidget(QLabel("OS Priority:"), 2, 0)
        layout.addWidget(self.high_priority_checkbox, 2, 1)
        layout.addWidget(QLabel("CPU Yield:"), 2, 2)
        layout.addWidget(self.yield_checkbox, 2, 3)

        # Row 3: I/O Priority + Memory Usage
        layout.addWidget(QLabel("I/O Priority:"), 3, 0)
        layout.addWidget(self.io_priority, 3, 1)

        layout.addWidget(QLabel("Memory Usage:"), 3, 2)
        mem_layout = QHBoxLayout()
        mem_layout.addWidget(self.memory_usage_slider)
        mem_layout.addWidget(self.memory_usage_label)
        layout.addLayout(mem_layout, 3, 3)

        # Row 4: Priority Boost + Xmrig MSR
        layout.addWidget(QLabel("Priority Boost:"), 4, 0)
        layout.addWidget(self.priority_boost_checkbox, 4, 1)
        layout.addWidget(QLabel("Xmrig MSR:"), 4, 2)
        layout.addWidget(self.xmrig_msr_checkbox, 4, 3)

        # Row 5 (Intel Only): Power Limit slider
        row = 5
        layout.addWidget(self.power_limit_desc_label, row, 0)
        power_layout = QHBoxLayout()
        power_layout.addWidget(self.power_limit_slider)
        power_layout.addWidget(self.power_limit_value_label)
        layout.addLayout(power_layout, row, 1, 1, 3)
        row += 1

        # Row 6: Buttons (mine + stop)
        button_layout = QHBoxLayout()
        button_layout.addWidget(self.mine_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout, row, 0, 1, 4)  # Span across all 4 columns

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
                "io_priority": self.io_priority.currentData(),
                "memory_usage": self.memory_usage_slider.value(),
                "priority_boost": self.priority_boost_checkbox.isChecked(),
                "pl1_pl2": self.power_limit_slider.value(),
                "xmrig_msr": self.xmrig_msr_checkbox.isChecked(),
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
            "io_priority": self.io_priority.currentData(),
            "memory_usage": self.memory_usage_slider.value(),
            "priority_boost": self.priority_boost_checkbox.isChecked(),
            "pl1_pl2": self.power_limit_slider.value(),
            "xmrig_msr": self.xmrig_msr_checkbox.isChecked(),
        }

    def apply_settings(self, settings):
        """Applies a settings dictionary to this widget."""
        self.pool_ip_input.setText(settings.get("pool_ip", "192.168.0.10:3333"))
        self.thread_count_input.setText(settings.get("thread_count", "8"))
        self.cpu_priority.setCurrentIndex(settings.get("priority_index", 1))
        self.yield_checkbox.setChecked(settings.get("yield_cpu", True))
        self.high_priority_checkbox.setChecked(settings.get("high_priority", True))
        self.cpu_affinity_slider.setValue(settings.get("cpu_affinity", self._total_logical_cpus))
        self.io_priority.setCurrentIndex(settings.get("io_priority", psutil.IOPRIO_NORMAL))
        self.memory_usage_slider.setValue(settings.get("memory_usage", self.xmrig_data.process_manager.recommend_max_memory()))
        self.priority_boost_checkbox.setChecked(settings.get("priority_boost", False))
        self.power_limit_slider.setValue(settings.get("pl1_pl2", int(self.xmrig_data.hardware_monitor.get_max_power_draw() / 2)))
        self.xmrig_msr_checkbox.setChecked(settings.get("xmrig_msr", False))

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

