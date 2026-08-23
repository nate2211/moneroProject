import psutil

from xmrig_identity import compose_wallet_user, is_gulf_moneroocean_pool, read_mining_identity


from PyQt5.QtWidgets import (QWidget, QVBoxLayout, QHBoxLayout,
                             QLineEdit, QPushButton, QLabel, QFormLayout,
                             QToolButton, QSizePolicy,
                             QDialogButtonBox, QListWidget, QDialog,
                             QCheckBox, QGridLayout, QComboBox, QSlider, QPlainTextEdit, QSpinBox, QScrollArea)
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
    """Collapsible section with optional internal scrolling.

    Normal sections retain their original natural-size behavior.  Large
    sections, such as Mining Configuration, can opt into a capped scrollable
    viewport so every control remains reachable without fixing the main window
    size.
    """

    def __init__(
        self,
        title="",
        parent=None,
        start_expanded=False,
        scrollable=False,
        max_content_height=360,
        always_show_vertical_scrollbar=False,
    ):
        super().__init__(parent)
        self._scrollable = bool(scrollable)
        self._max_content_height = max(160, int(max_content_height))
        self._expanded_content_height = 0

        self.toggle_button = QToolButton(
            text=title,
            checkable=True,
            checked=start_expanded,
        )
        self.toggle_button.setObjectName("collapsibleHeader")
        self.toggle_button.setToolButtonStyle(Qt.ToolButtonTextBesideIcon)
        self.toggle_button.setArrowType(
            Qt.DownArrow if start_expanded else Qt.RightArrow
        )

        if self._scrollable:
            self.content_area = QScrollArea(self)
            self.content_area.setObjectName("collapsibleScrollArea")
            self.content_area.setWidgetResizable(True)
            self.content_area.setFrameStyle(0)
            self.content_area.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            self.content_area.setVerticalScrollBarPolicy(
                Qt.ScrollBarAlwaysOn
                if always_show_vertical_scrollbar
                else Qt.ScrollBarAsNeeded
            )

            self.content_container = QWidget()
            self.content_container.setObjectName("collapsibleContent")
            self.content_area_layout = QVBoxLayout(self.content_container)
            self.content_area_layout.setContentsMargins(0, 0, 0, 0)
            self.content_area_layout.setSpacing(0)
            self.content_area.setWidget(self.content_container)
        else:
            self.content_area = QWidget(self)
            self.content_area_layout = QVBoxLayout(self.content_area)
            self.content_area_layout.setContentsMargins(0, 0, 0, 0)
            self.content_area_layout.setSpacing(0)

        self.content_area.setMinimumHeight(0)
        self.content_area.setMaximumHeight(0)

        self.toggle_animation = QParallelAnimationGroup(self)

        main_layout = QVBoxLayout(self)
        main_layout.setSpacing(0)
        main_layout.setContentsMargins(0, 0, 0, 0)
        main_layout.addWidget(self.toggle_button)
        main_layout.addWidget(self.content_area)

        self.toggle_button.clicked.connect(self.toggle)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Maximum)

    def _collapsed_height(self):
        return self.toggle_button.sizeHint().height() + 10

    def _clear_content(self):
        while self.content_area_layout.count():
            item = self.content_area_layout.takeAt(0)
            old_widget = item.widget()
            if old_widget is not None:
                old_widget.setParent(None)

    def _configure_animation(self, content_height):
        self._expanded_content_height = max(0, int(content_height))

        while self.toggle_animation.animationCount():
            self.toggle_animation.removeAnimation(
                self.toggle_animation.animationAt(0)
            )

        collapsed_height = self._collapsed_height()
        expanded_height = collapsed_height + self._expanded_content_height

        self.toggle_animation.addAnimation(
            QPropertyAnimation(self, b"minimumHeight")
        )
        self.toggle_animation.addAnimation(
            QPropertyAnimation(self, b"maximumHeight")
        )
        self.toggle_animation.addAnimation(
            QPropertyAnimation(self.content_area, b"maximumHeight")
        )

        for index in range(self.toggle_animation.animationCount()):
            animation = self.toggle_animation.animationAt(index)
            animation.setDuration(220)
            if index < 2:
                animation.setStartValue(collapsed_height)
                animation.setEndValue(expanded_height)
            else:
                animation.setStartValue(0)
                animation.setEndValue(self._expanded_content_height)

        if self.toggle_button.isChecked():
            self.setMinimumHeight(expanded_height)
            self.setMaximumHeight(expanded_height)
            self.content_area.setMaximumHeight(self._expanded_content_height)
        else:
            self.setMinimumHeight(collapsed_height)
            self.setMaximumHeight(collapsed_height)
            self.content_area.setMaximumHeight(0)

    @pyqtSlot(bool)
    def toggle(self, checked):
        self.toggle_button.setArrowType(
            Qt.DownArrow if checked else Qt.RightArrow
        )
        self.toggle_animation.setDirection(
            QAbstractAnimation.Forward
            if checked
            else QAbstractAnimation.Backward
        )
        self.toggle_animation.start()

    def setContentLayout(self, layout):
        host = QWidget()
        host.setLayout(layout)
        self.setContentWidget(host)

    def setContentWidget(self, widget: QWidget):
        self._clear_content()

        if self._scrollable:
            widget.setParent(self.content_container)
        else:
            widget.setParent(self.content_area)

        widget.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Preferred)
        widget.ensurePolished()
        if widget.layout() is not None:
            widget.layout().activate()
        widget.adjustSize()
        natural_height = max(1, widget.sizeHint().height() + 8)

        if self._scrollable:
            # Preserve the full option page as scrollable content.  The Start
            # and Stop buttons remain in the final grid row and are reachable
            # by moving the vertical scrollbar to the bottom.
            widget.setMinimumHeight(natural_height)
            self.content_container.setMinimumHeight(natural_height)
            viewport_height = min(self._max_content_height, natural_height)
            self.content_area_layout.addWidget(widget)
            self._configure_animation(viewport_height)
        else:
            self.content_area_layout.addWidget(widget)
            self._configure_animation(natural_height)

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
        self._config_identity = read_mining_identity(self.xmrig_data.CONFIG_PATH)
        # Use QGridLayout for more control over rows and columns
        layout = QGridLayout(self)
        layout.setContentsMargins(10, 10, 10, 10)
        layout.setVerticalSpacing(15)



        # --- Create Widgets ---
        self.pool_ip_input = QLineEdit()
        self.pool_ip_input.setPlaceholderText("gulf.moneroocean.stream:10128")
        self.thread_count_input = QLineEdit()

        self.wallet_input = QLineEdit()
        self.wallet_input.setPlaceholderText("Actual wallet address / pool username")
        self.wallet_input.setToolTip(
            "The base wallet value written to pools[].user. The optional difficulty suffix is managed separately."
        )
        self.append_difficulty_checkbox = QCheckBox("Append fixed difficulty to wallet")
        self.append_difficulty_checkbox.setToolTip(
            "Writes the effective pool user as wallet+difficulty. Leave disabled when your pool uses port-based difficulty."
        )
        self.wallet_difficulty = QSpinBox()
        self.wallet_difficulty.setRange(1, 2_147_483_647)
        self.wallet_difficulty.setValue(max(1, int(self._config_identity.difficulty)))
        self.wallet_difficulty.setToolTip("Difficulty appended to the effective wallet username.")
        self.effective_wallet_label = QLabel()
        self.effective_wallet_label.setTextInteractionFlags(Qt.TextSelectableByMouse)

        self.use_moneroocean_native_checkbox = QCheckBox("Use MoneroOcean native DLL")
        self.use_moneroocean_native_checkbox.setToolTip(
            "Uses NateMiningNative.dll for Gulf MoneroOcean pool profiling, output parsing, and watchdog decisions. "
            "Python fallbacks remain available."
        )
        self.python_runtime_checkbox = QCheckBox("Enable PythonRuntime.dll (isolated)")
        self.python_runtime_checkbox.setToolTip(
            "Enables the bounded native asynchronous diagnostics queue. XMRig remains the hashing engine."
        )
        self.python_usage_checkbox = QCheckBox("Enable PythonUsage.dll (isolated)")
        self.python_usage_checkbox.setToolTip(
            "Starts the native callback worker that samples the latest XMRig hashrate from Python."
        )
        self.python_usage_interval = QSpinBox()
        self.python_usage_interval.setRange(50, 60_000)
        self.python_usage_interval.setValue(1000)
        self.python_usage_interval.setSuffix(" ms")
        self.python_usage_interval.setToolTip("PythonUsage native callback interval.")
        self.native_mode_label = QLabel()
        self.native_mode_label.setWordWrap(True)
        self.optional_dll_note_label = QLabel(
            "PythonRuntime and PythonUsage run in a separate helper process. "
            "They provide diagnostics only and cannot block XMRig hashing."
        )
        self.optional_dll_note_label.setWordWrap(True)

        self.wallet_input.textChanged.connect(self._update_wallet_preview)
        self.append_difficulty_checkbox.toggled.connect(self._update_wallet_preview)
        self.append_difficulty_checkbox.toggled.connect(self.wallet_difficulty.setEnabled)
        self.wallet_difficulty.valueChanged.connect(self._update_wallet_preview)
        self.pool_ip_input.textChanged.connect(self._update_native_mode_label)
        self.use_moneroocean_native_checkbox.toggled.connect(self._update_native_mode_label)
        self.python_usage_checkbox.toggled.connect(self.python_usage_interval.setEnabled)

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

        # ---- GPU settings ----
        # XMRig Default is intentionally first and selected by default. In this mode
        # the application enables a detected NVIDIA GPU but does not inject an rx
        # launch table, allowing XMRig/CUDA to choose its own stock launch settings.
        self.gpu_preset = QComboBox()
        self.gpu_preset.addItem("XMRig Default", "xmrig_default")
        self.gpu_preset.addItem("Existing Auto-Tuned Preset", "auto_tuned")
        self.gpu_preset.addItem("Manual CUDA Preset", "manual")
        self.gpu_preset.setCurrentIndex(0)
        self.gpu_preset.setToolTip(
            "XMRig Default leaves CUDA launch parameters to XMRig.\n"
            "Existing Auto-Tuned Preset uses the GPU tuner already included in this client.\n"
            "Manual CUDA Preset uses the values below."
        )

        self.cuda_enabled = QCheckBox("Enable NVIDIA CUDA mining")
        self.cuda_enabled.setChecked(True)
        self.cuda_enabled.setToolTip(
            "Enabled by default when an NVIDIA GPU is detected. Disable this to mine CPU-only."
        )

        self.opencl_enabled = QCheckBox("Enable OpenCL mining")
        self.opencl_enabled.setChecked(False)
        self.opencl_enabled.setToolTip(
            "Enable only when your XMRig build includes the OpenCL plugin and you want AMD/Intel GPU mining."
        )

        self.gpu_threads = QSpinBox()
        self.gpu_threads.setRange(1, 128)
        self.gpu_threads.setValue(32)
        self.gpu_threads.setToolTip("Manual CUDA threads per block.")

        self.gpu_blocks = QSpinBox()
        self.gpu_blocks.setRange(1, 4096)
        self.gpu_blocks.setValue(24)
        self.gpu_blocks.setToolTip("Manual CUDA block count.")

        self.gpu_bfactor = QSpinBox()
        self.gpu_bfactor.setRange(0, 12)
        self.gpu_bfactor.setValue(6)
        self.gpu_bfactor.setToolTip("Higher values split GPU work into smaller portions and improve responsiveness.")

        self.gpu_bsleep = QSpinBox()
        self.gpu_bsleep.setRange(0, 1000)
        self.gpu_bsleep.setValue(25)
        self.gpu_bsleep.setSuffix(" us")
        self.gpu_bsleep.setToolTip("Delay between CUDA work portions. Zero gives maximum throughput.")

        self.gpu_dataset_host = QCheckBox("Keep RandomX dataset in host memory")
        self.gpu_dataset_host.setChecked(False)

        self.gpu_preset.currentIndexChanged.connect(self._update_gpu_manual_controls)

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
        row = 0
        layout.addWidget(QLabel("Pool Address:"), row, 0)
        layout.addWidget(self.pool_ip_input, row, 1)
        layout.addWidget(QLabel("CPU Threads:"), row, 2)
        layout.addWidget(self.thread_count_input, row, 3)
        row += 1

        layout.addWidget(QLabel("Actual Wallet:"), row, 0)
        layout.addWidget(self.wallet_input, row, 1, 1, 3)
        row += 1

        layout.addWidget(self.append_difficulty_checkbox, row, 0, 1, 2)
        layout.addWidget(QLabel("Wallet Difficulty:"), row, 2)
        layout.addWidget(self.wallet_difficulty, row, 3)
        row += 1

        layout.addWidget(QLabel("Effective Pool User:"), row, 0)
        layout.addWidget(self.effective_wallet_label, row, 1, 1, 3)
        row += 1

        layout.addWidget(self.use_moneroocean_native_checkbox, row, 0, 1, 2)
        layout.addWidget(self.python_runtime_checkbox, row, 2)
        layout.addWidget(self.python_usage_checkbox, row, 3)
        row += 1

        layout.addWidget(self.optional_dll_note_label, row, 0, 1, 4)
        row += 1

        layout.addWidget(QLabel("PythonUsage Interval:"), row, 0)
        layout.addWidget(self.python_usage_interval, row, 1)
        layout.addWidget(self.native_mode_label, row, 2, 1, 2)
        row += 1

        layout.addWidget(QLabel("CPU Affinity:"), row, 0)
        affinity_layout = QHBoxLayout()
        affinity_layout.addWidget(self.cpu_affinity_slider)
        affinity_layout.addWidget(self.cpu_affinity_label)
        layout.addLayout(affinity_layout, row, 1)
        layout.addWidget(QLabel("CPU Priority:"), row, 2)
        layout.addWidget(self.cpu_priority, row, 3)
        row += 1

        layout.addWidget(QLabel("OS Priority:"), row, 0)
        layout.addWidget(self.high_priority_checkbox, row, 1)
        layout.addWidget(QLabel("CPU Yield:"), row, 2)
        layout.addWidget(self.yield_checkbox, row, 3)
        row += 1

        layout.addWidget(QLabel("I/O Priority:"), row, 0)
        layout.addWidget(self.io_priority, row, 1)
        layout.addWidget(QLabel("Memory Usage:"), row, 2)
        mem_layout = QHBoxLayout()
        mem_layout.addWidget(self.memory_usage_slider)
        mem_layout.addWidget(self.memory_usage_label)
        layout.addLayout(mem_layout, row, 3)
        row += 1

        layout.addWidget(QLabel("Priority Boost:"), row, 0)
        layout.addWidget(self.priority_boost_checkbox, row, 1)
        layout.addWidget(QLabel("Xmrig MSR:"), row, 2)
        layout.addWidget(self.xmrig_msr_checkbox, row, 3)
        row += 1

        layout.addWidget(self.power_limit_desc_label, row, 0)
        power_layout = QHBoxLayout()
        power_layout.addWidget(self.power_limit_slider)
        power_layout.addWidget(self.power_limit_value_label)
        layout.addLayout(power_layout, row, 1, 1, 3)
        row += 1

        layout.addWidget(QLabel("GPU Preset:"), row, 0)
        layout.addWidget(self.gpu_preset, row, 1)
        layout.addWidget(self.cuda_enabled, row, 2)
        layout.addWidget(self.opencl_enabled, row, 3)
        row += 1

        layout.addWidget(QLabel("CUDA Threads:"), row, 0)
        layout.addWidget(self.gpu_threads, row, 1)
        layout.addWidget(QLabel("CUDA Blocks:"), row, 2)
        layout.addWidget(self.gpu_blocks, row, 3)
        row += 1

        layout.addWidget(QLabel("CUDA B-Factor:"), row, 0)
        layout.addWidget(self.gpu_bfactor, row, 1)
        layout.addWidget(QLabel("CUDA B-Sleep:"), row, 2)
        layout.addWidget(self.gpu_bsleep, row, 3)
        row += 1

        layout.addWidget(self.gpu_dataset_host, row, 0, 1, 4)
        row += 1

        button_layout = QHBoxLayout()
        button_layout.addWidget(self.mine_button)
        button_layout.addWidget(self.stop_button)
        layout.addLayout(button_layout, row, 0, 1, 4)
        self._update_gpu_manual_controls()
        self._update_wallet_preview()
        self._update_native_mode_label()
        self.python_usage_interval.setEnabled(self.python_usage_checkbox.isChecked())

    def _update_wallet_preview(self, *_):
        effective = compose_wallet_user(
            self.wallet_input.text(),
            self.append_difficulty_checkbox.isChecked(),
            self.wallet_difficulty.value(),
        )
        self.effective_wallet_label.setText(effective or "<wallet not set>")

    def _update_native_mode_label(self, *_):
        gulf = is_gulf_moneroocean_pool(self.pool_ip_input.text())
        native = self.use_moneroocean_native_checkbox.isChecked()
        if gulf and native:
            text = "Gulf MoneroOcean: native pool parser/watchdog selected; algorithm negotiation stays enabled."
        elif gulf:
            text = "Gulf MoneroOcean: Python fallback selected; algorithm negotiation stays enabled."
        elif native:
            text = "Native DLL is enabled, but Gulf-specific behavior activates only for gulf.moneroocean.stream."
        else:
            text = "Python-only pool handling selected."
        self.native_mode_label.setText(text)

    def _update_gpu_manual_controls(self):
        manual = self.gpu_preset.currentData() == "manual"
        for widget in (self.gpu_threads, self.gpu_blocks, self.gpu_bfactor,
                       self.gpu_bsleep, self.gpu_dataset_host):
            widget.setEnabled(manual)

    def get_values(self):
        """Returns all mining parameters in a dictionary."""
        try:
            return {
                "pool": self.pool_ip_input.text().strip(),
                "threads": int(self.thread_count_input.text().strip()),
                "wallet": self.wallet_input.text().strip(),
                "append_wallet_difficulty": self.append_difficulty_checkbox.isChecked(),
                "wallet_difficulty": self.wallet_difficulty.value(),
                "effective_wallet": compose_wallet_user(
                    self.wallet_input.text(),
                    self.append_difficulty_checkbox.isChecked(),
                    self.wallet_difficulty.value(),
                ),
                "use_moneroocean_native": self.use_moneroocean_native_checkbox.isChecked(),
                "python_runtime_enabled": self.python_runtime_checkbox.isChecked(),
                "python_usage_enabled": self.python_usage_checkbox.isChecked(),
                "python_usage_interval_ms": self.python_usage_interval.value(),
                "cpu_priority": self.cpu_priority.currentData(),
                "cpu_yield": self.yield_checkbox.isChecked(),
                "high_priority": self.high_priority_checkbox.isChecked(),
                "cpu_affinity":self.cpu_affinity_slider.value(),
                "io_priority": self.io_priority.currentData(),
                "memory_usage": self.memory_usage_slider.value(),
                "priority_boost": self.priority_boost_checkbox.isChecked(),
                "pl1_pl2": self.power_limit_slider.value(),
                "xmrig_msr": self.xmrig_msr_checkbox.isChecked(),
                "gpu_preset": self.gpu_preset.currentData(),
                "cuda_enabled": self.cuda_enabled.isChecked(),
                "opencl_enabled": self.opencl_enabled.isChecked(),
                "gpu_threads": self.gpu_threads.value(),
                "gpu_blocks": self.gpu_blocks.value(),
                "gpu_bfactor": self.gpu_bfactor.value(),
                "gpu_bsleep": self.gpu_bsleep.value(),
                "gpu_dataset_host": self.gpu_dataset_host.isChecked(),
            }
        except (ValueError, TypeError):
            return None  # Indicates invalid input

    def get_settings(self):
        """Returns the current settings from this widget as a dict."""
        values = self.get_values()
        return {
            "pool_ip": values.get("pool") if values else "",
            "thread_count": str(values.get("threads")) if values else "",
            "wallet": self.wallet_input.text().strip(),
            "append_wallet_difficulty": self.append_difficulty_checkbox.isChecked(),
            "wallet_difficulty": self.wallet_difficulty.value(),
            "use_moneroocean_native": self.use_moneroocean_native_checkbox.isChecked(),
            "python_runtime_enabled": self.python_runtime_checkbox.isChecked(),
            "python_usage_enabled": self.python_usage_checkbox.isChecked(),
            "python_usage_interval_ms": self.python_usage_interval.value(),
            "priority_index": self.cpu_priority.currentIndex(),
            "yield_cpu": self.yield_checkbox.isChecked(),
            "high_priority": self.high_priority_checkbox.isChecked(),
            "cpu_affinity": self.cpu_affinity_slider.value(),
            "io_priority": self.io_priority.currentData(),
            "memory_usage": self.memory_usage_slider.value(),
            "priority_boost": self.priority_boost_checkbox.isChecked(),
            "pl1_pl2": self.power_limit_slider.value(),
            "xmrig_msr": self.xmrig_msr_checkbox.isChecked(),
            "gpu_preset": self.gpu_preset.currentData(),
            "cuda_enabled": self.cuda_enabled.isChecked(),
            "opencl_enabled": self.opencl_enabled.isChecked(),
            "gpu_threads": self.gpu_threads.value(),
            "gpu_blocks": self.gpu_blocks.value(),
            "gpu_bfactor": self.gpu_bfactor.value(),
            "gpu_bsleep": self.gpu_bsleep.value(),
            "gpu_dataset_host": self.gpu_dataset_host.isChecked(),
        }

    def apply_settings(self, settings):
        """Applies a settings dictionary to this widget."""
        default_pool = self._config_identity.pool_url or "gulf.moneroocean.stream:10128"
        self.pool_ip_input.setText(settings.get("pool_ip", default_pool))
        self.thread_count_input.setText(settings.get("thread_count", "8"))
        self.wallet_input.setText(settings.get("wallet", self._config_identity.wallet))
        self.append_difficulty_checkbox.setChecked(settings.get(
            "append_wallet_difficulty", self._config_identity.append_difficulty
        ))
        self.wallet_difficulty.setValue(int(settings.get(
            "wallet_difficulty", self._config_identity.difficulty or 10000
        )))
        default_native = is_gulf_moneroocean_pool(self.pool_ip_input.text())
        self.use_moneroocean_native_checkbox.setChecked(settings.get("use_moneroocean_native", default_native))
        self.python_runtime_checkbox.setChecked(settings.get("python_runtime_enabled", False))
        self.python_usage_checkbox.setChecked(settings.get("python_usage_enabled", False))
        self.python_usage_interval.setValue(int(settings.get("python_usage_interval_ms", 1000)))
        self.cpu_priority.setCurrentIndex(settings.get("priority_index", 1))
        self.yield_checkbox.setChecked(settings.get("yield_cpu", True))
        self.high_priority_checkbox.setChecked(settings.get("high_priority", True))
        self.cpu_affinity_slider.setValue(settings.get("cpu_affinity", self._total_logical_cpus))
        self.io_priority.setCurrentIndex(settings.get("io_priority", psutil.IOPRIO_NORMAL))
        self.memory_usage_slider.setValue(settings.get("memory_usage", self.xmrig_data.process_manager.recommend_max_memory()))
        self.priority_boost_checkbox.setChecked(settings.get("priority_boost", False))
        self.power_limit_slider.setValue(settings.get("pl1_pl2", int(self.xmrig_data.hardware_monitor.get_max_power_draw() / 2)))
        self.xmrig_msr_checkbox.setChecked(settings.get("xmrig_msr", False))

        preset = settings.get("gpu_preset", "xmrig_default")
        preset_index = self.gpu_preset.findData(preset)
        self.gpu_preset.setCurrentIndex(preset_index if preset_index >= 0 else 0)
        self.cuda_enabled.setChecked(settings.get("cuda_enabled", True))
        self.opencl_enabled.setChecked(settings.get("opencl_enabled", False))
        self.gpu_threads.setValue(int(settings.get("gpu_threads", 32)))
        self.gpu_blocks.setValue(int(settings.get("gpu_blocks", 24)))
        self.gpu_bfactor.setValue(int(settings.get("gpu_bfactor", 6)))
        self.gpu_bsleep.setValue(int(settings.get("gpu_bsleep", 25)))
        self.gpu_dataset_host.setChecked(settings.get("gpu_dataset_host", False))
        self._update_gpu_manual_controls()
        self.wallet_difficulty.setEnabled(self.append_difficulty_checkbox.isChecked())
        self.python_usage_interval.setEnabled(self.python_usage_checkbox.isChecked())
        self._update_wallet_preview()
        self._update_native_mode_label()

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
