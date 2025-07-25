import logging
import re
from typing import List
import queue
import threading
import asyncio
from PyQt5.QtWidgets import QWidget, QLineEdit, QLabel, QComboBox, QGroupBox, QFormLayout, QPushButton, QPlainTextEdit, \
    QVBoxLayout, QHBoxLayout, QTextEdit
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot, QThread, QTimer
from p2pool_managers import PacketManager
from p2pool_ai import GeminiChatBot


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


logger = logging.getLogger(__name__) # This logger is for this module's internal debug, not for GUI display


class GeminiChatWorker(QObject):
    """
    A QObject worker that runs the GeminiChatBot's send_message method in a separate thread.
    This prevents the GUI from freezing during API calls.
    """
    response_received = pyqtSignal(str)
    error_occurred = pyqtSignal(str)
    thinking_started = pyqtSignal()
    thinking_finished = pyqtSignal()
    # The 'finished' signal is retained but will NOT be used to quit the thread after every message.
    # It can be used for other purposes if needed, or removed if strictly not required.
    finished = pyqtSignal()

    def __init__(self, logger_instance, chatbot: GeminiChatBot):  # Accepts logger_instance and chatbot
        super().__init__()
        self.chatbot = chatbot
        self.logger = logger_instance  # Store the provided logger instance

    @pyqtSlot(str)
    def process_message(self, user_message: str):
        """
        Slot to receive user messages from the GUI and send them to the chatbot.
        Emits signals for response, error, and thinking status.
        """
        self.thinking_started.emit()
        try:
            # The chatbot's internal logging will now go through the logger_instance passed to it
            response = self.chatbot.send_message(user_message)
            self.response_received.emit(response)
        except Exception as e:
            # This catches any unexpected errors from the chatbot's send_message itself
            self.logger.log_message(f"Error in GeminiChatWorker: {e}")  # Use the provided logger
            self.error_occurred.emit(f"An internal error occurred: {e}")
        finally:
            self.thinking_finished.emit()
            # IMPORTANT: Removed self.finished.emit() here. The worker should NOT
            # signal completion after every message, as it needs to stay alive
            # to process subsequent messages. The thread will be quit on app shutdown.


class GeminiChatTab(QWidget):
    """
    A QWidget that encapsulates all UI elements and logic for the Gemini Chat tab.
    It manages the input, output, and interaction with the GeminiChatWorker.
    """
    send_message_requested = pyqtSignal(str)  # Signal to send user input to the worker

    def __init__(self, gemini_logger, parent=None):  # Accepts gemini_logger instance
        super().__init__(parent)
        self.gemini_logger = gemini_logger  # Store the logger instance

        # NEW: Add a timer and state for the "thinking" animation
        self.thinking_timer = QTimer(self)
        self.thinking_animation_state = 0

        self._create_widgets()
        self._configure_layout()
        self._connect_signals()

        # Initialize the chatbot backend FIRST
        self.chatbot_backend = GeminiChatBot(self.gemini_logger,  # Pass self.gemini_logger
                                             initial_instruction="You are a highly intelligent and analytical AI assistant. "
                                                                 "When providing code, please format it as if it were output from a blank terminal. "
                                                                 "Ensure there's ample blank space (e.g., a few empty lines) before and after "
                                                                 "code blocks to make them easy to copy and paste. "
                                                                 "Provide comprehensive and insightful responses, "
                                                                 "offering detailed explanations, multiple perspectives, "
                                                                 "and asking clarifying questions when necessary to deepen the conversation. "
                                                                 "Always maintain a professional and helpful tone. More about myself my name is Nate and im coding a huge solo project."
                                             )
        # THEN setup the worker thread, passing the already initialized chatbot_backend
        self._setup_worker_thread()  # This now happens AFTER chatbot_backend is initialized

        # Initial message for Gemini tab, logged via the consistent log_message method

    def _create_widgets(self):
        """Creates all the widgets for the tab."""
        self.chat_output = QTextEdit()
        self.chat_output.setReadOnly(True)
        self.chat_output.setPlaceholderText("Gemini's responses will appear here...")

        self.user_input = QPlainTextEdit()  # Changed from QLineEdit to QPlainTextEdit
        self.user_input.setPlaceholderText("Type your message here...")
        self.user_input.setFixedHeight(80)  # Give it an initial height for multi-line input

        self.send_button = QPushButton("Send")
        self.send_button.setObjectName("send_button")  # For potential styling

        self.clear_history_button = QPushButton("Clear History")
        self.clear_history_button.setObjectName("clear_history_button")

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #dcdcdc; font-style: italic;")

    def _configure_layout(self):
        """Sets up the layout for the tab."""
        main_layout = QVBoxLayout(self)

        # Output console
        main_layout.addWidget(self.chat_output, 1)  # Stretch factor 1 to take available space

        # Input and buttons
        # The input field is now QPlainTextEdit, which handles its own line breaks.
        # The send button and clear history button should be next to it.
        input_and_buttons_layout = QHBoxLayout()
        input_and_buttons_layout.addWidget(self.user_input, 1)  # Stretch factor 1 for input area

        button_column_layout = QVBoxLayout()
        button_column_layout.addWidget(self.send_button)
        button_column_layout.addWidget(self.clear_history_button)
        button_column_layout.addStretch(1)  # Push buttons to the top of their column

        input_and_buttons_layout.addLayout(button_column_layout)

        main_layout.addLayout(input_and_buttons_layout)
        main_layout.addWidget(self.status_label)

    def _connect_signals(self):
        """Connects UI element signals to handler methods."""
        self.send_button.clicked.connect(self._on_send_button_clicked)
        self.clear_history_button.clicked.connect(self._on_clear_history_clicked)

        # ADDED: Connect the timer's timeout signal to the animation slot
        self.thinking_timer.timeout.connect(self._update_thinking_animation)

    def _setup_worker_thread(self):
        """Sets up the QThread and worker for background API calls."""
        self.worker_thread = QThread()
        # Pass the gemini_logger instance AND the already initialized chatbot_backend to the worker
        self.worker = GeminiChatWorker(self.gemini_logger, self.chatbot_backend)
        self.worker.moveToThread(self.worker_thread)

        # Connect signals from worker to GUI slots
        self.worker.response_received.connect(self._handle_gemini_response)
        self.worker.error_occurred.connect(self._handle_gemini_error)
        self.worker.thinking_started.connect(self._on_thinking_started)
        self.worker.thinking_finished.connect(self._on_thinking_finished)

        # Connect GUI signal to worker slot
        self.send_message_requested.connect(self.worker.process_message)

        self.worker_thread.started.connect(lambda: self.gemini_logger.log_message("GeminiChatWorker thread started."))
        self.worker_thread.start()

    @pyqtSlot()
    def _on_send_button_clicked(self):
        """Handles the send button click."""
        user_message = self.user_input.toPlainText().strip()  # Use toPlainText() for QPlainTextEdit
        if user_message:
            # Pass only the raw message, log_message will add prefixes/styling
            self.log_message(user_message, "user")
            self.user_input.clear()
            self.send_message_requested.emit(user_message)
        else:
            self.gemini_loggerlog_message("Please enter a non-empty message.")

    @pyqtSlot()
    def _on_clear_history_clicked(self):
        """Clears the chat output and the chatbot's internal history."""
        self.chat_output.clear()
        self.chatbot_backend.clear_chat_history()
        self.gemini_logger.log_message("Chat history cleared.")

    @pyqtSlot(str)
    def _handle_gemini_response(self, response: str):
        """
        Receives and displays Gemini's response, parsing for code blocks.
        """

        code_block_pattern = re.compile(r"```(?P<lang>\w*)\n(?P<code>.*?)\n```", re.DOTALL)

        last_idx = 0
        formatted_response_parts = []

        for match in code_block_pattern.finditer(response):
            # Add text before the code block
            if match.start() > last_idx:
                text_before = response[last_idx:match.start()].strip()
                if text_before:
                    formatted_response_parts.append(f"<p>{self._escape_html(text_before)}</p>")

            # Add the code block
            lang = match.group('lang')
            code = match.group('code')
            # Using <pre><code> for code blocks for better formatting and copy-pasteability
            # Added inline styles for code block appearance, and extra margin for spacing
            formatted_response_parts.append(
                f"<div style='margin-top:10px; margin-bottom:10px;'>"  # Add vertical spacing around code block
                f"<pre style='background-color:#2a2a2a; color:#f8f8f2; padding:15px; border-radius:8px; overflow-x:auto; border:1px solid #444;'>"
                f"<div style='font-family:Consolas, Courier New, monospace; font-size:11px; white-space:pre-wrap;'>{self._escape_html(code)}</div>"
                f"</pre>"
                f"</div>"
            )
            last_idx = match.end()

        # Add any remaining text after the last code block
        if last_idx < len(response):
            text_after = response[last_idx:].strip()
            if text_after:
                formatted_response_parts.append(f"<p>{self._escape_html(text_after)}</p>")

        # If no code blocks were found, treat the entire response as plain text
        if not formatted_response_parts and response.strip():
            formatted_response_parts.append(f"<p>{self._escape_html(response)}</p>")
        elif not formatted_response_parts:  # Handle empty response
            formatted_response_parts.append("<p><i>(Empty response)</i></p>")

        # Join all parts and log them. log_message will now add the "Gemini:" prefix and color.
        full_html_content = "".join(formatted_response_parts)
        self.gemini_logger.log_message(full_html_content, "gemini")

    @pyqtSlot(str)
    def _handle_gemini_error(self, error_message: str):
        """Receives and displays error messages from the worker."""
        self.gemini_loggerlog_message(error_message, "error")

    # NEW: Slot for handling the timer's timeout signal to animate text
    @pyqtSlot()
    def _update_thinking_animation(self):
        """Cycles through animation states to update the status text."""
        # Cycle through 1, 2, or 3 dots
        self.thinking_animation_state = (self.thinking_animation_state % 3) + 1
        dots = "." * self.thinking_animation_state

        # Update the labels
        self.status_label.setText(f"Gemini is thinking{dots}")
        self.send_button.setText(f"Thinking{dots}")

    # MODIFIED: Start the timer when thinking begins
    @pyqtSlot()
    def _on_thinking_started(self):
        """Updates UI when Gemini starts thinking and starts the animation timer."""
        self.send_button.setEnabled(False)
        self.user_input.setEnabled(False)
        self.status_label.setStyleSheet("color: #ffff00; font-style: italic;")  # Yellow for thinking

        # Reset animation state and start the timer
        self.thinking_animation_state = 0
        self._update_thinking_animation()  # Call once immediately for instant feedback
        self.thinking_timer.start(500)  # Update every 500ms

    # MODIFIED: Stop the timer when thinking finishes
    @pyqtSlot()
    def _on_thinking_finished(self):
        """Updates UI when Gemini finishes thinking and stops the animation timer."""
        self.thinking_timer.stop()  # Stop the animation timer

        self.send_button.setEnabled(True)
        self.user_input.setEnabled(True)
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("color: #dcdcdc; font-style: italic;")  # Back to default
        self.send_button.setText("Send")

    def _escape_html(self, text: str) -> str:
        """Escapes HTML special characters in a string."""
        # Ensure proper escaping for display in HTML
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'",
                                                                                                                   "&#x27;")

    @pyqtSlot(str, str)  # Changed signature to accept content and message_type
    def log_message(self, content: str, message_type: str = "info"):
        """
        Appends a message to the chat output via the GeminiLogger, with appropriate styling.
        The 'content' argument should be the raw text or pre-formatted HTML for the message body.
        'message_type' can be "user", "gemini", "error", or "info".
        """
        prefix = ""
        color = ""

        if message_type == "user":
            prefix = "<b>You:</b> "
            color = "#87CEEB"  # Light blue
        elif message_type == "gemini":
            prefix = "<b>Gemini:</b> "
            color = "#90EE90"  # Light green
        elif message_type == "error":
            prefix = "<b>ERROR:</b> "
            color = "#FF6347"  # Red

        # Combine prefix and content.
        # The 'content' is expected to be already HTML formatted (e.g., from _handle_gemini_response)
        # or plain text that needs to be part of a larger HTML structure.
        final_html = (
            f"<div style='color:{color}; margin-bottom: 5px;'>{prefix}{content}</div>"
            f"<div style='height:10px;'></div>"  # Add vertical space after each message
        )

        self.chat_output.insertHtml(final_html)
        # Scroll to the bottom after adding message
        self.chat_output.verticalScrollBar().setValue(self.chat_output.verticalScrollBar().maximum())


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