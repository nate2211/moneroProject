import logging
import ctypes
import ctypes.wintypes as wintypes
import os
import re
import webbrowser
from typing import List, Dict
import queue
import threading
import asyncio
import time
from urllib.parse import urljoin, urlparse, quote_plus, parse_qs
from collections import defaultdict, deque
import requests
import psutil
from PyQt5.QtGui import QTextCursor, QIcon, QPixmap
from PyQt5.QtWidgets import QWidget, QLineEdit, QLabel, QComboBox, QGroupBox, QFormLayout, QPushButton, QPlainTextEdit, \
    QVBoxLayout, QHBoxLayout, QTextEdit, QListWidget, QCheckBox, QTreeWidgetItem, QTreeWidget, QTabWidget, QHeaderView, \
    QGridLayout, QProgressBar, QMessageBox, QFileDialog, QSizePolicy, QMenu, QApplication, QListWidgetItem, QSpinBox, \
    QSplitter, QAbstractItemView, QFrame
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot, QThread, QTimer, Qt
from pygments.formatters.html import HtmlFormatter

from p2pool_managers import PacketManager, AsyncNmapManager, AsyncGobusterManager, AsyncScrapingManager
from p2pool_ai import GeminiChatBot
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer
from tools.pythontools import yield_no_gil
import xml.etree.ElementTree as ET
try:
    from p2pool_ollama import OllamaModelTab, OllamaLogger
except Exception:
    OllamaModelTab = None
    OllamaLogger = None


class AsyncWorker(QObject):
    finished = pyqtSignal()
    started = pyqtSignal()

    def __init__(self, stop_event, main_loop):
        super().__init__()
        self.stop_event = stop_event
        self.main_loop = main_loop
        self.loop = None
    def run(self):
        self.started.emit()
        try:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.loop.run_until_complete(self.main_loop(self.stop_event))
        except Exception as e:
            print(f"CRITICAL ERROR in application thread: {e}")
        finally:
            self.finished.emit()


class ImageListItemWidget(QWidget):
    def __init__(self, image_url, image_data, parent=None):
        super().__init__(parent)
        self.image_url = image_url

        layout = QHBoxLayout(self)
        layout.setContentsMargins(5, 5, 5, 5)

        # Image Label
        self.image_label = QLabel()
        self.image_label.setFixedSize(128, 128)
        self.image_label.setAlignment(Qt.AlignCenter)
        pixmap = QPixmap()
        pixmap.loadFromData(image_data)
        self.image_label.setPixmap(pixmap.scaled(128, 128, Qt.KeepAspectRatio, Qt.SmoothTransformation))
        layout.addWidget(self.image_label)

        # Info and Button Layout
        info_layout = QVBoxLayout()
        url_label = QLabel(f"<b>URL:</b> {self.image_url}")
        url_label.setWordWrap(True)
        copy_button = QPushButton("📋 Copy URL")
        copy_button.clicked.connect(self._copy_url_to_clipboard)

        info_layout.addWidget(url_label)
        info_layout.addWidget(copy_button)
        info_layout.addStretch()

        layout.addLayout(info_layout)

    def _copy_url_to_clipboard(self):
        clipboard = QApplication.clipboard()
        clipboard.setText(self.image_url)
        # Optionally, provide feedback to the user
        print(f"Copied to clipboard: {self.image_url}")


class ScrapingTab(QWidget):
    """
    A PyQt widget for a web scraping tool, integrating with AsyncScrapingManager.
    Includes interactive features for extracted links and a Google search helper.
    """
    initialization_finished_signal = pyqtSignal()
    scraping_finished_signal = pyqtSignal(dict)
    scraping_progress_signal = pyqtSignal(str)

    def __init__(self, logger, async_worker_loop, parent=None):
        super().__init__(parent)
        self.logger = logger
        self.async_loop = async_worker_loop
        self.scraping_manager = AsyncScrapingManager(self.logger, self.async_loop)

        self._init_ui()
        self._setup_logging_and_signals()
        self._update_controls_enabled(False)
        self._on_initialize_manager()

    def _init_ui(self):
        main_layout = QGridLayout(self)
        self.setLayout(main_layout)

        # Status
        status_groupbox = QGroupBox("Scraper Status")
        status_layout = QVBoxLayout(status_groupbox)
        self.status_label = QLabel("Status: Initializing...")
        self.progress_label = QLabel("Progress: Idle")
        status_layout.addWidget(self.status_label)
        status_layout.addWidget(self.progress_label)
        main_layout.addWidget(status_groupbox, 0, 0, 1, 1)

        # URL Input & Options
        url_input_groupbox = QGroupBox("Target URL & Options")
        url_input_layout = QHBoxLayout(url_input_groupbox)
        self.url_input = QLineEdit("https://www.google.com")

        self.delay_label = QLabel("Load Delay (s):")
        self.delay_input = QSpinBox()
        self.delay_input.setMinimum(0)
        self.delay_input.setMaximum(300)
        self.delay_input.setValue(5)
        self.delay_input.setToolTip(
            "Seconds to wait on the page before scraping, to allow for logins or dynamic content loading.")

        self.scrape_button = QPushButton("🚀 Start Scrape")
        self.stop_button = QPushButton("⏹️ Stop Scrape")

        url_input_layout.addWidget(self.url_input)
        url_input_layout.addWidget(self.delay_label)
        url_input_layout.addWidget(self.delay_input)
        url_input_layout.addWidget(self.scrape_button)
        url_input_layout.addWidget(self.stop_button)
        main_layout.addWidget(url_input_groupbox, 0, 1, 1, 2)

        # Google Search Box
        gsearch_groupbox = QGroupBox("Google Search")
        gsearch_layout = QHBoxLayout(gsearch_groupbox)

        self.gsearch_type_combo = QComboBox()
        self.gsearch_type_combo.addItems(["Web Search", "Image Search"])

        self.gsearch_query_input = QLineEdit()
        self.gsearch_query_input.setPlaceholderText("Enter web search query...")

        self.gsearch_page_input = QSpinBox()
        self.gsearch_page_input.setMinimum(1)
        self.gsearch_page_input.setMaximum(100)
        self.gsearch_page_input.setPrefix("Page: ")

        self.gsearch_button = QPushButton("🔍 Search & Scrape")

        gsearch_layout.addWidget(self.gsearch_type_combo)
        gsearch_layout.addWidget(self.gsearch_query_input)
        gsearch_layout.addWidget(self.gsearch_page_input)
        gsearch_layout.addWidget(self.gsearch_button)
        main_layout.addWidget(gsearch_groupbox, 0, 3, 1, 1)

        # Output
        self.output_tabs = QTabWidget()
        self.output_tabs.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.rendered_view_display = QTextEdit()
        self.rendered_view_display.setReadOnly(True)
        self.raw_html_display = QTextEdit()
        self.raw_html_display.setReadOnly(True)
        self.raw_html_display.setFontFamily("monospace")
        self.extracted_text_display = QTextEdit()
        self.extracted_text_display.setReadOnly(True)
        self.extracted_links_list = QListWidget()
        self.extracted_images_list = QListWidget()

        self.output_tabs.addTab(self.rendered_view_display, "🌐 Rendered View (Simulated)")
        self.output_tabs.addTab(self.raw_html_display, "📝 Raw HTML")
        self.output_tabs.addTab(self.extracted_text_display, "📄 Extracted Text")
        self.output_tabs.addTab(self.extracted_links_list, "🔗 Extracted Links")
        self.output_tabs.addTab(self.extracted_images_list, "🖼️ Extracted Images")
        main_layout.addWidget(self.output_tabs, 1, 0, 1, 4)

        # Logging Console
        log_groupbox = QGroupBox("Application Log")
        log_layout = QVBoxLayout(log_groupbox)
        self.raw_log_display = QTextEdit()
        self.raw_log_display.setReadOnly(True)
        self.raw_log_display.setFontFamily("monospace")
        log_layout.addWidget(self.raw_log_display)
        main_layout.addWidget(log_groupbox, 2, 0, 1, 4)

        main_layout.setRowStretch(1, 2)
        main_layout.setRowStretch(2, 1)

    def _setup_logging_and_signals(self):
        self.log_timer = QTimer(self)
        self.log_timer.setInterval(100)
        self.log_timer.timeout.connect(self._flush_log)
        self._buffered_log_lines = []

        if hasattr(self.logger, 'message_signal'):
            self.logger.message_signal.connect(self.log_message)

        self.scraping_manager.scraping_started_signal.connect(self._handle_scraping_started)
        self.scraping_manager.scraping_finished_signal.connect(self._handle_scraping_finished)
        self.scraping_manager.scraping_progress_signal.connect(self._handle_scraping_progress)

        self.scrape_button.clicked.connect(self._on_start_scrape)
        self.stop_button.clicked.connect(self._on_stop_scrape)
        self.gsearch_button.clicked.connect(self._on_start_google_search)

        self.extracted_links_list.setContextMenuPolicy(Qt.CustomContextMenu)
        self.extracted_links_list.customContextMenuRequested.connect(self._show_link_context_menu)
        self.extracted_links_list.itemDoubleClicked.connect(self._open_link_in_browser)

    @pyqtSlot(str)
    def log_message(self, msg: str):
        self._buffered_log_lines.append(msg)
        if not self.log_timer.isActive():
            self.log_timer.start()

    def _flush_log(self):
        if self._buffered_log_lines:
            cursor = self.raw_log_display.textCursor()
            cursor.movePosition(QTextCursor.End)
            cursor.insertText("\n".join(self._buffered_log_lines) + "\n")
            self._buffered_log_lines.clear()
            self.raw_log_display.setTextCursor(cursor)
            self.raw_log_display.ensureCursorVisible()

    def _update_controls_enabled(self, enabled: bool):
        self.url_input.setEnabled(enabled)
        self.scrape_button.setEnabled(enabled)
        self.stop_button.setEnabled(False)
        self.delay_input.setEnabled(enabled)
        self.gsearch_query_input.setEnabled(enabled)
        self.gsearch_page_input.setEnabled(enabled)
        self.gsearch_button.setEnabled(enabled)

    def _on_initialize_manager(self):
        self.status_label.setText("Status: Initializing...")
        self.progress_label.setText("Progress: Starting manager...")
        self.log_timer.start()
        self.initialization_finished_signal.connect(self._handle_manager_initialized)
        asyncio.run_coroutine_threadsafe(
            self.scraping_manager.initialize(
                on_complete_callback=lambda: self.initialization_finished_signal.emit()
            ),
            self.async_loop
        )

    @pyqtSlot()
    def _handle_manager_initialized(self):
        self.status_label.setText(f"Status: {self.scraping_manager.status.capitalize()}")
        self.progress_label.setText("Progress: Ready to scrape.")
        self._update_controls_enabled(True)
        self.log_timer.stop()
        self._flush_log()

    @pyqtSlot()
    def _on_start_scrape(self):
        url = self.url_input.text().strip()
        delay = self.delay_input.value()
        if not url:
            self.logger.log_message("[GUI] ❌ Please enter a URL.")
            return

        self.rendered_view_display.clear()
        self.raw_html_display.clear()
        self.extracted_text_display.clear()
        self.extracted_links_list.clear()
        self.extracted_images_list.clear()
        self.scrape_button.setEnabled(False)
        self.gsearch_button.setEnabled(False)

        asyncio.run_coroutine_threadsafe(
            self.scraping_manager.start_scrape(
                url,
                delay,
                on_complete_callback=lambda data: self.scraping_finished_signal.emit(data)
            ),
            self.async_loop
        )

    @pyqtSlot()
    def _on_start_google_search(self):
        """Constructs a Google search URL, parses one, or uses direct image URL and starts the scrape."""
        raw_input = self.gsearch_query_input.text().strip()
        if not raw_input:
            self.logger.log_message("[GUI] ❌ Please enter a query, Google URL, or image URL.")
            return

        # --- Case 1: Direct image URL ---
        if raw_input.lower().endswith((".jpg", ".jpeg", ".png", ".gif", ".webp")):
            self.logger.log_message("[GUI] 📸 Detected direct image URL.")
            self.url_input.setText(raw_input)
            self._on_start_scrape()
            return

        # --- Case 2: Google Search URL ---
        if raw_input.startswith("http://") or raw_input.startswith("https://"):
            try:
                parsed = urlparse(raw_input)
                if "google." in parsed.netloc and "/search" in parsed.path:
                    query_params = parse_qs(parsed.query)
                    query = query_params.get("q", [""])[0]
                    start = int(query_params.get("start", [0])[0])
                    tbm = query_params.get("tbm", [""])[0]

                    self.gsearch_query_input.setText(query)
                    self.gsearch_page_input.setValue((start // 10) + 1)
                    self.gsearch_type_combo.setCurrentText("Image Search" if tbm == "isch" else "Web Search")
                    self.url_input.setText(raw_input)
                    self._on_start_scrape()
                    return
            except Exception as e:
                self.logger.log_message(f"[GUI] ❌ Failed to parse Google URL: {e}")
                return

        # --- Case 3: Raw Query ---
        encoded_query = quote_plus(raw_input)
        page_num = self.gsearch_page_input.value()
        start_index = (page_num - 1) * 10
        search_type = self.gsearch_type_combo.currentText()

        url = f"https://www.google.com/search?q={encoded_query}&start={start_index}"
        if search_type == "Image Search":
            url += "&tbm=isch"

        self.url_input.setText(url)
        self._on_start_scrape()

    @pyqtSlot()
    def _handle_scraping_started(self):
        self.status_label.setText("Status: Scraping...")
        self.progress_label.setText("Progress: Initiating scrape...")
        self.stop_button.setEnabled(True)
        self.log_timer.start()

    @pyqtSlot(str)
    def _handle_scraping_progress(self, message: str):
        self.progress_label.setText(f"Progress: {message}")

    @pyqtSlot(dict)
    def _handle_scraping_finished(self, scraped_data: dict):
        self.status_label.setText(f"Status: {self.scraping_manager.status.capitalize()}")
        self.scrape_button.setEnabled(True)
        self.gsearch_button.setEnabled(True)
        self.stop_button.setEnabled(False)
        self.log_timer.stop()
        self._flush_log()

        if "error" in scraped_data:
            self.progress_label.setText(f"Progress: Error - {scraped_data['error']}")
            self.raw_html_display.setText(f"Error: {scraped_data['error']}")
        else:
            self.progress_label.setText("Progress: Scrape completed successfully.")
            self._display_scraped_results(scraped_data)

    def _display_scraped_results(self, data: dict):
        self.rendered_view_display.setHtml(data.get("html_content", "No HTML content."))
        self.raw_html_display.setText(data.get("html_content", "No raw HTML content."))
        self.extracted_text_display.setText(data.get("extracted_text", "No extracted text."))

        self.extracted_links_list.clear()
        links = data.get("extracted_links", [])
        if links:
            link_icon = QIcon.fromTheme("text-html", QIcon("🌐"))
            for link in links:
                href = link.get('href', '#')
                text = link.get('text', href) or href
                item = QListWidgetItem(f"{text}")
                item.setIcon(link_icon)
                item.setData(Qt.UserRole, link)
                item.setToolTip(f"URL: {href}")
                self.extracted_links_list.addItem(item)
        else:
            self.extracted_links_list.addItem("No links extracted.")

        self.extracted_images_list.clear()
        images = data.get("extracted_images", [])
        if images:
            for image_info in images:
                if image_info.get('data'):
                    self._add_image_to_list(image_info['src'], image_info['data'])
        else:
            self.extracted_images_list.addItem("No images extracted.")

        self.output_tabs.setCurrentIndex(4)  # Switch to images tab

    @pyqtSlot(str, bytes)
    def _add_image_to_list(self, url, image_data):
        """Adds a custom widget for the downloaded image to the list."""
        item = QListWidgetItem(self.extracted_images_list)
        widget = ImageListItemWidget(url, image_data)
        item.setSizeHint(widget.sizeHint())
        self.extracted_images_list.addItem(item)
        self.extracted_images_list.setItemWidget(item, widget)

    @pyqtSlot()
    def _on_stop_scrape(self):
        self.scraping_manager.stop_scrape()
        self.status_label.setText("Status: Stopping...")
        self.progress_label.setText("Progress: Stopping scrape...")
        self.stop_button.setEnabled(False)
        self.scrape_button.setEnabled(True)
        self.gsearch_button.setEnabled(True)

    @pyqtSlot(QListWidgetItem)
    def _open_link_in_browser(self, item):
        link_data = item.data(Qt.UserRole)
        if link_data and 'href' in link_data:
            url = link_data['href']
            try:
                webbrowser.open_new_tab(url)
                self.logger.log_message(f"[GUI] Opening link: {url}")
            except Exception as e:
                self.logger.log_message(f"[GUI] ❌ Failed to open link: {e}")

    @pyqtSlot("QPoint")
    def _show_link_context_menu(self, position):
        item = self.extracted_links_list.itemAt(position)
        if not item or not item.data(Qt.UserRole):
            return

        menu = QMenu()
        copy_action = menu.addAction("📋 Copy Link URL")
        action = menu.exec_(self.extracted_links_list.mapToGlobal(position))
        if action == copy_action:
            self._copy_link_url(item)

    def _copy_link_url(self, item):
        link_data = item.data(Qt.UserRole)
        if link_data and 'href' in link_data:
            url = link_data['href']
            clipboard = QApplication.clipboard()
            clipboard.setText(url)
            self.logger.log_message(f"[GUI] ✅ Copied to clipboard: {url}")

    def closeEvent(self, event):
        """Clean up the main downloads folder on application close."""
        self.logger.log_message("[GUI] Close event detected. Cleaning up downloads...")
        # No longer needed as we are not saving files
        event.accept()


class GobusterTab(QWidget):
    initialization_finished_signal = pyqtSignal()
    # Removed scan_progress_signal
    # scan_finished_signal is still used for final status/error message from manager
    scan_finished_signal = pyqtSignal(str)

    def __init__(self, logger, async_worker_loop, parent=None):
        super().__init__(parent)
        self.logger = logger
        self.async_loop = async_worker_loop
        self.gobuster_manager = AsyncGobusterManager(self.logger, async_worker_loop, "tools/Linux/gobuster")
        # Connect manager signals to local slots
        self.gobuster_manager.gobuster_process_started_signal.connect(self._on_gobuster_process_started_notification)
        # Connect new_result_signal for real-time updates
        self.gobuster_manager.gobuster_new_result_signal.connect(self._display_new_result)
        # Connect scan_finished_signal from manager for final status
        self.gobuster_manager.gobuster_scan_finished_signal.connect(self._handle_scan_update)
        self._init_ui()

    def _init_ui(self):
        main_layout = QGridLayout(self)
        self.setLayout(main_layout)

        # Row 0: Controls
        wsl_status_groupbox = QGroupBox("WSL Status (Gobuster)")
        wsl_status_layout = QHBoxLayout(wsl_status_groupbox)
        self.wsl_status_label = QLabel("Click 'Initialize' to begin setup.")
        self.init_wsl_button = QPushButton("🚀 Initialize")
        wsl_status_layout.addWidget(self.wsl_status_label, 1)
        wsl_status_layout.addWidget(self.init_wsl_button)
        main_layout.addWidget(wsl_status_groupbox, 0, 0)

        scan_control_groupbox = QGroupBox("Scan Control (Gobuster)")
        scan_control_layout = QVBoxLayout(scan_control_groupbox)
        self.status_label = QLabel("Status: Idle")
        # Removed self.progress_bar and its related setup
        button_layout = QHBoxLayout()
        self.start_button = QPushButton("Start Gobuster Scan")
        self.stop_button = QPushButton("Stop Gobuster Scan")
        self.download_button = QPushButton("💾 Save Results")
        self.download_files_button = QPushButton("⬇️ Download Discovered Files")
        self.download_files_button.setEnabled(False)
        button_layout.addWidget(self.download_files_button)
        self.download_files_button.clicked.connect(self._on_download_discovered_files)
        button_layout.addWidget(self.start_button)
        button_layout.addWidget(self.stop_button)
        scan_control_layout.addWidget(self.status_label)
        scan_control_layout.addLayout(button_layout)
        main_layout.addWidget(scan_control_groupbox, 0, 1)

        options_groupbox = QGroupBox("Gobuster Options")
        options_layout = QFormLayout(options_groupbox)
        self.target_url_input = QLineEdit()
        self.target_url_input.setPlaceholderText("e.g., http://example.com")
        self.arguments_input = QLineEdit()
        self.arguments_input.setPlaceholderText("e.g., -x php,html -k") # -k to disable SSL cert verification
        options_layout.addRow("Target URL:", self.target_url_input)
        options_layout.addRow("Gobuster Args:", self.arguments_input)
        main_layout.addWidget(options_groupbox, 0, 2, 1, 2) # Span across two columns

        # Row 1: Results and Raw Log
        self.output_tabs = QTabWidget()
        self.results_list = QListWidget() # Using QListWidget for simpler Gobuster output
        self.raw_log_display = QTextEdit()
        self.raw_log_display.setReadOnly(True)
        self.output_tabs.addTab(self.results_list, "📊 Found Assets")
        self.output_tabs.addTab(self.raw_log_display, "📝 Raw Log")
        main_layout.addWidget(self.output_tabs, 1, 0, 1, 4) # Span across all columns
        main_layout.setRowStretch(1, 1) # Make results/log section expandable

        self._populate_defaults()
        self._setup_logging_and_signals()
        self._update_all_controls_enabled(False) # Disable controls initially

    def _populate_defaults(self):
        self.target_url_input.setText("http://localhost:5000")
        # Default wordlist path (common in Kali/WSL)
        firefox_user_agent = "Mozilla/5.0 Windows NT 10.0; Win64; x64; rv:128.0 Gecko/20100101 Firefox/128.0"

        common_extensions = "html,php,txt,js,css,json,xml,asp,aspx,jsp,do,action,cgi,pl,rb,py,bak,old,zip,tar.gz,tgz,rar,7z,sql,db,mdb,sqlite,log,conf,config,env,sh,bash,ini,yml,yaml,md,pdf,doc,docx,xls,xlsx,ppt,pptx,jpg,jpeg,png,gif,bmp,svg,ico"
        self.arguments_input.setText(f"--exclude-length 466 --threads 100 --no-error --expanded --add-slash --follow-redirect --extensions {common_extensions} --useragent \"{firefox_user_agent}\" --timeout 15s --hide-length --no-progress -q")

    def _setup_logging_and_signals(self):
        self.timer = QTimer(self)
        self.timer.setInterval(250)
        self.timer.timeout.connect(self._flush_log)
        self._buffered_lines = []
        if hasattr(self.logger, 'message_signal'):
            self.logger.message_signal.connect(self.log_message)

        self.init_wsl_button.clicked.connect(self._on_initialize)
        self.start_button.clicked.connect(self._on_start)
        self.stop_button.clicked.connect(self._on_stop)

    @pyqtSlot(str)
    def log_message(self, msg: str):
        self._buffered_lines.append(msg)

    def _flush_log(self):
        if self._buffered_lines:
            self.raw_log_display.append("\n".join(self._buffered_lines))
            self._buffered_lines.clear()
            self.raw_log_display.verticalScrollBar().setValue(self.raw_log_display.verticalScrollBar().maximum())

    def _on_initialize(self):
        self.init_wsl_button.setEnabled(False)
        self.wsl_status_label.setText("Initializing...")
        self.timer.start() # Start flushing logs during initialization

        asyncio.run_coroutine_threadsafe(
            self.gobuster_manager.initialize(on_complete_callback=lambda: self.initialization_finished_signal.emit()),
            self.async_loop
        )
        # Connect the initialization finished signal from GobusterManager to this tab's handler
        self.initialization_finished_signal.connect(self._handle_initialization_update)

    @pyqtSlot()
    def _handle_initialization_update(self):
        is_ready = self.gobuster_manager.is_ready
        self.wsl_status_label.setText(self.gobuster_manager.setup_message)
        self._update_all_controls_enabled(is_ready) # Enable/disable based on readiness
        self.init_wsl_button.setVisible(not is_ready) # Hide if ready
        self.timer.stop() # Stop log flushing timer
        self._flush_log() # Flush any remaining logs

    def _update_all_controls_enabled(self, enabled: bool):
        self.start_button.setEnabled(enabled and self.gobuster_manager.status != "running")
        self.stop_button.setEnabled(enabled and self.gobuster_manager.status == "running")
        self.target_url_input.setEnabled(enabled and self.gobuster_manager.status != "running")
        self.arguments_input.setEnabled(enabled and self.gobuster_manager.status != "running")


    def _on_start(self):
        try:
            target_url = self.target_url_input.text().strip()
            arguments = self.arguments_input.text().strip().split()
            print(arguments)
            if not target_url:
                self.logger.log_message("[Gobuster-GUI] ❌ No target URL provided.")
                return

            self.results_list.clear() # Clear previous results
            self.status_label.setText("Status: Scanning...")
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.target_url_input.setEnabled(False) # Disable input during scan
            self.arguments_input.setEnabled(False) # Disable input during scan
            self.timer.start() # Start log flushing during scan

            asyncio.run_coroutine_threadsafe(
                self.gobuster_manager.start_scan(target_url, "tools/Linux/SecLists", arguments,
                                                  on_complete_callback=lambda output: self.scan_finished_signal.emit(output)),
                self.async_loop
            )
        except Exception as e:
            self.logger.log_message(f"Error starting scan: {e}")
            self.status_label.setText("Status: Error")
            self.start_button.setEnabled(True) # Re-enable start button on error
            self.stop_button.setEnabled(False)
            self.target_url_input.setEnabled(True)
            self.arguments_input.setEnabled(True)

    @pyqtSlot(str)
    def _handle_scan_update(self, final_message: str):
        self.status_label.setText(f"Status: {self.gobuster_manager.status.capitalize()}.")
        self.start_button.setEnabled(True) # Re-enable start button
        self.stop_button.setEnabled(False) # Disable stop button
        self.target_url_input.setEnabled(True) # Re-enable input
        self.arguments_input.setEnabled(True) # Re-enable input
        self.timer.stop() # Stop log flushing
        self._flush_log() # Flush any remaining logs
        self.download_files_button.setEnabled(self.results_list.count() > 0)
        if final_message.startswith("<error>"):
            self.results_list.addItem(f"Gobuster Scan Error: {final_message.replace('<error>', '').replace('</error>', '')}")
            self.output_tabs.setCurrentWidget(self.results_list)
        else:
            self.logger.log_message(f"[Gobuster] {final_message}")

    @pyqtSlot()
    def _on_download_discovered_files(self):
        base_url = self.target_url_input.text().strip()
        if not base_url:
            QMessageBox.warning(self, "Missing Base URL", "Please enter a valid base URL.")
            return

        folder = QFileDialog.getExistingDirectory(self, "Choose Folder to Save Files")
        if not folder:
            return

        session = requests.Session()

        for i in range(self.results_list.count()):
            path = self.results_list.item(i).text().strip()

            # Skip status-only lines that aren't actual paths, or if they are just base URLs with no sub-path
            if not path.startswith('/') and not path.startswith("http"):
                continue

            full_url = urljoin(base_url, path)
            try:
                self.logger.log_message(f"[Downloader] Attempting to download: {full_url}")
                response = session.get(full_url, timeout=15, allow_redirects=True)  # Added timeout and allow_redirects
                response.raise_for_status()  # Raise HTTPError for bad responses (4xx or 5xx)

                # Determine filename and extension
                filename_parts = urlparse(full_url).path.split('/')
                filename = filename_parts[-1] if filename_parts[-1] else "index"  # Use last part or "index" for root
                if not filename:  # If it's a directory like /foo/
                    filename = "index"

                ext = ""
                content_type = response.headers.get('Content-Type', '').split(';')[
                    0].strip().lower()  # Get main type, strip charset etc.

                # Comprehensive Content-Type to Extension Mapping
                if "text/html" in content_type:
                    ext = ".html"
                elif "application/json" in content_type:
                    ext = ".json"
                elif "text/plain" in content_type:
                    ext = ".txt"
                elif "application/xml" in content_type or "text/xml" in content_type:
                    ext = ".xml"
                elif "application/javascript" in content_type or "text/javascript" in content_type:
                    ext = ".js"
                elif "text/css" in content_type:
                    ext = ".css"
                elif "image/jpeg" in content_type:
                    ext = ".jpg"
                elif "image/png" in content_type:
                    ext = ".png"
                elif "image/gif" in content_type:
                    ext = ".gif"
                elif "image/svg+xml" in content_type:
                    ext = ".svg"
                elif "image/x-icon" in content_type:
                    ext = ".ico"
                elif "application/pdf" in content_type:
                    ext = ".pdf"
                elif "application/zip" in content_type:
                    ext = ".zip"
                elif "application/x-gzip" in content_type or "application/gzip" in content_type:
                    ext = ".gz"
                elif "application/x-tar" in content_type:  # Common for .tar.gz or .tgz
                    ext = ".tar"
                elif "application/x-rar-compressed" in content_type:
                    ext = ".rar"
                elif "application/x-7z-compressed" in content_type:
                    ext = ".7z"
                elif "application/vnd.openxmlformats-officedocument.wordprocessingml.document" in content_type:
                    ext = ".docx"
                elif "application/msword" in content_type:
                    ext = ".doc"
                elif "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet" in content_type:
                    ext = ".xlsx"
                elif "application/vnd.ms-excel" in content_type:
                    ext = ".xls"
                elif "application/vnd.openxmlformats-officedocument.presentationml.presentation" in content_type:
                    ext = ".pptx"
                elif "application/vnd.ms-powerpoint" in content_type:
                    ext = ".ppt"
                elif "application/octet-stream" in content_type:
                    # Generic binary, try to infer from original path or just leave blank
                    # This is tricky, often it's a fallback for unrecognised types
                    pass
                # Add more as needed

                # Fallback: If no content-type match, check if original path already has an extension
                if not ext and '.' in filename:
                    # Extract last part after dot and check if it looks like a common extension
                    potential_ext = "." + filename.rsplit('.', 1)[-1].lower()
                    # You can maintain a list of known extensions if you want to be strict,
                    # or just accept any if you're lenient.
                    # For example: if potential_ext in {".html", ".php", ".txt", ...}
                    ext = potential_ext
                elif not ext and 'common.txt' in path:  # Special case for your default wordlist
                    ext = '.txt'
                elif not ext and 'index' in filename:  # If it's an index page, assume HTML
                    ext = '.html'

                # Ensure filename doesn't end with a dot if no extension was found/added
                if filename.endswith('.') and not ext:
                    filename = filename.rstrip('.')

                # If no extension found and filename doesn't suggest one, and it's not "index", add a generic .bin or .dat
                if not ext and 'index' not in filename.lower() and not '.' in filename:
                    ext = '.bin'  # Or '.dat', or don't add one at all. Depends on preference.

                file_path = os.path.join(folder, f"{filename}{ext}")

                # Handle potential duplicate filenames gracefully
                counter = 1
                original_file_path = file_path
                while os.path.exists(file_path):
                    name, ext_part = os.path.splitext(original_file_path)
                    file_path = f"{name}_{counter}{ext_part}"
                    counter += 1

                with open(file_path, 'wb') as f:
                    f.write(response.content)

                self.logger.log_message(f"[Downloader] Saved: {file_path}")
            except requests.exceptions.HTTPError as errh:
                self.logger.log_message(f"[Downloader] HTTP Error for {full_url}: {errh}")
            except requests.exceptions.ConnectionError as errc:
                self.logger.log_message(f"[Downloader] Error Connecting for {full_url}: {errc}")
            except requests.exceptions.Timeout as errt:
                self.logger.log_message(f"[Downloader] Timeout Error for {full_url}: {errt}")
            except requests.exceptions.RequestException as err:
                self.logger.log_message(f"[Downloader] General Request Error for {full_url}: {err}")
            except Exception as e:
                self.logger.log_message(f"[Downloader] Failed to download {full_url}: {e}")

        QMessageBox.information(self, "Download Complete", f"All downloadable files saved to:\n{folder}")
    @pyqtSlot(str)
    def _display_new_result(self, result_line: str):
        """Adds a new found result to the results list."""
        self.results_list.addItem(result_line.strip())
        # Ensure the results tab is active if you want immediate user feedback there
        if self.output_tabs.currentIndex() != self.output_tabs.indexOf(self.results_list):
            self.output_tabs.setCurrentWidget(self.results_list)

    def _on_stop(self):
        self.status_label.setText("Status: Stopping...")
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(False) # Disable stop button while stopping
        self.gobuster_manager.stop_scan()

    @pyqtSlot()
    def _on_gobuster_process_started_notification(self):
        msg_box = QMessageBox(self)
        msg_box.setIcon(QMessageBox.Information)
        msg_box.setText("Gobuster Scan Process Started!")
        msg_box.setInformativeText("The Gobuster process has successfully launched in WSL.")
        msg_box.setWindowTitle("Scan Notification")
        msg_box.setStandardButtons(QMessageBox.Ok)
        msg_box.exec_()



class NmapTab(QWidget):
    initialization_finished_signal = pyqtSignal()
    scan_finished_signal = pyqtSignal(str)

    def __init__(self, logger, async_worker_loop, parent=None):
        super().__init__(parent)
        self.logger = logger
        self.async_loop = async_worker_loop
        self.nmap_manager = AsyncNmapManager(self.logger, async_worker_loop)

        # --- MODIFIED: Profiles now control both args and ports for reliability ---
        self.scan_profiles = {
            "Quick Scan (Top 100 ports)": {
                "args": "-sS -T3 --max-retries 2 --max-rate 100 --open",  # TCP connect scan, low timing
                "ports": "-F"
            },
            "Moderate Scan (Top 1000 ports)": {
                "args": "-sS -T3 --max-retries 2 --max-rate 100 --open",  # Avoid version detection or OS detection
                "ports": ""
            },
            "Full SYN Scan (All 65k ports)": {
                "args": "-sS -T3 --max-retries 2 --max-rate 100 --open",  # Still low timing, but large port range
                "ports": "-p-"
            },
        }
        self._init_ui()

    def _init_ui(self):
        main_layout = QGridLayout(self)
        self.setLayout(main_layout)

        # Row 0: Controls
        wsl_status_groupbox = QGroupBox("WSL Status");
        wsl_status_layout = QHBoxLayout(wsl_status_groupbox);
        self.wsl_status_label = QLabel("Click 'Initialize' to begin setup.");
        self.init_wsl_button = QPushButton("🚀 Initialize");
        wsl_status_layout.addWidget(self.wsl_status_label, 1);
        wsl_status_layout.addWidget(self.init_wsl_button);
        main_layout.addWidget(wsl_status_groupbox, 0, 0)
        scan_control_groupbox = QGroupBox("Scan Control");
        scan_control_layout = QVBoxLayout(scan_control_groupbox);
        self.status_label = QLabel("Status: Idle");
        button_layout = QHBoxLayout();
        self.start_button = QPushButton("Start Scan");
        self.stop_button = QPushButton("Stop Scan");
        button_layout.addWidget(self.start_button);
        button_layout.addWidget(self.stop_button);
        scan_control_layout.addWidget(self.status_label);
        scan_control_layout.addLayout(button_layout);
        main_layout.addWidget(scan_control_groupbox, 0, 1)
        self.wsl_shell_groupbox = QGroupBox("Interactive WSL Shell");
        wsl_shell_layout = QVBoxLayout(self.wsl_shell_groupbox);
        session_control_layout = QHBoxLayout();
        self.session_button = QPushButton("▶️ Start Session");
        self.session_button.setCheckable(True);
        session_control_layout.addWidget(self.session_button);
        session_control_layout.addStretch();
        command_layout = QHBoxLayout();
        self.wsl_input = QLineEdit();
        self.wsl_input.setPlaceholderText("Enter command...");
        self.wsl_send_button = QPushButton("Send");
        command_layout.addWidget(self.wsl_input, 1);
        command_layout.addWidget(self.wsl_send_button);
        wsl_shell_layout.addLayout(session_control_layout);
        wsl_shell_layout.addLayout(command_layout);
        main_layout.addWidget(self.wsl_shell_groupbox, 0, 2)
        options_groupbox = QGroupBox("Scan Options");
        options_layout = QFormLayout(options_groupbox);
        self.profile_combo = QComboBox();
        self.ports_input = QLineEdit();
        self.arguments_input = QLineEdit();
        options_layout.addRow("Scan Profile:", self.profile_combo);
        options_layout.addRow("Ports:", self.ports_input);
        options_layout.addRow("Nmap Arguments:", self.arguments_input);
        main_layout.addWidget(options_groupbox, 0, 3)

        # Row 1: Targets
        target_groupbox = QGroupBox("Scan Targets");
        target_layout = QVBoxLayout(target_groupbox);
        self.target_list_widget = QListWidget();
        target_layout.addWidget(self.target_list_widget);
        add_target_layout = QHBoxLayout();
        self.target_input = QLineEdit();
        self.target_input.setPlaceholderText("Enter IP, hostname, or CIDR range...");
        self.add_target_button = QPushButton("Add Target");
        add_target_layout.addWidget(self.target_input, 1);
        add_target_layout.addWidget(self.add_target_button);
        target_layout.addLayout(add_target_layout);
        manage_targets_layout = QHBoxLayout();
        self.remove_target_button = QPushButton("Remove Selected");
        self.clear_targets_button = QPushButton("Clear All");
        manage_targets_layout.addStretch();
        manage_targets_layout.addWidget(self.remove_target_button);
        manage_targets_layout.addWidget(self.clear_targets_button);
        target_layout.addLayout(manage_targets_layout);
        main_layout.addWidget(target_groupbox, 1, 0, 1, 4)

        # Row 2: Console
        self.output_tabs = QTabWidget();
        self.results_tree = QTreeWidget();
        self.results_tree.setHeaderLabels(["Host / Port", "State", "Service", "Version"]);
        self.results_tree.header().setSectionResizeMode(QHeaderView.ResizeToContents);
        self.raw_log_display = QTextEdit();
        self.raw_log_display.setReadOnly(True);
        self.output_tabs.addTab(self.results_tree, "📊 Parsed Results");
        self.output_tabs.addTab(self.raw_log_display, "📝 Raw Log");
        main_layout.addWidget(self.output_tabs, 2, 0, 1, 4)

        main_layout.setRowStretch(2, 1)

        self._populate_defaults()
        self._setup_logging_and_signals()
        self._update_all_controls_enabled(False)

    def _setup_logging_and_signals(self):
        self.timer = QTimer(self);
        self.timer.setInterval(250);
        self.timer.timeout.connect(self._flush_log);
        self._buffered_lines = []
        if hasattr(self.logger, 'message_signal'): self.logger.message_signal.connect(self.log_message)
        self.init_wsl_button.clicked.connect(self._on_initialize)
        self.start_button.clicked.connect(self._on_start)
        self.stop_button.clicked.connect(self._on_stop)
        self.session_button.toggled.connect(self._on_session_toggled)
        self.wsl_send_button.clicked.connect(self._on_wsl_send)
        self.wsl_input.returnPressed.connect(self._on_wsl_send)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        self.add_target_button.clicked.connect(self._on_add_target)
        self.target_input.returnPressed.connect(self._on_add_target)
        self.remove_target_button.clicked.connect(self._on_remove_target)
        self.clear_targets_button.clicked.connect(self._on_clear_targets)
        self.initialization_finished_signal.connect(self._handle_initialization_update)
        self.scan_finished_signal.connect(self._handle_scan_update)

    @pyqtSlot(str)
    def log_message(self, msg: str):
        self._buffered_lines.append(msg)

    def _flush_log(self):
        if self._buffered_lines: self.raw_log_display.append("\n".join(
            self._buffered_lines)); self._buffered_lines.clear(); self.raw_log_display.verticalScrollBar().setValue(
            self.raw_log_display.verticalScrollBar().maximum())

    def _populate_defaults(self):
        self.target_list_widget.addItems(["localhost"])
        self.profile_combo.addItems(self.scan_profiles.keys())
        self.profile_combo.currentText()
        profile_name = self.profile_combo.currentText()
        profile_data = self.scan_profiles.get(profile_name, {})
        self.arguments_input.setText(profile_data.get("args", ""))

    @pyqtSlot()
    def _on_profile_changed(self):
        """When a profile is selected, update BOTH arguments and ports."""
        profile_name = self.profile_combo.currentText()
        profile_data = self.scan_profiles.get(profile_name, {})
        self.arguments_input.setText(profile_data.get("args", ""))
        self.ports_input.setText(profile_data.get("ports", ""))

    def _on_initialize(self):
        self.init_wsl_button.setEnabled(False);
        self.wsl_status_label.setText("Initializing...");
        self.timer.start()
        asyncio.run_coroutine_threadsafe(
            self.nmap_manager.initialize(on_complete_callback=lambda: self.initialization_finished_signal.emit()),
            self.async_loop)

    @pyqtSlot()
    def _handle_initialization_update(self):
        is_ready = self.nmap_manager.is_ready;
        self.wsl_status_label.setText(self.nmap_manager.setup_message);
        self._update_all_controls_enabled(is_ready);
        self.wsl_shell_groupbox.setVisible(is_ready);
        self.init_wsl_button.setVisible(not is_ready);
        self.timer.stop();
        self._flush_log()

    def _update_all_controls_enabled(self, enabled: bool):
        self.start_button.setEnabled(enabled);
        self.stop_button.setEnabled(False);
        self.target_list_widget.setEnabled(enabled);
        self.profile_combo.setEnabled(enabled);
        self.ports_input.setEnabled(enabled);
        self.arguments_input.setEnabled(enabled);
        self.wsl_shell_groupbox.setVisible(enabled);
        self.wsl_input.setEnabled(False);
        self.wsl_send_button.setEnabled(False);
        self.target_input.setEnabled(enabled);
        self.add_target_button.setEnabled(enabled);
        self.remove_target_button.setEnabled(enabled);
        self.clear_targets_button.setEnabled(enabled)

    def _on_start(self):
        try:
            """ --- CORRECTED: This method now builds the argument list reliably --- """
            targets = [self.target_list_widget.item(i).text().strip() for i in range(self.target_list_widget.count())]
            targets = [t for t in targets if t]
            if not targets:
                self.logger.log_message("[GUI] ❌ No valid targets to scan.")
                return

            # Start with the arguments from the text box
            args = self.arguments_input.text().strip().split()
            ports_spec = self.ports_input.text().strip()

            # This logic correctly handles the -F flag vs. a specific port list.
            if ports_spec:
                if ports_spec.upper() == '-F':
                    # If -F is the port spec, ensure it's in the args list and -p is not.
                    args = [arg for arg in args if arg != '-p']
                    if '-F' not in args:
                        args.append('-F')
                else:
                    # If a specific port list is given, ensure -F is not present
                    # and add the port list with the -p flag.
                    args = [arg for arg in args if arg.upper() != '-F']
                    if '-p' not in args:
                        args.extend(['-p', ports_spec])

            if not args:
                self.logger.log_message("[GUI] ❌ No scan arguments provided.")
                return

            self.results_tree.clear()
            self.status_label.setText("Status: Scanning...")
            self.start_button.setEnabled(False)
            self.stop_button.setEnabled(True)
            self.timer.start()

            asyncio.run_coroutine_threadsafe(
                self.nmap_manager.start_scan(targets, args,
                                             on_complete_callback=lambda xml: self.scan_finished_signal.emit(xml)),
                self.async_loop
            )
        except Exception as e:
            self.logger.log_message(str(e))
    @pyqtSlot(str)
    def _handle_scan_update(self, xml_data: str):
        self.logger.log_message(xml_data)
        self.status_label.setText(f"Status: {self.nmap_manager.status.capitalize()}.");
        self.start_button.setEnabled(True);
        self.stop_button.setEnabled(False);
        self.timer.stop();
        self._flush_log()
        self._parse_and_display_results(xml_data)

    def _on_stop(self):
        self.nmap_manager.stop_scan()

    @pyqtSlot(bool)
    def _on_session_toggled(self, checked: bool):
        if checked:
            self.session_button.setText("⏹️ Stop Session");
            self.wsl_input.setEnabled(True);
            self.wsl_send_button.setEnabled(True);
            self.timer.start()
            asyncio.run_coroutine_threadsafe(self.nmap_manager.start_interactive_session(), self.async_loop)
        else:
            self.session_button.setText("▶️ Start Session");
            self.wsl_input.setEnabled(False);
            self.wsl_send_button.setEnabled(False);
            self.timer.stop();
            self._flush_log()
            asyncio.run_coroutine_threadsafe(self.nmap_manager.stop_interactive_session(), self.async_loop)

    @pyqtSlot()
    def _on_wsl_send(self):
        command = self.wsl_input.text().strip()
        if command: asyncio.run_coroutine_threadsafe(self.nmap_manager.send_command_to_session(command),
                                                     self.async_loop); self.wsl_input.clear()

    @pyqtSlot()
    def _on_add_target(self):
        target = self.target_input.text().strip()
        if target and not self.target_list_widget.findItems(target, Qt.MatchExactly): self.target_list_widget.addItem(
            target)
        self.target_input.clear()

    @pyqtSlot()
    def _on_remove_target(self):
        for item in self.target_list_widget.selectedItems(): self.target_list_widget.takeItem(
            self.target_list_widget.row(item))

    @pyqtSlot()
    def _on_clear_targets(self):
        self.target_list_widget.clear()

    def _parse_and_display_results(self, xml_data: str):
        self.results_tree.clear()

        if not xml_data or xml_data.startswith("<error>"):
            QTreeWidgetItem(self.results_tree, ["Scan Error", xml_data or "No XML data received."])
            return

        try:
            root = ET.fromstring(xml_data)

            # --- Primary parsing for detailed host/port results ---
            hosts_found_in_xml = False
            for host in root.findall('host'):
                hosts_found_in_xml = True
                address_element = host.find('address')
                addr = address_element.get('addr') if address_element is not None else 'Unknown'

                status_element = host.find('status')
                host_state = status_element.get('state', 'unknown') if status_element is not None else 'unknown'

                host_item = QTreeWidgetItem(self.results_tree, [f"Host: {addr} ({host_state})"])

                ports_element = host.find('ports')
                if ports_element is not None:
                    ports = ports_element.findall('port')
                    if ports:
                        for port in ports:
                            port_id = port.get('portid') or 'unknown'
                            protocol = port.get('protocol') or 'unknown'

                            state_element = port.find('state')
                            state = state_element.get('state', '') if state_element is not None else ''

                            service_element = port.find('service')
                            name = service_element.get('name', '') if service_element is not None else ''
                            version = service_element.get('version', '') if service_element is not None else ''

                            QTreeWidgetItem(host_item, [f"  Port: {port_id}/{protocol}", state, name, version])
                    else:
                        QTreeWidgetItem(host_item, ["  No open ports found for this host.", "", "", ""])
                else:
                    QTreeWidgetItem(host_item, ["  No port information available for this host.", "", "", ""])

            # --- Secondary parsing for scan summary if no detailed host data ---
            if not hosts_found_in_xml:
                runstats_element = root.find('runstats')
                if runstats_element is not None:
                    finished = runstats_element.find('finished')
                    summary_text = finished.get('summary') if finished is not None else "No summary available"

                    hosts_element = runstats_element.find('hosts')
                    hosts_up = hosts_element.get('up') if hosts_element is not None else "0"
                    hosts_total = hosts_element.get('total') if hosts_element is not None else "0"

                    summary_item = QTreeWidgetItem(self.results_tree, [f"Scan Summary: {summary_text}"])
                    QTreeWidgetItem(summary_item, [f"Hosts Up: {hosts_up}", f"Total Hosts: {hosts_total}", "", ""])

                    if int(hosts_up) > 0:
                        QTreeWidgetItem(summary_item, ["Note: No open ports were found for live hosts.", "", "", ""])
                    elif int(hosts_total) > 0 and int(hosts_up) == 0:
                        QTreeWidgetItem(summary_item, ["All targets appear to be down.", "", "", ""])
                    else:
                        QTreeWidgetItem(summary_item, ["No scan results reported in detail.", "", "", ""])
                else:
                    QTreeWidgetItem(self.results_tree, ["No hosts found and no runstats summary in XML.", "", "", ""])

            self.results_tree.expandAll()
            self.output_tabs.setCurrentWidget(self.results_tree)

        except ET.ParseError as e:
            self.logger.log_message(f"XML Parse Error: {e}")
            QTreeWidgetItem(self.results_tree, ["XML Parse Error", "Could not parse Nmap output."])
        except Exception as e:
            self.logger.log_message(f"Unhandled XML parsing error: {e}")
            QTreeWidgetItem(self.results_tree, ["Unhandled Parsing Error", str(e)])


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
        self.chatbot_backend = GeminiChatBot(self.gemini_logger,
                                             initial_instruction="You are a highly intelligent and analytical AI assistant. "
                                                                 "When providing code, please format it as if it were output from a blank terminal. "
                                                                 "Ensure there's ample blank space (e.g., a few empty lines) before and after "
                                                                 "code blocks to make them easy to copy and paste. "
                                                                 "Provide comprehensive and insightful responses, "
                                                                 "offering detailed explanations, multiple perspectives, "
                                                                 "and asking clarifying questions when necessary to deepen the conversation. "
                                                                 "Always maintain a professional and helpful tone. More about myself my name is Nate and im coding a huge solo project."
                                                                 "Also write as much code as possible and always include everything we need in the code."
                                             )
        # THEN setup the worker thread, passing the already initialized chatbot_backend
        self._setup_worker_thread()  # This now happens AFTER chatbot_backend is initialized

        # Initial message for Gemini tab, logged via the consistent log_message method
        self.pygments_formatter = HtmlFormatter(noclasses=True, style="monokai", nowrap=True)

    def _create_widgets(self):
        """Creates all the widgets for the tab."""
        self.chat_output = QTextEdit()
        self.chat_output.setReadOnly(True)
        self.chat_output.setPlaceholderText("Gemini's responses will appear here...")
        # Ensure rich text is accepted and formatting works
        self.chat_output.setAcceptRichText(True)

        self.user_input = QPlainTextEdit()
        self.user_input.setPlaceholderText("Type your message here...")
        # REMOVED: self.user_input.setFixedHeight(80) -> This allows the splitter to control size

        self.send_button = QPushButton("Send")
        self.send_button.setObjectName("send_button")

        self.clear_history_button = QPushButton("Clear History")
        self.clear_history_button.setObjectName("clear_history_button")

        self.status_label = QLabel("Ready")
        self.status_label.setStyleSheet("color: #dcdcdc; font-style: italic;")

    def _configure_layout(self):
        """Sets up the layout for the tab with a QSplitter for resizing."""
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(5, 5, 5, 5) # Add slight margin around the whole tab

        # 1. Create a Vertical Splitter
        self.splitter = QSplitter(Qt.Vertical)
        self.splitter.setHandleWidth(8) # Make the grab handle visible and easy to click
        # Optional: Style the splitter handle
        self.splitter.setStyleSheet("""
            QSplitter::handle {
                background-color: #444;
                border: 1px solid #222;
            }
            QSplitter::handle:hover {
                background-color: #666;
            }
        """)

        # 2. Add Chat Output to Top of Splitter
        self.splitter.addWidget(self.chat_output)

        # 3. Create a container for the Input Area (Input Box + Buttons)
        input_container = QWidget()
        # Use horizontal layout for text box + buttons side-by-side
        input_container_layout = QHBoxLayout(input_container)
        input_container_layout.setContentsMargins(0, 0, 0, 0) # No extra margins inside the split

        # Add User Input to container
        input_container_layout.addWidget(self.user_input, 1) # Stretch factor 1

        # Create Button Column
        button_column_layout = QVBoxLayout()
        button_column_layout.addWidget(self.send_button)
        button_column_layout.addWidget(self.clear_history_button)
        button_column_layout.addStretch(1) # Push buttons to the top

        # Add buttons to container
        input_container_layout.addLayout(button_column_layout)

        # 4. Add Input Container to Bottom of Splitter
        self.splitter.addWidget(input_container)

        # Set initial sizes (e.g., 80% Chat, 20% Input)
        self.splitter.setStretchFactor(0, 4)
        self.splitter.setStretchFactor(1, 1)
        # Prevent sections from collapsing completely
        self.splitter.setCollapsible(0, False)
        self.splitter.setCollapsible(1, False)

        # 5. Add Splitter and Status Label to Main Layout
        main_layout.addWidget(self.splitter)
        main_layout.addWidget(self.status_label)

    def _connect_signals(self):
        """Connects UI element signals to handler methods."""
        self.send_button.clicked.connect(self._on_send_button_clicked)
        self.clear_history_button.clicked.connect(self._on_clear_history_clicked)
        self.thinking_timer.timeout.connect(self._update_thinking_animation)

    def _setup_worker_thread(self):
        """Sets up the QThread and worker for background API calls."""
        self.worker_thread = QThread()
        self.worker = GeminiChatWorker(self.gemini_logger, self.chatbot_backend)
        self.worker.moveToThread(self.worker_thread)

        self.worker.response_received.connect(self._handle_gemini_response)
        self.worker.error_occurred.connect(self._handle_gemini_error)
        self.worker.thinking_started.connect(self._on_thinking_started)
        self.worker.thinking_finished.connect(self._on_thinking_finished)

        self.send_message_requested.connect(self.worker.process_message)

        self.worker_thread.started.connect(lambda: self.gemini_logger.log_message("GeminiChatWorker thread started."))
        self.worker_thread.start()

    @pyqtSlot()
    def _on_send_button_clicked(self):
        """Handles the send button click."""
        user_message = self.user_input.toPlainText().strip()
        if user_message:
            self.gemini_logger.log_message(user_message, "user")
            self.user_input.clear()
            self.send_message_requested.emit(user_message)
        else:
            self.gemini_logger.log_message("Please enter a non-empty message.")

    @pyqtSlot()
    def _on_clear_history_clicked(self):
        """Clears the chat output and the chatbot's internal history."""
        self.chat_output.clear()
        self.chatbot_backend.clear_chat_history()
        self.gemini_logger.log_message("Chat history cleared.")

    @pyqtSlot(str)
    @pyqtSlot(str)
    def _handle_gemini_response(self, response: str):
        """
        Parses markdown code blocks, highlights them, and handles plain text gracefully.
        """
        # REGEX to find code blocks:
        # 1. ``` matches opening
        # 2. (?P<lang>[\w\-\+]+)? matches optional language
        # 3. [^\n]*\n matches remainder of opening line
        # 4. (?P<code>.*?) matches content
        # 5. ``` matches closing
        code_block_pattern = re.compile(r"```(?P<lang>[\w\-\+]+)?[^\n]*\n(?P<code>.*?)```", re.DOTALL)

        last_idx = 0
        formatted_response_parts = []

        for match in code_block_pattern.finditer(response):
            # 1. Handle Plain Text BEFORE the code block
            if match.start() > last_idx:
                text_before = response[last_idx:match.start()]
                # We process this text to preserve newlines
                formatted_response_parts.append(self._format_text_block(text_before))

            # 2. Extract Language and Code
            lang = match.group('lang')
            code = match.group('code')

            # 3. Determine Lexer
            try:
                if lang:
                    lexer = get_lexer_by_name(lang.strip())
                else:
                    lexer = guess_lexer(code)
            except Exception:
                lexer = get_lexer_by_name("text")

            # 4. Highlight
            highlighted_code = highlight(code, lexer, self.pygments_formatter)

            # 5. Wrap code in styled HTML
            formatted_response_parts.append(
                f"<div style='margin: 10px 0;'>"
                f"<div style='background-color:#444; color:#ccc; padding: 2px 10px; font-size:10px; "
                f"border-radius: 8px 8px 0 0; border:1px solid #555;'>{lang if lang else 'Code'}</div>"
                f"<pre style='background-color:#2a2a2a; color:#f8f8f2; padding:15px; margin:0; "
                f"border-radius: 0 0 8px 8px; overflow-x:auto; border:1px solid #555; border-top:none;'>"
                f"<div style='font-family:Consolas, Courier New, monospace; font-size:12px; white-space:pre-wrap;'>"
                f"{highlighted_code}</div>"
                f"</pre>"
                f"</div>"
            )
            last_idx = match.end()

        # 6. Handle Plain Text AFTER the last code block (Or the WHOLE text if no code blocks exist)
        if last_idx < len(response):
            text_after = response[last_idx:]
            formatted_response_parts.append(self._format_text_block(text_after))

        # 7. Fallback for completely empty strings
        if not formatted_response_parts:
            formatted_response_parts.append("<p><i>(Empty response)</i></p>")

        # Join and log
        full_html_content = "".join(formatted_response_parts)
        self.gemini_logger.log_message(full_html_content, "gemini")

    def _format_text_block(self, text: str) -> str:
        """
        Helper to format plain text for HTML rendering.
        It escapes HTML characters AND converts newlines to <br> so formatting isn't lost.
        """
        if not text.strip():
            return ""

        # 1. Escape HTML special characters (<, >, &)
        safe_text = self._escape_html(text)

        # 2. Convert Python newlines to HTML line breaks so lists/paragraphs render correctly
        formatted_text = safe_text.replace("\n", "<br>")

        return f"<p style='margin-bottom: 10px;'>{formatted_text}</p>"

    @pyqtSlot(str)
    def _handle_gemini_error(self, error_message: str):
        self.gemini_logger.log_message(error_message, "error")

    @pyqtSlot()
    def _update_thinking_animation(self):
        self.thinking_animation_state = (self.thinking_animation_state % 3) + 1
        dots = "." * self.thinking_animation_state
        self.status_label.setText(f"Gemini is thinking{dots}")
        self.send_button.setText(f"Thinking{dots}")

    @pyqtSlot()
    def _on_thinking_started(self):
        self.send_button.setEnabled(False)
        self.user_input.setEnabled(False)
        self.status_label.setStyleSheet("color: #ffff00; font-style: italic;")
        self.thinking_animation_state = 0
        self._update_thinking_animation()
        self.thinking_timer.start(500)

    @pyqtSlot()
    def _on_thinking_finished(self):
        self.thinking_timer.stop()
        self.send_button.setEnabled(True)
        self.user_input.setEnabled(True)
        self.status_label.setText("Ready")
        self.status_label.setStyleSheet("color: #dcdcdc; font-style: italic;")
        self.send_button.setText("Send")

    def _escape_html(self, text: str) -> str:
        return text.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;").replace("'", "&#x27;")

    @pyqtSlot(str, str)
    def log_message(self, content: str, message_type: str = "info"):
        prefix = ""
        color = ""

        if message_type == "user":
            prefix = "<b>You:</b> "
            color = "#87CEEB"
        elif message_type == "gemini":
            prefix = "<b>Gemini:</b> "
            color = "#90EE90"
        elif message_type == "error":
            prefix = "<b>ERROR:</b> "
            color = "#FF6347"

        final_html = (
            f"<div style='color:{color}; margin-bottom: 12px;'>"
            f"{prefix}{content}</div><br>"
        )

        self.chat_output.moveCursor(QTextCursor.End)
        self.chat_output.insertHtml(final_html)
        self.chat_output.insertHtml("<br>")
        self.chat_output.moveCursor(QTextCursor.End)


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

    @pyqtSlot(dict)
    def do_send_packetlab(self, config):
        self.request_queue.put(('packetlab', (dict(config or {}),)))


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
                elif request_type == 'packetlab':
                    status, packet = self.packet_manager.send_packetlab(*args)
                    summary = packet.summary() if packet is not None else "no packet"
                    self.logger.log_message(f"[PacketLab Result] {status}: {summary}")

            except Exception as e:
                self.logger.log_message(f"[PacketSenderThread] CRITICAL ERROR: {e}")

        self.logger.log_message("[PacketSenderThread] Worker thread stopped.")



class P2PoolTab(QWidget):
    """
    P2Pool tab with:
      - Start/Stop buttons
      - Console log
      - Command textbox that writes to the running P2Pool process stdin
    """

    log_signal = pyqtSignal(str)

    def __init__(self, p2pool_helper=None, parent=None):
        super().__init__(parent)
        self.p2pool_helper = p2pool_helper

        self._create_widgets()
        self._configure_layout()

        self.log_signal.connect(self.log_message)

    def _create_widgets(self):
        self.start_p2pool_button = QPushButton("Start P2Pool")
        self.start_p2pool_button.setObjectName("start_button")
        self.start_p2pool_button.setEnabled(False)

        self.stop_p2pool_button = QPushButton("Stop P2Pool")
        self.stop_p2pool_button.setObjectName("stop_button")
        self.stop_p2pool_button.setEnabled(False)

        self.command_label = QLabel("P2Pool Command:")
        self.command_input = QLineEdit()
        self.command_input.setPlaceholderText("Type a P2Pool command and press Enter...")
        self.command_input.returnPressed.connect(self.send_command_to_p2pool)

        self.send_command_button = QPushButton("Send Command")
        self.send_command_button.setObjectName("send_command_button")
        self.send_command_button.clicked.connect(self.send_command_to_p2pool)

        self.console_log = QPlainTextEdit()
        self.console_log.setReadOnly(True)
        self.console_log.setMaximumBlockCount(25000)

    def _configure_layout(self):
        layout = QVBoxLayout(self)

        control_layout = QHBoxLayout()
        control_layout.addWidget(self.start_p2pool_button)
        control_layout.addWidget(self.stop_p2pool_button)
        control_layout.addStretch(1)

        command_layout = QHBoxLayout()
        command_layout.addWidget(self.command_label)
        command_layout.addWidget(self.command_input, 1)
        command_layout.addWidget(self.send_command_button)

        layout.addLayout(control_layout)
        layout.addLayout(command_layout)
        layout.addWidget(self.console_log)

    def set_p2pool_helper(self, p2pool_helper):
        self.p2pool_helper = p2pool_helper

    def _get_running_proc(self):
        if not self.p2pool_helper:
            return None

        try:
            return self.p2pool_helper.p2pooldata.p2pool_proc
        except Exception:
            return None

    def _get_async_loop(self):
        if not self.p2pool_helper:
            return None

        return getattr(self.p2pool_helper, "asyncio_main_loop", None)

    def _append_local_status(self, text: str):
        self.log_signal.emit(text)

    def send_command_to_p2pool(self):
        command = self.command_input.text().strip()
        if not command:
            self._append_local_status("[P2PoolTab] No command entered.")
            return

        if not self.p2pool_helper:
            self._append_local_status("[P2PoolTab] No p2pool_helper is attached.")
            return

        loop = self._get_async_loop()
        if loop is None:
            self._append_local_status("[P2PoolTab] Asyncio loop is not available.")
            return

        proc = self._get_running_proc()
        if proc is None or proc.returncode is not None:
            self._append_local_status("[P2PoolTab] P2Pool is not running.")
            return

        try:
            future = asyncio.run_coroutine_threadsafe(
                self.p2pool_helper.processor.write_to_stdin(command),
                loop,
            )
            ok = future.result(timeout=5)

            if ok:
                self._append_local_status(f"> {command}")
                self.command_input.clear()
            else:
                self._append_local_status(f"[P2PoolTab] Failed to send command: {command}")

        except Exception as e:
            self._append_local_status(f"[P2PoolTab] Error sending command: {e}")

    @pyqtSlot(str)
    def log_message(self, message: str):
        self.console_log.appendPlainText(message)

class WiresharkTab(QWidget):
    """Wireshark/tshark capture controls with bounded, explicit capture policy."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_widgets()
        self._configure_layout()

    def _create_widgets(self):
        self.start_wireshark_button = QPushButton("Start Wireshark Capture")
        self.start_wireshark_button.setObjectName("start_wireshark_button")
        self.start_wireshark_button.setEnabled(False)

        self.stop_wireshark_button = QPushButton("Stop Wireshark Capture")
        self.stop_wireshark_button.setObjectName("stop_wireshark_button")
        self.stop_wireshark_button.setEnabled(False)

        self.main_interface_input = QLineEdit("Auto")
        self.main_interface_input.setPlaceholderText("Friendly name, GUID, NPF path, or Auto")

        self.include_loopback_checkbox = QCheckBox("Capture loopback")
        self.include_loopback_checkbox.setChecked(True)
        self.include_vpn_checkbox = QCheckBox("Capture detected VPN adapters")
        self.include_vpn_checkbox.setChecked(True)
        self.include_multicast_checkbox = QCheckBox("Capture multicast")
        self.include_multicast_checkbox.setChecked(False)
        self.include_discovery_checkbox = QCheckBox("Capture mDNS/SSDP/WS-Discovery/LLMNR")
        self.include_discovery_checkbox.setChecked(False)
        self.include_dhcp_checkbox = QCheckBox("Capture DHCPv4/DHCPv6")
        self.include_dhcp_checkbox.setChecked(True)
        self.include_localhost_checkbox = QCheckBox("Capture localhost addresses")
        self.include_localhost_checkbox.setChecked(True)
        self.promiscuous_checkbox = QCheckBox("Promiscuous mode")
        self.promiscuous_checkbox.setChecked(True)
        self.full_details_checkbox = QCheckBox("Request full tshark protocol details")
        self.full_details_checkbox.setChecked(True)
        self.feed_router_checkbox = QCheckBox("Feed reconstructed packets into router queue")
        self.feed_router_checkbox.setChecked(False)
        self.feed_router_checkbox.setToolTip(
            "Off by default because Npcap already feeds the router. Enable only when tshark is the intended capture source."
        )
        self.log_summaries_checkbox = QCheckBox("Log one summary per packet")
        self.log_summaries_checkbox.setChecked(False)
        self.log_payloads_checkbox = QCheckBox("Log decoded/raw payload previews")
        self.log_payloads_checkbox.setChecked(False)
        self.log_filtered_checkbox = QCheckBox("Log every filtered/noisy packet")
        self.log_filtered_checkbox.setChecked(False)

        self.min_packet_len_input = QSpinBox()
        self.min_packet_len_input.setRange(0, 65535)
        self.min_packet_len_input.setValue(0)
        self.max_interfaces_input = QSpinBox()
        self.max_interfaces_input.setRange(1, 32)
        self.max_interfaces_input.setValue(8)
        self.custom_bpf_input = QLineEdit()
        self.custom_bpf_input.setPlaceholderText("Optional additional BPF expression")

        self.wireshark_log = QPlainTextEdit()
        self.wireshark_log.setReadOnly(True)
        self.wireshark_log.setMaximumBlockCount(10000)

    def capture_settings(self) -> dict:
        return {
            "main_interface": self.main_interface_input.text().strip() or "Auto",
            "include_loopback": self.include_loopback_checkbox.isChecked(),
            "include_vpn": self.include_vpn_checkbox.isChecked(),
            "include_multicast": self.include_multicast_checkbox.isChecked(),
            "include_discovery": self.include_discovery_checkbox.isChecked(),
            "include_dhcp": self.include_dhcp_checkbox.isChecked(),
            "include_localhost": self.include_localhost_checkbox.isChecked(),
            "promiscuous": self.promiscuous_checkbox.isChecked(),
            "full_details": self.full_details_checkbox.isChecked(),
            "feed_router": self.feed_router_checkbox.isChecked(),
            "log_packet_summaries": self.log_summaries_checkbox.isChecked(),
            "log_payloads": self.log_payloads_checkbox.isChecked(),
            "log_filtered_packets": self.log_filtered_checkbox.isChecked(),
            "min_packet_len": int(self.min_packet_len_input.value()),
            "max_interfaces": int(self.max_interfaces_input.value()),
            "custom_bpf": self.custom_bpf_input.text().strip(),
        }

    def _configure_layout(self):
        layout = QVBoxLayout(self)
        control_layout = QHBoxLayout()
        control_layout.addWidget(self.start_wireshark_button)
        control_layout.addWidget(self.stop_wireshark_button)
        control_layout.addStretch(1)
        layout.addLayout(control_layout)

        settings_box = QGroupBox("Capture Settings")
        grid = QGridLayout(settings_box)
        grid.addWidget(QLabel("Main interface:"), 0, 0)
        grid.addWidget(self.main_interface_input, 0, 1, 1, 3)
        grid.addWidget(self.include_loopback_checkbox, 1, 0)
        grid.addWidget(self.include_vpn_checkbox, 1, 1)
        grid.addWidget(self.include_multicast_checkbox, 1, 2)
        grid.addWidget(self.include_discovery_checkbox, 1, 3)
        grid.addWidget(self.include_dhcp_checkbox, 2, 0)
        grid.addWidget(self.include_localhost_checkbox, 2, 1)
        grid.addWidget(self.promiscuous_checkbox, 2, 2)
        grid.addWidget(self.full_details_checkbox, 2, 3)
        grid.addWidget(self.feed_router_checkbox, 3, 0, 1, 2)
        grid.addWidget(self.log_summaries_checkbox, 3, 2)
        grid.addWidget(self.log_payloads_checkbox, 3, 3)
        grid.addWidget(self.log_filtered_checkbox, 4, 0, 1, 2)
        grid.addWidget(QLabel("Minimum frame length:"), 5, 0)
        grid.addWidget(self.min_packet_len_input, 5, 1)
        grid.addWidget(QLabel("Maximum interfaces:"), 5, 2)
        grid.addWidget(self.max_interfaces_input, 5, 3)
        grid.addWidget(QLabel("Additional BPF:"), 6, 0)
        grid.addWidget(self.custom_bpf_input, 6, 1, 1, 3)
        layout.addWidget(settings_box)
        layout.addWidget(self.wireshark_log)

    @pyqtSlot(str)
    def log_message(self, message: str):
        self.wireshark_log.appendPlainText(message)




class RouterTab(QWidget):
    codeoutput_probe_requested = pyqtSignal(dict)
    codeoutput_interface_create_requested = pyqtSignal(dict)
    codeoutput_interface_remove_requested = pyqtSignal(bool)
    _PREFIX_RE = re.compile(r"\[([^\[\]]{1,64})\]")

    def __init__(self, logger, parent=None):
        super().__init__(parent)
        self.router_logger = logger

        self.router_logger.message_signal.connect(
            self.log_message,
            Qt.ConnectionType.QueuedConnection
        )
        self._console_panes = {}
        self._pane_index = {}
        self._settings_sections = {}
        self._active_settings_section = None

        self.presets = {
            "Full": [
                "General", "Router", "DHCP", "Transport", "HostBoundary", "TLS", "Python", "C++", "Signing",
                "CodeOutput", "Kerberos/ESP", "Stratum/StratumConn", "DNS",
                "Handshake/SSL/TCP", "ICMP/IGMP", "PacketWriter", "PacketCatcher",
                "Notifier", "NAT/RIP/ARP/NDP","Bridge/L2", "Wintun/WinDivert", "HyperVRouterManager", "SocketInterface", "mDNS", "Firewall", "Packet", "Analysis"
            ],
            "Minimal": ["General"],
        }

        self._hot_prefix_to_pane = {
            self._norm("C++"): "C++",
        }

        # -------- safe logging state --------
        # The RouterLogger already applies producer-side pressure.  This second
        # bounded queue protects the GUI consumer and limits both line count and
        # memory, while a small time budget keeps paint/input events responsive.
        self._log_queue = deque()
        self._log_queue_bytes = 0
        self._max_log_queue = 10000
        self._max_log_queue_bytes = 12 * 1024 * 1024
        self._flush_batch_size = 300
        self._flush_time_budget_seconds = 0.012
        self._logging_shutdown = False
        self._flush_in_progress = False
        self._dropping_logs = False
        self._dropped_log_lines = 0
        self._last_drop_notice = 0.0

        self._create_widgets()
        self._configure_layout()
        self._connect_signals()

        if "General" not in self._console_panes:
            self._add_console_pane("General")

        self._log_flush_timer = QTimer(self)
        self._log_flush_timer.setInterval(33)
        self._log_flush_timer.timeout.connect(self._flush_log_queue)
        self._log_flush_timer.start()


    def _create_widgets(self):
        self.start_router_button = QPushButton("Start Router")
        self.stop_router_button = QPushButton("Stop Router")
        self.stop_router_button.setEnabled(False)

        self.settings_toggle_button = QPushButton("⚙ Settings ▶")
        self.settings_toggle_button.setCheckable(True)
        self.settings_toggle_button.setChecked(False)
        self.settings_toggle_button.setToolTip(
            "Show or hide all router settings menus."
        )

        self.stratum_comm_checkbox = QCheckBox("Use Stratum Comm")
        self.stratum_comm_checkbox.setChecked(False)

        self.stratum_mode_dropdown = QComboBox()
        self.stratum_mode_dropdown.addItems(
            ["Direct Pool / P2Pool", "Local Monero Daemon"]
        )

        self.stratum_pool_host_input = QLineEdit()
        self.stratum_pool_host_input.setText("127.0.0.1")
        self.stratum_pool_host_input.setPlaceholderText(
            "Pool address or hostname"
        )

        # Backward-compatible alias used by existing GUI code.
        self.p2pool_server_ip_input = self.stratum_pool_host_input

        self.stratum_pool_port_input = QLineEdit()
        self.stratum_pool_port_input.setText("3333")
        self.stratum_pool_port_input.setPlaceholderText("Pool port")

        self.stratum_wallet_input = QLineEdit()
        self.stratum_wallet_input.setText(
            "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
        )
        self.stratum_wallet_input.setPlaceholderText(
            "Wallet address or pool login"
        )

        self.stratum_password_input = QLineEdit()
        self.stratum_password_input.setText("x")
        self.stratum_password_input.setEchoMode(QLineEdit.Password)
        self.stratum_password_input.setPlaceholderText(
            "Stratum server password"
        )
        self.stratum_password_input.setToolTip(
            "Used only for Stratum login and never written to router logs."
        )

        self.stratum_worker_input = QLineEdit()
        self.stratum_worker_input.setText("PythonProxy")
        self.stratum_worker_input.setPlaceholderText("Worker / rig name")

        self.stratum_tls_dropdown = QComboBox()
        self.stratum_tls_dropdown.addItems(["Auto", "Enabled", "Disabled"])

        self.stratum_sni_input = QLineEdit()
        self.stratum_sni_input.setPlaceholderText(
            "TLS hostname / SNI (optional)"
        )

        self.stratum_proxy_checkbox = QCheckBox("Enable Local Stratum Proxy")
        self.stratum_proxy_checkbox.setChecked(True)

        self.stratum_proxy_host_input = QLineEdit()
        self.stratum_proxy_host_input.setText("127.0.0.1")
        self.stratum_proxy_host_input.setPlaceholderText("Proxy listen host")

        self.stratum_proxy_port_input = QLineEdit()
        self.stratum_proxy_port_input.setText("3334")
        self.stratum_proxy_port_input.setPlaceholderText("Proxy listen port")

        self.stratum_user_agent_input = QLineEdit()
        self.stratum_user_agent_input.setText("pystratum/0.5")
        self.stratum_user_agent_input.setPlaceholderText("Stratum user agent")

        self.stratum_daemon_url_input = QLineEdit()
        self.stratum_daemon_url_input.setText("http://127.0.0.1:18081")
        self.stratum_daemon_url_input.setPlaceholderText("Monero daemon RPC URL")

        self.stratum_zmq_address_input = QLineEdit()
        self.stratum_zmq_address_input.setText("tcp://127.0.0.1:18083")
        self.stratum_zmq_address_input.setPlaceholderText(
            "Monero daemon ZMQ address"
        )

        self.blocknet_checkbox = QCheckBox("Use BlockNet")
        self.blocknet_checkbox.setChecked(False)

        self.peer_to_peer_checkbox = QCheckBox("Use Peer to Peer")
        self.peer_to_peer_checkbox.setChecked(False)

        self.dhcp_out_checkbox = QCheckBox("DHCP OUT")
        self.dhcp_out_checkbox.setChecked(False)

        self.dhcp_in_checkbox = QCheckBox("DHCP IN")
        self.dhcp_in_checkbox.setChecked(False)

        self.dhcp_out_mode_dropdown = QComboBox()
        self.dhcp_out_mode_dropdown.addItems([
            "Direct Lease Only", "Managed / Repair"
        ])
        self.dhcp_out_mode_dropdown.setToolTip(
            "Direct Lease Only accepts the adapter DHCP lease without starting "
            "host-preservation, uplink repair, or extra interprocess orchestration."
        )
        self.dhcp_in_mode_dropdown = QComboBox()
        self.dhcp_in_mode_dropdown.addItems([
            "Direct Lease Only", "Managed / Repair"
        ])
        self.dhcp_in_mode_dropdown.setToolTip(
            "Direct Lease Only accepts the LAN-side adapter lease directly."
        )

        self.dhcp_interface_refresh_button = QPushButton("Refresh Interfaces")
        self.dhcp_lan_interfaces_list = QListWidget()
        self.dhcp_wan_interfaces_list = QListWidget()
        for interface_list in (
            self.dhcp_lan_interfaces_list,
            self.dhcp_wan_interfaces_list,
        ):
            interface_list.setSelectionMode(QAbstractItemView.MultiSelection)
            interface_list.setMinimumHeight(100)
            interface_list.setToolTip(
                "Select every physical or virtual adapter that belongs to this DHCP role."
            )

        self.dhcp_server_checkbox = QCheckBox("Run LAN DHCP Server")
        self.dhcp_server_checkbox.setChecked(True)

        self.serve_dhcp_on_wan_checkbox = QCheckBox(
            "Serve DHCP on WAN"
        )
        self.serve_dhcp_on_wan_checkbox.setChecked(False)
        self.serve_dhcp_on_wan_checkbox.setToolTip(
            "Advanced: replies to DHCP clients on the selected WAN/uplink. "
            "Leave disabled on networks you do not own or administer."
        )

        self.dhcp_pool_start_input = QLineEdit()
        self.dhcp_pool_start_input.setPlaceholderText(
            "Auto from router LAN network"
        )
        self.dhcp_pool_end_input = QLineEdit()
        self.dhcp_pool_end_input.setPlaceholderText(
            "Auto from router LAN network"
        )
        self.dhcp_dns_input = QLineEdit()
        self.dhcp_dns_input.setPlaceholderText(
            "Blank = router LAN IP; comma-separated"
        )
        self.dhcp_domain_input = QLineEdit()
        self.dhcp_domain_input.setText("lan.internal")
        self.dhcp_lease_seconds_input = QLineEdit()
        self.dhcp_lease_seconds_input.setText("600")
        self.dhcp_max_leases_input = QLineEdit()
        self.dhcp_max_leases_input.setPlaceholderText(
            "Blank = pool capacity"
        )
        self.dhcp_authoritative_checkbox = QCheckBox("Authoritative")
        self.dhcp_authoritative_checkbox.setChecked(True)
        self.dhcp_allow_out_of_pool_checkbox = QCheckBox(
            "Allow Out-of-Pool Requests"
        )
        self.dhcp_allow_out_of_pool_checkbox.setChecked(False)
        self.dhcp_enforce_subnet_checkbox = QCheckBox(
            "Enforce Same Subnet"
        )
        self.dhcp_enforce_subnet_checkbox.setChecked(True)
        self.dhcp_rogue_policy_dropdown = QComboBox()
        self.dhcp_rogue_policy_dropdown.addItems(
            ["Log Only", "NAK on Mismatch"]
        )
        self.dhcp_relay_input = QLineEdit()
        self.dhcp_relay_input.setPlaceholderText(
            "DHCPv4 relay target (optional)"
        )
        self.dhcp6_prefix_input = QLineEdit()
        self.dhcp6_prefix_input.setPlaceholderText(
            "IPv6 prefix (optional)"
        )
        self.dhcp6_relay_input = QLineEdit()
        self.dhcp6_relay_input.setPlaceholderText(
            "DHCPv6 relay target (optional)"
        )
        self.dhcp_dns_v6_input = QLineEdit()
        self.dhcp_dns_v6_input.setText("fd00::1, fd00::2")
        self.dhcp_search_domains_input = QLineEdit()
        self.dhcp_search_domains_input.setText("lan.internal")

        self.dhcp_additional_ifaces_input = QLineEdit()
        self.dhcp_additional_ifaces_input.setText(
            "WinDivertBridge, Nate's Tunnel, WireShark"
        )
        self.dhcp_additional_ifaces_input.setPlaceholderText(
            "Comma-separated aliases that share the LAN DHCP scope"
        )
        self.dhcp_additional_ifaces_input.setToolTip(
            "Assign the LAN DHCP server to logical/virtual interfaces such as "
            "WinDivertBridge, Nate's Tunnel, WireShark, or vEthernet. These "
            "aliases inherit the LAN router IP/netmask and are persisted for "
            "the sniffer's IPv4 resolver."
        )

        self.dhcp_interface_profiles_input = QPlainTextEdit()
        self.dhcp_interface_profiles_input.setMaximumHeight(110)
        self.dhcp_interface_profiles_input.setPlaceholderText(
            '[{"iface":"vEthernet (Router)","cidr":"192.168.162.1/24",'
            '"pool_start":"192.168.162.100","pool_end":"192.168.162.220"}]'
        )
        self.dhcp_interface_profiles_input.setToolTip(
            "Optional JSON list of independent private DHCP scopes. Each object "
            "needs iface and cidr; pool_start/pool_end, dns_v4, aliases, lease "
            "settings, and other LAN DHCP options are optional."
        )

        self.wan_dhcp_pool_start_input = QLineEdit()
        self.wan_dhcp_pool_start_input.setPlaceholderText(
            "WAN pool start"
        )
        self.wan_dhcp_pool_end_input = QLineEdit()
        self.wan_dhcp_pool_end_input.setPlaceholderText(
            "WAN pool end"
        )
        self.wan_dhcp_dns_input = QLineEdit()
        self.wan_dhcp_dns_input.setPlaceholderText(
            "Blank = router WAN IP; comma-separated"
        )
        self.wan_dhcp_domain_input = QLineEdit()
        self.wan_dhcp_domain_input.setText("wan.router")
        self.wan_dhcp_lease_seconds_input = QLineEdit()
        self.wan_dhcp_lease_seconds_input.setText("600")
        self.wan_dhcp_max_leases_input = QLineEdit()
        self.wan_dhcp_max_leases_input.setPlaceholderText(
            "Blank = pool capacity"
        )
        self.wan_dhcp_authoritative_checkbox = QCheckBox(
            "WAN Authoritative"
        )
        self.wan_dhcp_authoritative_checkbox.setChecked(True)
        self.wan_dhcp_allow_out_of_pool_checkbox = QCheckBox(
            "WAN Allow Out-of-Pool"
        )
        self.wan_dhcp_allow_out_of_pool_checkbox.setChecked(False)
        self.wan_dhcp_enforce_subnet_checkbox = QCheckBox(
            "WAN Enforce Same Subnet"
        )
        self.wan_dhcp_enforce_subnet_checkbox.setChecked(True)
        self.wan_dhcp_rogue_policy_dropdown = QComboBox()
        self.wan_dhcp_rogue_policy_dropdown.addItems(
            ["Log Only", "NAK on Mismatch"]
        )
        self.wan_dhcp_relay_input = QLineEdit()
        self.wan_dhcp_relay_input.setPlaceholderText(
            "WAN DHCP relay target (optional)"
        )

        self.transport_enabled_checkbox = QCheckBox(
            "Enable Transport Manager"
        )
        self.transport_enabled_checkbox.setChecked(True)
        self.transport_parallel_analysis_checkbox = QCheckBox(
            "Parallel Passive Analysis"
        )
        self.transport_parallel_analysis_checkbox.setChecked(True)
        self.transport_protocol_checkboxes = {}
        transport_protocol_labels = [
            ("inspection", "Deep Inspection"),
            ("scraper", "Transport Scraper"),
            ("https", "HTTPS / TLS"),
            ("http", "HTTP"),
            ("stratum", "Stratum"),
            ("monero", "Monero / P2Pool"),
            ("dns", "DNS"),
            ("dhcp4", "DHCPv4"),
            ("dhcp6", "DHCPv6"),
            ("mdns", "mDNS"),
            ("llmnr", "LLMNR"),
            ("nbns", "NBNS"),
            ("nbds", "NBDS"),
            ("ssdp", "SSDP"),
            ("ws_discovery", "WS-Discovery"),
            ("quic", "QUIC"),
            ("ipv6", "IPv6"),
            ("ike_esp", "IKE / ESP"),
            ("wireguard", "WireGuard"),
            ("ssh", "SSH"),
            ("ftp", "FTP"),
            ("rdp", "RDP"),
            ("kerberos", "Kerberos"),
            ("steam", "Steam"),
            ("scada", "SCADA"),
            ("snmp", "SNMP"),
            ("rip", "RIP"),
            ("rtp", "RTP / VoIP"),
            ("sip", "SIP"),
            ("ntp", "NTP"),
            ("tftp", "TFTP"),
            ("overlay", "Overlay Networks"),
            ("files", "File Services"),
            ("tcp_ephemeral", "Ephemeral TCP"),
            ("tcp_high_server", "High Server TCP"),
            ("udp_ephemeral", "Ephemeral UDP"),
            ("undecoded", "Undecoded UDP"),
        ]
        for protocol_key, protocol_label in transport_protocol_labels:
            checkbox = QCheckBox(protocol_label)
            checkbox.setChecked(True)
            self.transport_protocol_checkboxes[
                protocol_key
            ] = checkbox

        self.transport_stratum_ports_input = QLineEdit()
        self.transport_stratum_ports_input.setText(
            "3333, 4444, 5555, 6666, 7777, 8888, 9999, 14444, 24444"
        )
        self.transport_monero_ports_input = QLineEdit()
        self.transport_monero_ports_input.setText(
            "18080, 28080, 38080, 41257, 18081, 18083, "
            "18089, 28081, 38081, 37888, 37889"
        )
        self.transport_voip_start_input = QLineEdit()
        self.transport_voip_start_input.setText("10000")
        self.transport_voip_end_input = QLineEdit()
        self.transport_voip_end_input.setText("20000")
        self.transport_inspection_rps_input = QLineEdit()
        self.transport_inspection_rps_input.setText("0.2")
        self.transport_inspection_burst_input = QLineEdit()
        self.transport_inspection_burst_input.setText("50")
        self.transport_inspection_cooldown_input = QLineEdit()
        self.transport_inspection_cooldown_input.setText("20.0")
        self.transport_stratum_rps_input = QLineEdit()
        self.transport_stratum_rps_input.setText("1.5")
        self.transport_stratum_burst_input = QLineEdit()
        self.transport_stratum_burst_input.setText("120")
        self.transport_stratum_cooldown_input = QLineEdit()
        self.transport_stratum_cooldown_input.setText("1.2")
        self.transport_monero_rps_input = QLineEdit()
        self.transport_monero_rps_input.setText("2.0")
        self.transport_monero_burst_input = QLineEdit()
        self.transport_monero_burst_input.setText("140")
        self.transport_monero_cooldown_input = QLineEdit()
        self.transport_monero_cooldown_input.setText("1.2")
        self.transport_dns_pending_ttl_input = QLineEdit()
        self.transport_dns_pending_ttl_input.setText("30")
        self.transport_dns_gc_interval_input = QLineEdit()
        self.transport_dns_gc_interval_input.setText("10")
        self.transport_dns_rebind_alert_checkbox = QCheckBox(
            "Alert on DNS Rebinding"
        )
        self.transport_dns_rebind_alert_checkbox.setChecked(True)
        self.transport_dhcp_transaction_ttl_input = QLineEdit()
        self.transport_dhcp_transaction_ttl_input.setText("180")
        self.transport_dhcp_lease_ttl_input = QLineEdit()
        self.transport_dhcp_lease_ttl_input.setText("86400")
        self.transport_https_logging_checkbox = QCheckBox(
            "HTTPS Logging"
        )
        self.transport_https_logging_checkbox.setChecked(True)
        self.transport_https_certificates_checkbox = QCheckBox(
            "Parse TLS Certificates"
        )
        self.transport_https_certificates_checkbox.setChecked(True)
        self.transport_https_quic_crypto_checkbox = QCheckBox(
            "Parse QUIC Crypto"
        )
        self.transport_https_quic_crypto_checkbox.setChecked(True)
        self.transport_tls_learning_checkbox = QCheckBox(
            "Feed Handshake/TLS Learning into Transport"
        )
        self.transport_tls_learning_checkbox.setChecked(True)
        self.transport_https_init_context_checkbox = QCheckBox(
            "Use TLS Context in Initial HTTPS Logs"
        )
        self.transport_https_init_context_checkbox.setChecked(True)

        self.codeoutput_enabled_checkbox = QCheckBox("Enable CodeOutput Manager")
        self.codeoutput_enabled_checkbox.setChecked(True)
        self.codeoutput_auto_emit_checkbox = QCheckBox("Automatic Code Generation")
        self.codeoutput_auto_emit_checkbox.setChecked(True)
        self.codeoutput_active_probes_checkbox = QCheckBox(
            "Enable Active Packet/Socket Probes"
        )
        self.codeoutput_active_probes_checkbox.setChecked(False)
        self.codeoutput_allow_public_checkbox = QCheckBox(
            "Allow Public Internet Targets"
        )
        self.codeoutput_allow_public_checkbox.setChecked(False)
        self.codeoutput_verbose_input = QSpinBox()
        self.codeoutput_verbose_input.setRange(0, 5)
        self.codeoutput_verbose_input.setValue(2)
        self.codeoutput_emit_interval_input = QLineEdit("10.0")
        self.codeoutput_emit_jitter_input = QLineEdit("2.0")
        self.codeoutput_min_packets_input = QSpinBox()
        self.codeoutput_min_packets_input.setRange(1, 100000)
        self.codeoutput_min_packets_input.setValue(4)
        self.codeoutput_max_chars_input = QSpinBox()
        self.codeoutput_max_chars_input.setRange(4096, 2000000)
        self.codeoutput_max_chars_input.setValue(250000)
        self.codeoutput_probe_timeout_input = QLineEdit("3.0")
        self.codeoutput_probe_rate_input = QSpinBox()
        self.codeoutput_probe_rate_input.setRange(1, 600)
        self.codeoutput_probe_rate_input.setValue(30)
        self.codeoutput_probe_concurrency_input = QSpinBox()
        self.codeoutput_probe_concurrency_input.setRange(1, 16)
        self.codeoutput_probe_concurrency_input.setValue(2)
        self.codeoutput_target_input = QLineEdit()
        self.codeoutput_target_input.setPlaceholderText("IP address or hostname")
        self.codeoutput_protocol_dropdown = QComboBox()
        self.codeoutput_protocol_dropdown.addItems(["TCP", "UDP", "ICMP"])
        self.codeoutput_port_input = QSpinBox()
        self.codeoutput_port_input.setRange(0, 65535)
        self.codeoutput_port_input.setValue(443)
        self.codeoutput_payload_input = QLineEdit()
        self.codeoutput_payload_input.setPlaceholderText("Optional payload text")
        self.codeoutput_iface_dropdown = QComboBox()
        self.codeoutput_iface_dropdown.setEditable(True)
        self.codeoutput_probe_button = QPushButton("Send CodeOutput Probe")

        self.codeoutput_interface_checkbox = QCheckBox("Create and register real CodeOutput interface")
        self.codeoutput_interface_checkbox.setChecked(False)
        self.codeoutput_switch_name_input = QLineEdit("CodeOutput")
        self.codeoutput_adapter_name_input = QLineEdit("CodeOutput")
        self.codeoutput_interface_ip_input = QLineEdit("172.30.253.1")
        self.codeoutput_interface_prefix_input = QSpinBox()
        self.codeoutput_interface_prefix_input.setRange(1, 30)
        self.codeoutput_interface_prefix_input.setValue(30)
        self.codeoutput_remove_on_shutdown_checkbox = QCheckBox("Remove CodeOutput switch on router shutdown")
        self.codeoutput_remove_on_shutdown_checkbox.setChecked(False)
        self.codeoutput_force_remove_checkbox = QCheckBox("Force removal of an existing switch")
        self.codeoutput_force_remove_checkbox.setChecked(False)
        self.codeoutput_create_interface_button = QPushButton("Create / Register CodeOutput Interface")
        self.codeoutput_remove_interface_button = QPushButton("Remove CodeOutput Interface")

        self.core_firewall_checkbox = QCheckBox("Firewall Manager")
        self.core_firewall_checkbox.setChecked(True)
        self.core_packet_analyzer_checkbox = QCheckBox(
            "Packet Analyzer"
        )
        self.core_packet_analyzer_checkbox.setChecked(True)
        self.core_packet_catcher_checkbox = QCheckBox(
            "Packet Catcher"
        )
        self.core_packet_catcher_checkbox.setChecked(True)
        self.core_handshake_checkbox = QCheckBox(
            "TCP / TLS Handshake Manager"
        )
        self.core_handshake_checkbox.setChecked(True)
        self.core_syn_scanner_checkbox = QCheckBox("SYN Scanner")
        self.core_syn_scanner_checkbox.setChecked(False)
        self.core_syn_scanner_checkbox.setToolTip(
            "Active scanner. Disabled by default to keep router startup idle."
        )
        self.core_igmp_checkbox = QCheckBox("IGMP Manager")
        self.core_igmp_checkbox.setChecked(True)
        self.core_mdns_checkbox = QCheckBox("mDNS Manager")
        self.core_mdns_checkbox.setChecked(True)
        self.handshake_half_open_timeout_input = QLineEdit()
        self.handshake_half_open_timeout_input.setText("60")
        self.handshake_established_timeout_input = QLineEdit()
        self.handshake_established_timeout_input.setText("300")
        self.handshake_rate_threshold_input = QLineEdit()
        self.handshake_rate_threshold_input.setText("20")
        self.handshake_rate_period_input = QLineEdit()
        self.handshake_rate_period_input.setText("60")
        self.handshake_ban_duration_input = QLineEdit()
        self.handshake_ban_duration_input.setText("300")
        self.handshake_log_tcp_checkbox = QCheckBox(
            "Log TCP Lifecycle"
        )
        self.handshake_log_tcp_checkbox.setChecked(True)
        self.handshake_log_non_tls_checkbox = QCheckBox(
            "Log Non-TLS TCP"
        )
        self.handshake_log_non_tls_checkbox.setChecked(False)
        self.handshake_log_tls_records_checkbox = QCheckBox(
            "Log TLS Records"
        )
        self.handshake_log_tls_records_checkbox.setChecked(True)
        self.handshake_log_app_data_checkbox = QCheckBox(
            "Log TLS Application Data"
        )
        self.handshake_log_app_data_checkbox.setChecked(False)
        self.handshake_log_tls13_keys_checkbox = QCheckBox(
            "Log TLS 1.3 Key Events"
        )
        self.handshake_log_tls13_keys_checkbox.setChecked(True)
        self.syn_scan_interval_input = QLineEdit()
        self.syn_scan_interval_input.setText("300")
        self.packet_catcher_tcp_rate_input = QLineEdit()
        self.packet_catcher_tcp_rate_input.setText("0.60")
        self.packet_catcher_udp_rate_input = QLineEdit()
        self.packet_catcher_udp_rate_input.setText("0.60")
        self.packet_catcher_default_rate_input = QLineEdit()
        self.packet_catcher_default_rate_input.setText("0.60")

        self.use_static_checkbox = QCheckBox("Use Static (all)")
        self.use_static_checkbox.setChecked(False)
        self.use_scrapewebsite_checkbox = QCheckBox("Accept ScrapeWebsite Requests")
        self.use_scrapewebsite_checkbox.setChecked(False)

        self.scrapewebsite_endpoint_input = QLineEdit()
        self.scrapewebsite_endpoint_input.setText("https://scrapewebsite.pages.dev/api/router/router")
        self.scrapewebsite_endpoint_input.setPlaceholderText("ScrapeWebsite router API endpoint")
        self.use_netroute_checkbox = QCheckBox("Use NetRoute")
        self.use_netroute_checkbox.setChecked(False)
        self.use_hostbypass_checkbox = QCheckBox("Use Host Bypass")
        self.use_hostbypass_checkbox.setChecked(False)
        self.use_hyperv_checkbox = QCheckBox("Use C++ HyperV")
        self.use_hyperv_checkbox.setChecked(False)
        self.use_peerinterface_checkbox = QCheckBox("Use PeerInterface P2P")
        self.use_peerinterface_checkbox.setChecked(False)
        self.peerinterface_segment_input = QLineEdit()
        self.peerinterface_segment_input.setText("peer-main")
        self.peerinterface_segment_input.setPlaceholderText("Shared peer segment name")
        self.peerinterface_bind_ip_input = QLineEdit()
        self.peerinterface_bind_ip_input.setPlaceholderText("Blank = auto-select active LAN/WAN IPv4")
        self.peerinterface_discovery_group_input = QLineEdit()
        self.peerinterface_discovery_group_input.setText("239.255.78.78")
        self.peerinterface_discovery_port_input = QSpinBox()
        self.peerinterface_discovery_port_input.setRange(1024, 65535)
        self.peerinterface_discovery_port_input.setValue(47781)
        self.peerinterface_data_port_input = QSpinBox()
        self.peerinterface_data_port_input.setRange(1024, 65535)
        self.peerinterface_data_port_input.setValue(47782)
        self.peerinterface_shared_secret_input = QLineEdit()
        self.peerinterface_shared_secret_input.setEchoMode(QLineEdit.Password)
        self.peerinterface_shared_secret_input.setPlaceholderText("Optional shared authentication secret")
        self.peerinterface_require_auth_checkbox = QCheckBox("Require authenticated peer frames")
        self.peerinterface_require_auth_checkbox.setChecked(False)
        self.use_gateway_checkbox = QCheckBox("Use Gateway Manager")
        self.use_gateway_checkbox.setChecked(False)
        self.gateway_health_interval_input = QLineEdit()
        self.gateway_health_interval_input.setText("2.0")
        self.gateway_dns64_checkbox = QCheckBox("Enable DNS64")
        self.gateway_dns64_checkbox.setChecked(True)
        self.gateway_dns64_prefix_input = QLineEdit()
        self.gateway_dns64_prefix_input.setText("64:ff9b::/96")
        self.gateway_upstream_dns_input = QLineEdit()
        self.gateway_upstream_dns_input.setText(
            "1.1.1.1, 8.8.8.8, 9.9.9.9"
        )
        self.gateway_repair_checkbox = QCheckBox("Repair on Failure")
        self.gateway_repair_checkbox.setChecked(True)
        self.gateway_pin_arp_checkbox = QCheckBox("Pin Gateway ARP")
        self.gateway_pin_arp_checkbox.setChecked(True)
        self.gateway_probe_budget_input = QLineEdit()
        self.gateway_probe_budget_input.setText("8")

        self.use_lan_checkbox = QCheckBox("Use Lan Manager")
        self.use_lan_checkbox.setChecked(False)
        self.lan_bridge_name_input = QLineEdit()
        self.lan_bridge_name_input.setText("ManagedLANBridge")
        self.lan_create_bridge_checkbox = QCheckBox("Create LAN Bridge")
        self.lan_create_bridge_checkbox.setChecked(True)
        self.lan_health_interval_input = QLineEdit()
        self.lan_health_interval_input.setText("20.0")
        self.lan_handle_icmp_checkbox = QCheckBox("Handle LAN ICMP")
        self.lan_handle_icmp_checkbox.setChecked(True)
        self.lan_transport_dhcp_client_checkbox = QCheckBox(
            "Start LAN Transport DHCP Client"
        )
        self.lan_transport_dhcp_client_checkbox.setChecked(False)

        self.use_uplink_checkbox = QCheckBox("Use Uplink Manager")
        self.use_uplink_checkbox.setChecked(False)
        self.uplink_health_interval_input = QLineEdit()
        self.uplink_health_interval_input.setText("15.0")
        self.uplink_preferred_ifaces_input = QLineEdit()
        self.uplink_preferred_ifaces_input.setText("Wi-Fi")
        self.uplink_allow_failover_checkbox = QCheckBox(
            "Allow Router Failover"
        )
        self.uplink_allow_failover_checkbox.setChecked(True)
        self.uplink_preserve_wifi_checkbox = QCheckBox(
            "Preserve Wi-Fi Link"
        )
        self.uplink_preserve_wifi_checkbox.setChecked(True)
        self.uplink_min_score_input = QLineEdit()
        self.uplink_min_score_input.setText("45.0")

        self.use_socket = QCheckBox("Use Socket Interface")
        self.use_socket.setChecked(False)
        self.nat_os_checkbox = QCheckBox("Use OS Nat")
        self.nat_os_checkbox.setChecked(False)
        self.python_server_checkbox = QCheckBox("Use Python Server")
        self.python_server_checkbox.setChecked(False)
        self.python_server_host_input = QLineEdit()
        self.python_server_host_input.setText("0.0.0.0")
        self.python_server_port_input = QLineEdit()
        self.python_server_port_input.setText("8844")
        self.python_server_title_input = QLineEdit()
        self.python_server_title_input.setText("Router Dashboard")
        self.python_server_max_packets_input = QLineEdit()
        self.python_server_max_packets_input.setText("4000")
        self.python_server_max_logs_input = QLineEdit()
        self.python_server_max_logs_input.setText("12000")
        self.python_server_max_events_input = QLineEdit()
        self.python_server_max_events_input.setText("16000")
        self.python_server_store_raw_checkbox = QCheckBox(
            "Store Raw Packets"
        )
        self.python_server_store_raw_checkbox.setChecked(True)
        self.python_server_max_raw_bytes_input = QLineEdit()
        self.python_server_max_raw_bytes_input.setText("0")

        self.promisc_checkbox = QCheckBox("Promiscuous")
        self.promisc_checkbox.setChecked(False)
        self.ollama_checkbox = QCheckBox("Ollama")
        self.ollama_checkbox.setChecked(False)
        self.use_wifi_host_checkbox = QCheckBox("Host Wireless Network")
        self.use_wifi_host_checkbox.setChecked(False)
        self.use_wifi_host_checkbox.setToolTip(
            "Starts PythonRouterWirelessHost.exe and creates a "
            "discoverable Wi-Fi Direct network."
        )

        self.wifi_ssid_input = QLineEdit()
        self.wifi_ssid_input.setText("NateRouter")
        self.wifi_ssid_input.setMaxLength(32)
        self.wifi_ssid_input.setPlaceholderText("Wireless network name")

        self.wifi_password_input = QLineEdit()
        self.wifi_password_input.setEchoMode(QLineEdit.Password)
        self.wifi_password_input.setMaxLength(63)
        self.wifi_password_input.setPlaceholderText(
            "8-63 character wireless password"
        )
        self.wifi_password_input.setToolTip(
            "The password is passed to the wireless-host process "
            "and is not written to the router log."
        )
        self.wifi_router_ip_input = QLineEdit()
        self.wifi_router_ip_input.setText("192.168.160.1")
        self.wifi_router_ip_input.setPlaceholderText(
            "Hotspot router IPv4"
        )
        self.wifi_prefix_length_input = QLineEdit()
        self.wifi_prefix_length_input.setText("24")
        self.wifi_auto_restart_checkbox = QCheckBox(
            "Auto-Restart Wireless Host"
        )
        self.wifi_auto_restart_checkbox.setChecked(True)
        self.wifi_start_timeout_input = QLineEdit()
        self.wifi_start_timeout_input.setText("35.0")
        self.wifi_adapter_timeout_input = QLineEdit()
        self.wifi_adapter_timeout_input.setText("45.0")

        self.network_preset_dropdown = QComboBox()
        self.network_preset_dropdown.addItems(
            [
                "Detected LAN",
                "Personal Network",
                "Personal 172 Network",
                "Ole Miss 172.24.56 Lab",
                "Enterprise Network",
                "Custom",
            ]
        )
        self.apply_network_preset_button = QPushButton("Apply Preset")
        self.detect_wan_ip_button = QPushButton("Detect WAN IP")

        self.router_ip_out_input = QLineEdit()
        self.router_ip_out_input.setPlaceholderText(
            "Auto-detected current LAN/uplink IPv4"
        )

        self.router_netmask_out_input = QLineEdit()
        self.router_netmask_out_input.setText("255.255.255.0")

        self.router_ip_in_input = QLineEdit()
        self.router_ip_in_input.setPlaceholderText(
            "Blank = auto-select private LAN IP"
        )

        self.router_netmask_in_input = QLineEdit()
        self.router_netmask_in_input.setText("255.255.255.0")

        self.ipc_host_input = QLineEdit()
        self.ipc_host_input.setText("127.0.0.1")

        self.blocknet_relay_input = QLineEdit()
        self.blocknet_relay_input.setPlaceholderText("http://HOST:PORT (BlockNet Relay)")

        self.blocknet_token_input = QLineEdit()
        self.blocknet_token_input.setPlaceholderText("BlockNet Token (optional)")
        self.blocknet_token_input.setEchoMode(QLineEdit.Password)

        self.add_pane_input = QLineEdit()
        self.add_pane_input.setPlaceholderText("Add Pane")

        self.add_pane_button = QPushButton("➕")
        self.remove_pane_button = QPushButton("➖")

        self.console_tabs = QTabWidget()

        self.preset_dropdown = QComboBox()
        self.preset_dropdown.addItems(self.presets.keys())

        self._load_presets("Full")
        self._autofill_router_wan_ip(log_result=False)
        self.refresh_network_interfaces()
        self._sync_enable_states()

    def _configure_layout(self):
        try:
            from PyQt5.QtWidgets import QScrollArea
        except ImportError:
            from PyQt6.QtWidgets import QScrollArea

        layout = QVBoxLayout(self)

        top_row = QHBoxLayout()
        top_row.addWidget(self.start_router_button)
        top_row.addWidget(self.stop_router_button)
        top_row.addWidget(self.settings_toggle_button)
        top_row.addStretch(1)
        layout.addLayout(top_row)

        self.settings_container = QWidget()
        settings_layout = QVBoxLayout(self.settings_container)
        settings_layout.setContentsMargins(0, 0, 0, 0)
        settings_layout.setSpacing(4)

        addressing_content = QWidget()
        addressing_grid = QGridLayout(addressing_content)
        addressing_grid.setContentsMargins(8, 8, 8, 8)
        addressing_grid.setHorizontalSpacing(12)
        addressing_grid.setVerticalSpacing(8)
        addressing_grid.setColumnStretch(1, 1)
        addressing_grid.setColumnStretch(3, 1)

        addressing_grid.addWidget(QLabel("Preset:"), 0, 0)
        addressing_grid.addWidget(self.network_preset_dropdown, 0, 1)
        addressing_grid.addWidget(self.apply_network_preset_button, 0, 2)
        addressing_grid.addWidget(self.detect_wan_ip_button, 0, 3)
        addressing_grid.addWidget(QLabel("Router WAN IP:"), 1, 0)
        addressing_grid.addWidget(self.router_ip_out_input, 1, 1)
        addressing_grid.addWidget(QLabel("WAN netmask:"), 1, 2)
        addressing_grid.addWidget(self.router_netmask_out_input, 1, 3)
        addressing_grid.addWidget(QLabel("Router LAN IP:"), 2, 0)
        addressing_grid.addWidget(self.router_ip_in_input, 2, 1)
        addressing_grid.addWidget(QLabel("LAN netmask:"), 2, 2)
        addressing_grid.addWidget(self.router_netmask_in_input, 2, 3)

        routing_content = QWidget()
        routing_grid = QGridLayout(routing_content)
        routing_grid.setContentsMargins(8, 8, 8, 8)
        routing_grid.setHorizontalSpacing(18)
        routing_grid.setVerticalSpacing(10)

        routing_grid.addWidget(self.dhcp_out_checkbox, 0, 0)
        routing_grid.addWidget(self.dhcp_in_checkbox, 0, 1)
        routing_grid.addWidget(self.use_static_checkbox, 0, 2)
        routing_grid.addWidget(self.use_hyperv_checkbox, 0, 3)
        routing_grid.addWidget(self.use_peerinterface_checkbox, 0, 4)

        routing_grid.addWidget(self.use_netroute_checkbox, 1, 0)
        routing_grid.addWidget(self.use_hostbypass_checkbox, 1, 1)
        routing_grid.addWidget(self.use_socket, 1, 2)
        routing_grid.addWidget(self.promisc_checkbox, 1, 3)
        routing_grid.addWidget(self.ollama_checkbox, 1, 4)

        peerinterface_content = QWidget()
        peerinterface_form = QFormLayout(peerinterface_content)
        peerinterface_form.setContentsMargins(8, 8, 8, 8)
        peerinterface_form.setHorizontalSpacing(12)
        peerinterface_form.setVerticalSpacing(8)
        peerinterface_form.addRow(QLabel("Segment:"), self.peerinterface_segment_input)
        peerinterface_form.addRow(QLabel("Bind IPv4:"), self.peerinterface_bind_ip_input)
        peerinterface_form.addRow(QLabel("Discovery group:"), self.peerinterface_discovery_group_input)
        peerinterface_form.addRow(QLabel("Discovery port:"), self.peerinterface_discovery_port_input)
        peerinterface_form.addRow(QLabel("Frame/ACK port:"), self.peerinterface_data_port_input)
        peerinterface_form.addRow(QLabel("Shared secret:"), self.peerinterface_shared_secret_input)
        peerinterface_form.addRow(self.peerinterface_require_auth_checkbox)
        peerinterface_help = QLabel(
            "PeerInterface creates a UDP P2P frame network with discovery, retries, "
            "deduplication, and ACKs. It does not start or require Hyper-V. When OS NAT is enabled, "
            "the selected discovery and frame ports are also published through NetNat and Windows Firewall."
        )
        peerinterface_help.setWordWrap(True)
        peerinterface_form.addRow(peerinterface_help)

        core_managers_content = QWidget()
        core_managers_grid = QGridLayout(core_managers_content)
        core_managers_grid.setContentsMargins(8, 8, 8, 8)
        core_managers_grid.setHorizontalSpacing(12)
        core_managers_grid.setVerticalSpacing(8)
        core_managers_grid.setColumnStretch(1, 1)
        core_managers_grid.setColumnStretch(3, 1)
        core_managers_grid.addWidget(
            self.core_firewall_checkbox,
            0,
            0,
        )
        core_managers_grid.addWidget(
            self.core_packet_analyzer_checkbox,
            0,
            1,
        )
        core_managers_grid.addWidget(
            self.core_packet_catcher_checkbox,
            0,
            2,
        )
        core_managers_grid.addWidget(
            self.core_handshake_checkbox,
            0,
            3,
        )
        core_managers_grid.addWidget(
            self.core_syn_scanner_checkbox,
            1,
            0,
        )
        core_managers_grid.addWidget(
            self.core_igmp_checkbox,
            1,
            1,
        )
        core_managers_grid.addWidget(
            self.core_mdns_checkbox,
            1,
            2,
        )
        core_managers_grid.addWidget(
            QLabel("Half-open timeout:"),
            2,
            0,
        )
        core_managers_grid.addWidget(
            self.handshake_half_open_timeout_input,
            2,
            1,
        )
        core_managers_grid.addWidget(
            QLabel("Established timeout:"),
            2,
            2,
        )
        core_managers_grid.addWidget(
            self.handshake_established_timeout_input,
            2,
            3,
        )
        core_managers_grid.addWidget(
            QLabel("Rate threshold:"),
            3,
            0,
        )
        core_managers_grid.addWidget(
            self.handshake_rate_threshold_input,
            3,
            1,
        )
        core_managers_grid.addWidget(
            QLabel("Rate period:"),
            3,
            2,
        )
        core_managers_grid.addWidget(
            self.handshake_rate_period_input,
            3,
            3,
        )
        core_managers_grid.addWidget(
            QLabel("Ban duration:"),
            4,
            0,
        )
        core_managers_grid.addWidget(
            self.handshake_ban_duration_input,
            4,
            1,
        )
        core_managers_grid.addWidget(
            QLabel("SYN scan interval:"),
            4,
            2,
        )
        core_managers_grid.addWidget(
            self.syn_scan_interval_input,
            4,
            3,
        )
        core_managers_grid.addWidget(
            self.handshake_log_tcp_checkbox,
            5,
            0,
        )
        core_managers_grid.addWidget(
            self.handshake_log_non_tls_checkbox,
            5,
            1,
        )
        core_managers_grid.addWidget(
            self.handshake_log_tls_records_checkbox,
            5,
            2,
        )
        core_managers_grid.addWidget(
            self.handshake_log_app_data_checkbox,
            5,
            3,
        )
        core_managers_grid.addWidget(
            self.handshake_log_tls13_keys_checkbox,
            6,
            0,
            1,
            2,
        )
        core_managers_grid.addWidget(
            QLabel("Packet catch TCP rate:"),
            7,
            0,
        )
        core_managers_grid.addWidget(
            self.packet_catcher_tcp_rate_input,
            7,
            1,
        )
        core_managers_grid.addWidget(
            QLabel("UDP rate:"),
            7,
            2,
        )
        core_managers_grid.addWidget(
            self.packet_catcher_udp_rate_input,
            7,
            3,
        )
        core_managers_grid.addWidget(
            QLabel("Default catch rate:"),
            8,
            0,
        )
        core_managers_grid.addWidget(
            self.packet_catcher_default_rate_input,
            8,
            1,
        )

        transport_content = QWidget()
        transport_layout = QVBoxLayout(transport_content)
        transport_layout.setContentsMargins(8, 8, 8, 8)
        transport_layout.setSpacing(8)

        transport_tuning_box = QGroupBox(
            "Transport Pipeline and Tuning"
        )
        transport_tuning_grid = QGridLayout(transport_tuning_box)
        transport_tuning_grid.setColumnStretch(1, 1)
        transport_tuning_grid.setColumnStretch(3, 1)
        transport_tuning_grid.addWidget(
            self.transport_enabled_checkbox,
            0,
            0,
            1,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_parallel_analysis_checkbox,
            0,
            2,
            1,
            2,
        )
        transport_tuning_grid.addWidget(
            QLabel("Stratum ports:"),
            1,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_stratum_ports_input,
            1,
            1,
            1,
            3,
        )
        transport_tuning_grid.addWidget(
            QLabel("Monero ports:"),
            2,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_monero_ports_input,
            2,
            1,
            1,
            3,
        )
        transport_tuning_grid.addWidget(
            QLabel("VoIP start:"),
            3,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_voip_start_input,
            3,
            1,
        )
        transport_tuning_grid.addWidget(
            QLabel("VoIP end:"),
            3,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_voip_end_input,
            3,
            3,
        )
        transport_tuning_grid.addWidget(
            QLabel("Inspection logs/sec:"),
            4,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_inspection_rps_input,
            4,
            1,
        )
        transport_tuning_grid.addWidget(
            QLabel("Inspection burst:"),
            4,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_inspection_burst_input,
            4,
            3,
        )
        transport_tuning_grid.addWidget(
            QLabel("Inspection cooldown:"),
            5,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_inspection_cooldown_input,
            5,
            1,
        )
        transport_tuning_grid.addWidget(
            QLabel("Stratum logs/sec:"),
            5,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_stratum_rps_input,
            5,
            3,
        )
        transport_tuning_grid.addWidget(
            QLabel("Stratum burst:"),
            6,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_stratum_burst_input,
            6,
            1,
        )
        transport_tuning_grid.addWidget(
            QLabel("Stratum cooldown:"),
            6,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_stratum_cooldown_input,
            6,
            3,
        )
        transport_tuning_grid.addWidget(
            QLabel("Monero logs/sec:"),
            7,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_monero_rps_input,
            7,
            1,
        )
        transport_tuning_grid.addWidget(
            QLabel("Monero burst:"),
            7,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_monero_burst_input,
            7,
            3,
        )
        transport_tuning_grid.addWidget(
            QLabel("Monero cooldown:"),
            8,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_monero_cooldown_input,
            8,
            1,
        )
        transport_tuning_grid.addWidget(
            QLabel("DNS pending TTL:"),
            8,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_dns_pending_ttl_input,
            8,
            3,
        )
        transport_tuning_grid.addWidget(
            QLabel("DNS GC interval:"),
            9,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_dns_gc_interval_input,
            9,
            1,
        )
        transport_tuning_grid.addWidget(
            self.transport_dns_rebind_alert_checkbox,
            9,
            2,
            1,
            2,
        )
        transport_tuning_grid.addWidget(
            QLabel("DHCP transaction TTL:"),
            10,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_dhcp_transaction_ttl_input,
            10,
            1,
        )
        transport_tuning_grid.addWidget(
            QLabel("Observed lease TTL:"),
            10,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_dhcp_lease_ttl_input,
            10,
            3,
        )
        transport_tuning_grid.addWidget(
            self.transport_https_logging_checkbox,
            11,
            0,
        )
        transport_tuning_grid.addWidget(
            self.transport_https_certificates_checkbox,
            11,
            1,
        )
        transport_tuning_grid.addWidget(
            self.transport_https_quic_crypto_checkbox,
            11,
            2,
            1,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_tls_learning_checkbox,
            12,
            0,
            1,
            2,
        )
        transport_tuning_grid.addWidget(
            self.transport_https_init_context_checkbox,
            12,
            2,
            1,
            2,
        )

        transport_protocol_box = QGroupBox(
            "Protocol Managers"
        )
        transport_protocol_grid = QGridLayout(
            transport_protocol_box
        )
        for protocol_index, checkbox in enumerate(
                self.transport_protocol_checkboxes.values()
        ):
            transport_protocol_grid.addWidget(
                checkbox,
                protocol_index // 4,
                protocol_index % 4,
            )

        transport_layout.addWidget(transport_tuning_box)
        transport_layout.addWidget(transport_protocol_box)

        codeoutput_content = QWidget()
        codeoutput_grid = QGridLayout(codeoutput_content)
        codeoutput_grid.setContentsMargins(8, 8, 8, 8)
        codeoutput_grid.setColumnStretch(1, 1)
        codeoutput_grid.setColumnStretch(3, 1)
        codeoutput_grid.addWidget(self.codeoutput_enabled_checkbox, 0, 0, 1, 2)
        codeoutput_grid.addWidget(self.codeoutput_auto_emit_checkbox, 0, 2, 1, 2)
        codeoutput_grid.addWidget(QLabel("Verbose:"), 1, 0)
        codeoutput_grid.addWidget(self.codeoutput_verbose_input, 1, 1)
        codeoutput_grid.addWidget(QLabel("Max generated chars:"), 1, 2)
        codeoutput_grid.addWidget(self.codeoutput_max_chars_input, 1, 3)
        codeoutput_grid.addWidget(QLabel("Emit interval:"), 2, 0)
        codeoutput_grid.addWidget(self.codeoutput_emit_interval_input, 2, 1)
        codeoutput_grid.addWidget(QLabel("Jitter:"), 2, 2)
        codeoutput_grid.addWidget(self.codeoutput_emit_jitter_input, 2, 3)
        codeoutput_grid.addWidget(QLabel("Minimum new packets:"), 3, 0)
        codeoutput_grid.addWidget(self.codeoutput_min_packets_input, 3, 1)
        codeoutput_grid.addWidget(self.codeoutput_active_probes_checkbox, 4, 0, 1, 2)
        codeoutput_grid.addWidget(self.codeoutput_allow_public_checkbox, 4, 2, 1, 2)
        codeoutput_grid.addWidget(QLabel("Probe timeout:"), 5, 0)
        codeoutput_grid.addWidget(self.codeoutput_probe_timeout_input, 5, 1)
        codeoutput_grid.addWidget(QLabel("Rate/min:"), 5, 2)
        codeoutput_grid.addWidget(self.codeoutput_probe_rate_input, 5, 3)
        codeoutput_grid.addWidget(QLabel("Target:"), 6, 0)
        codeoutput_grid.addWidget(self.codeoutput_target_input, 6, 1)
        codeoutput_grid.addWidget(self.codeoutput_protocol_dropdown, 6, 2)
        codeoutput_grid.addWidget(self.codeoutput_port_input, 6, 3)
        codeoutput_grid.addWidget(QLabel("Interface/source IP:"), 7, 0)
        codeoutput_grid.addWidget(self.codeoutput_iface_dropdown, 7, 1)
        codeoutput_grid.addWidget(QLabel("Payload:"), 7, 2)
        codeoutput_grid.addWidget(self.codeoutput_payload_input, 7, 3)
        codeoutput_grid.addWidget(QLabel("Concurrency:"), 8, 0)
        codeoutput_grid.addWidget(self.codeoutput_probe_concurrency_input, 8, 1)
        codeoutput_grid.addWidget(self.codeoutput_probe_button, 8, 2, 1, 2)
        codeoutput_grid.addWidget(self.codeoutput_interface_checkbox, 9, 0, 1, 4)
        codeoutput_grid.addWidget(QLabel("Hyper-V switch name:"), 10, 0)
        codeoutput_grid.addWidget(self.codeoutput_switch_name_input, 10, 1)
        codeoutput_grid.addWidget(QLabel("Windows adapter name:"), 10, 2)
        codeoutput_grid.addWidget(self.codeoutput_adapter_name_input, 10, 3)
        codeoutput_grid.addWidget(QLabel("CodeOutput IPv4:"), 11, 0)
        codeoutput_grid.addWidget(self.codeoutput_interface_ip_input, 11, 1)
        codeoutput_grid.addWidget(QLabel("Prefix length:"), 11, 2)
        codeoutput_grid.addWidget(self.codeoutput_interface_prefix_input, 11, 3)
        codeoutput_grid.addWidget(self.codeoutput_remove_on_shutdown_checkbox, 12, 0, 1, 2)
        codeoutput_grid.addWidget(self.codeoutput_force_remove_checkbox, 12, 2, 1, 2)
        codeoutput_grid.addWidget(self.codeoutput_create_interface_button, 13, 0, 1, 2)
        codeoutput_grid.addWidget(self.codeoutput_remove_interface_button, 13, 2, 1, 2)

        comms_content = QWidget()
        comms_form = QFormLayout(comms_content)
        comms_form.setContentsMargins(8, 8, 8, 8)
        comms_form.addRow(self.peer_to_peer_checkbox, self.nat_os_checkbox)
        comms_form.addRow(QLabel("IPC Host:"), self.ipc_host_input)

        stratum_content = QWidget()
        stratum_grid = QGridLayout(stratum_content)
        stratum_grid.setContentsMargins(8, 8, 8, 8)
        stratum_grid.setHorizontalSpacing(12)
        stratum_grid.setVerticalSpacing(8)
        stratum_grid.setColumnStretch(1, 1)
        stratum_grid.setColumnStretch(3, 1)

        stratum_grid.addWidget(self.stratum_comm_checkbox, 0, 0, 1, 2)
        stratum_grid.addWidget(QLabel("Connection:"), 0, 2)
        stratum_grid.addWidget(self.stratum_mode_dropdown, 0, 3)

        stratum_grid.addWidget(QLabel("Pool host:"), 1, 0)
        stratum_grid.addWidget(self.stratum_pool_host_input, 1, 1)
        stratum_grid.addWidget(QLabel("Pool port:"), 1, 2)
        stratum_grid.addWidget(self.stratum_pool_port_input, 1, 3)

        stratum_grid.addWidget(QLabel("Wallet / login:"), 2, 0)
        stratum_grid.addWidget(self.stratum_wallet_input, 2, 1, 1, 3)

        stratum_grid.addWidget(QLabel("Server password:"), 3, 0)
        stratum_grid.addWidget(self.stratum_password_input, 3, 1)
        stratum_grid.addWidget(QLabel("Worker:"), 3, 2)
        stratum_grid.addWidget(self.stratum_worker_input, 3, 3)

        stratum_grid.addWidget(QLabel("TLS:"), 4, 0)
        stratum_grid.addWidget(self.stratum_tls_dropdown, 4, 1)
        stratum_grid.addWidget(QLabel("TLS host / SNI:"), 4, 2)
        stratum_grid.addWidget(self.stratum_sni_input, 4, 3)

        stratum_grid.addWidget(QLabel("User agent:"), 5, 0)
        stratum_grid.addWidget(self.stratum_user_agent_input, 5, 1, 1, 3)

        stratum_grid.addWidget(self.stratum_proxy_checkbox, 6, 0)
        stratum_grid.addWidget(self.stratum_proxy_host_input, 6, 1)
        stratum_grid.addWidget(QLabel("Proxy port:"), 6, 2)
        stratum_grid.addWidget(self.stratum_proxy_port_input, 6, 3)

        stratum_grid.addWidget(QLabel("Daemon RPC:"), 7, 0)
        stratum_grid.addWidget(self.stratum_daemon_url_input, 7, 1, 1, 3)
        stratum_grid.addWidget(QLabel("Daemon ZMQ:"), 8, 0)
        stratum_grid.addWidget(self.stratum_zmq_address_input, 8, 1, 1, 3)

        dhcp_content = QWidget()
        dhcp_layout = QVBoxLayout(dhcp_content)
        dhcp_layout.setContentsMargins(8, 8, 8, 8)
        dhcp_layout.setSpacing(8)

        lease_mode_box = QGroupBox("DHCP Client Lease Modes")
        lease_mode_grid = QGridLayout(lease_mode_box)
        lease_mode_grid.addWidget(self.dhcp_out_checkbox, 0, 0)
        lease_mode_grid.addWidget(QLabel("DHCP OUT mode:"), 0, 1)
        lease_mode_grid.addWidget(self.dhcp_out_mode_dropdown, 0, 2)
        lease_mode_grid.addWidget(self.dhcp_in_checkbox, 1, 0)
        lease_mode_grid.addWidget(QLabel("DHCP IN mode:"), 1, 1)
        lease_mode_grid.addWidget(self.dhcp_in_mode_dropdown, 1, 2)
        direct_help = QLabel(
            "Direct Lease Only accepts the adapter lease and skips host-preserving/uplink orchestration."
        )
        direct_help.setWordWrap(True)
        lease_mode_grid.addWidget(direct_help, 2, 0, 1, 3)

        lan_dhcp_box = QGroupBox("LAN DHCP Server")
        lan_dhcp_grid = QGridLayout(lan_dhcp_box)
        lan_dhcp_grid.setColumnStretch(1, 1)
        lan_dhcp_grid.setColumnStretch(3, 1)
        lan_dhcp_grid.addWidget(self.dhcp_server_checkbox, 0, 0, 1, 2)
        lan_dhcp_grid.addWidget(self.dhcp_authoritative_checkbox, 0, 2)
        lan_dhcp_grid.addWidget(self.dhcp_enforce_subnet_checkbox, 0, 3)
        lan_dhcp_grid.addWidget(QLabel("Pool start:"), 1, 0)
        lan_dhcp_grid.addWidget(self.dhcp_pool_start_input, 1, 1)
        lan_dhcp_grid.addWidget(QLabel("Pool end:"), 1, 2)
        lan_dhcp_grid.addWidget(self.dhcp_pool_end_input, 1, 3)
        lan_dhcp_grid.addWidget(QLabel("DNS:"), 2, 0)
        lan_dhcp_grid.addWidget(self.dhcp_dns_input, 2, 1)
        lan_dhcp_grid.addWidget(QLabel("Domain:"), 2, 2)
        lan_dhcp_grid.addWidget(self.dhcp_domain_input, 2, 3)
        lan_dhcp_grid.addWidget(QLabel("Lease seconds:"), 3, 0)
        lan_dhcp_grid.addWidget(self.dhcp_lease_seconds_input, 3, 1)
        lan_dhcp_grid.addWidget(QLabel("Max leases:"), 3, 2)
        lan_dhcp_grid.addWidget(self.dhcp_max_leases_input, 3, 3)
        lan_dhcp_grid.addWidget(
            self.dhcp_allow_out_of_pool_checkbox,
            4,
            0,
            1,
            2,
        )
        lan_dhcp_grid.addWidget(QLabel("Rogue policy:"), 4, 2)
        lan_dhcp_grid.addWidget(self.dhcp_rogue_policy_dropdown, 4, 3)
        lan_dhcp_grid.addWidget(QLabel("DHCP relay:"), 5, 0)
        lan_dhcp_grid.addWidget(self.dhcp_relay_input, 5, 1)
        lan_dhcp_grid.addWidget(QLabel("DHCPv6 prefix:"), 5, 2)
        lan_dhcp_grid.addWidget(self.dhcp6_prefix_input, 5, 3)
        lan_dhcp_grid.addWidget(QLabel("DHCPv6 relay:"), 6, 0)
        lan_dhcp_grid.addWidget(self.dhcp6_relay_input, 6, 1)
        lan_dhcp_grid.addWidget(QLabel("IPv6 DNS:"), 6, 2)
        lan_dhcp_grid.addWidget(self.dhcp_dns_v6_input, 6, 3)
        lan_dhcp_grid.addWidget(QLabel("Search domains:"), 7, 0)
        lan_dhcp_grid.addWidget(
            self.dhcp_search_domains_input,
            7,
            1,
            1,
            3,
        )

        interface_dhcp_box = QGroupBox("DHCP Interface Assignment")
        interface_dhcp_grid = QGridLayout(interface_dhcp_box)
        interface_dhcp_grid.setColumnStretch(1, 1)
        interface_dhcp_grid.addWidget(self.dhcp_interface_refresh_button, 0, 0, 1, 2)
        interface_dhcp_grid.addWidget(QLabel("LAN DHCP interfaces:"), 1, 0)
        interface_dhcp_grid.addWidget(self.dhcp_lan_interfaces_list, 1, 1)
        interface_dhcp_grid.addWidget(QLabel("WAN DHCP interfaces:"), 2, 0)
        interface_dhcp_grid.addWidget(self.dhcp_wan_interfaces_list, 2, 1)
        interface_dhcp_grid.addWidget(QLabel("Additional LAN aliases:"), 3, 0)
        interface_dhcp_grid.addWidget(self.dhcp_additional_ifaces_input, 3, 1)
        interface_dhcp_grid.addWidget(QLabel("Independent scopes (JSON):"), 4, 0)
        interface_dhcp_grid.addWidget(self.dhcp_interface_profiles_input, 4, 1)
        interface_help = QLabel(
            "Shared aliases reuse the LAN pool. Independent scopes create one DHCP "
            "server per virtual interface. WAN remains denied unless WAN DHCP is "
            "explicitly enabled."
        )
        interface_help.setWordWrap(True)
        interface_dhcp_grid.addWidget(interface_help, 5, 0, 1, 2)

        wan_dhcp_box = QGroupBox("WAN DHCP Server (Advanced)")
        wan_dhcp_grid = QGridLayout(wan_dhcp_box)
        wan_dhcp_grid.setColumnStretch(1, 1)
        wan_dhcp_grid.setColumnStretch(3, 1)
        wan_dhcp_grid.addWidget(
            self.serve_dhcp_on_wan_checkbox,
            0,
            0,
            1,
            2,
        )
        wan_dhcp_grid.addWidget(
            self.wan_dhcp_authoritative_checkbox,
            0,
            2,
        )
        wan_dhcp_grid.addWidget(
            self.wan_dhcp_enforce_subnet_checkbox,
            0,
            3,
        )
        wan_dhcp_grid.addWidget(QLabel("WAN pool start:"), 1, 0)
        wan_dhcp_grid.addWidget(self.wan_dhcp_pool_start_input, 1, 1)
        wan_dhcp_grid.addWidget(QLabel("WAN pool end:"), 1, 2)
        wan_dhcp_grid.addWidget(self.wan_dhcp_pool_end_input, 1, 3)
        wan_dhcp_grid.addWidget(QLabel("WAN DNS:"), 2, 0)
        wan_dhcp_grid.addWidget(self.wan_dhcp_dns_input, 2, 1)
        wan_dhcp_grid.addWidget(QLabel("WAN domain:"), 2, 2)
        wan_dhcp_grid.addWidget(self.wan_dhcp_domain_input, 2, 3)
        wan_dhcp_grid.addWidget(QLabel("Lease seconds:"), 3, 0)
        wan_dhcp_grid.addWidget(
            self.wan_dhcp_lease_seconds_input,
            3,
            1,
        )
        wan_dhcp_grid.addWidget(QLabel("Max leases:"), 3, 2)
        wan_dhcp_grid.addWidget(self.wan_dhcp_max_leases_input, 3, 3)
        wan_dhcp_grid.addWidget(
            self.wan_dhcp_allow_out_of_pool_checkbox,
            4,
            0,
            1,
            2,
        )
        wan_dhcp_grid.addWidget(QLabel("Rogue policy:"), 4, 2)
        wan_dhcp_grid.addWidget(
            self.wan_dhcp_rogue_policy_dropdown,
            4,
            3,
        )
        wan_dhcp_grid.addWidget(QLabel("WAN DHCP relay:"), 5, 0)
        wan_dhcp_grid.addWidget(
            self.wan_dhcp_relay_input,
            5,
            1,
            1,
            3,
        )

        dhcp_layout.addWidget(lease_mode_box)
        dhcp_layout.addWidget(lan_dhcp_box)
        dhcp_layout.addWidget(interface_dhcp_box)
        dhcp_layout.addWidget(wan_dhcp_box)

        gateway_content = QWidget()
        gateway_grid = QGridLayout(gateway_content)
        gateway_grid.setContentsMargins(8, 8, 8, 8)
        gateway_grid.setColumnStretch(1, 1)
        gateway_grid.setColumnStretch(3, 1)
        gateway_grid.addWidget(self.use_gateway_checkbox, 0, 0, 1, 2)
        gateway_grid.addWidget(self.gateway_repair_checkbox, 0, 2)
        gateway_grid.addWidget(self.gateway_pin_arp_checkbox, 0, 3)
        gateway_grid.addWidget(QLabel("Health interval:"), 1, 0)
        gateway_grid.addWidget(self.gateway_health_interval_input, 1, 1)
        gateway_grid.addWidget(QLabel("Probe budget:"), 1, 2)
        gateway_grid.addWidget(self.gateway_probe_budget_input, 1, 3)
        gateway_grid.addWidget(self.gateway_dns64_checkbox, 2, 0)
        gateway_grid.addWidget(self.gateway_dns64_prefix_input, 2, 1)
        gateway_grid.addWidget(QLabel("Upstream DNS:"), 2, 2)
        gateway_grid.addWidget(self.gateway_upstream_dns_input, 2, 3)

        lan_content = QWidget()
        lan_grid = QGridLayout(lan_content)
        lan_grid.setContentsMargins(8, 8, 8, 8)
        lan_grid.setColumnStretch(1, 1)
        lan_grid.setColumnStretch(3, 1)
        lan_grid.addWidget(self.use_lan_checkbox, 0, 0, 1, 2)
        lan_grid.addWidget(self.lan_create_bridge_checkbox, 0, 2)
        lan_grid.addWidget(self.lan_handle_icmp_checkbox, 0, 3)
        lan_grid.addWidget(QLabel("Bridge name:"), 1, 0)
        lan_grid.addWidget(self.lan_bridge_name_input, 1, 1)
        lan_grid.addWidget(QLabel("Health interval:"), 1, 2)
        lan_grid.addWidget(self.lan_health_interval_input, 1, 3)
        lan_grid.addWidget(
            self.lan_transport_dhcp_client_checkbox,
            2,
            0,
            1,
            4,
        )

        uplink_content = QWidget()
        uplink_grid = QGridLayout(uplink_content)
        uplink_grid.setContentsMargins(8, 8, 8, 8)
        uplink_grid.setColumnStretch(1, 1)
        uplink_grid.setColumnStretch(3, 1)
        uplink_grid.addWidget(self.use_uplink_checkbox, 0, 0, 1, 2)
        uplink_grid.addWidget(
            self.uplink_allow_failover_checkbox,
            0,
            2,
        )
        uplink_grid.addWidget(
            self.uplink_preserve_wifi_checkbox,
            0,
            3,
        )
        uplink_grid.addWidget(QLabel("Health interval:"), 1, 0)
        uplink_grid.addWidget(self.uplink_health_interval_input, 1, 1)
        uplink_grid.addWidget(QLabel("Minimum score:"), 1, 2)
        uplink_grid.addWidget(self.uplink_min_score_input, 1, 3)
        uplink_grid.addWidget(QLabel("Preferred interfaces:"), 2, 0)
        uplink_grid.addWidget(
            self.uplink_preferred_ifaces_input,
            2,
            1,
            1,
            3,
        )

        python_server_content = QWidget()
        python_server_grid = QGridLayout(python_server_content)
        python_server_grid.setContentsMargins(8, 8, 8, 8)
        python_server_grid.setColumnStretch(1, 1)
        python_server_grid.setColumnStretch(3, 1)
        python_server_grid.addWidget(
            self.python_server_checkbox,
            0,
            0,
            1,
            2,
        )
        python_server_grid.addWidget(
            self.python_server_store_raw_checkbox,
            0,
            2,
            1,
            2,
        )
        python_server_grid.addWidget(QLabel("Host:"), 1, 0)
        python_server_grid.addWidget(self.python_server_host_input, 1, 1)
        python_server_grid.addWidget(QLabel("Port:"), 1, 2)
        python_server_grid.addWidget(self.python_server_port_input, 1, 3)
        python_server_grid.addWidget(QLabel("Dashboard title:"), 2, 0)
        python_server_grid.addWidget(
            self.python_server_title_input,
            2,
            1,
            1,
            3,
        )
        python_server_grid.addWidget(QLabel("Max packets:"), 3, 0)
        python_server_grid.addWidget(
            self.python_server_max_packets_input,
            3,
            1,
        )
        python_server_grid.addWidget(QLabel("Max logs:"), 3, 2)
        python_server_grid.addWidget(
            self.python_server_max_logs_input,
            3,
            3,
        )
        python_server_grid.addWidget(QLabel("Max events:"), 4, 0)
        python_server_grid.addWidget(
            self.python_server_max_events_input,
            4,
            1,
        )
        python_server_grid.addWidget(QLabel("Max raw bytes:"), 4, 2)
        python_server_grid.addWidget(
            self.python_server_max_raw_bytes_input,
            4,
            3,
        )

        blocknet_content = QWidget()
        blocknet_form = QFormLayout(blocknet_content)
        blocknet_form.setContentsMargins(8, 8, 8, 8)
        blocknet_form.addRow(self.blocknet_checkbox)
        blocknet_form.addRow(QLabel("Relay:"), self.blocknet_relay_input)
        blocknet_form.addRow(QLabel("Token:"), self.blocknet_token_input)

        scrape_content = QWidget()
        scrape_form = QFormLayout(scrape_content)
        scrape_form.setContentsMargins(8, 8, 8, 8)
        scrape_form.addRow(self.use_scrapewebsite_checkbox)
        scrape_form.addRow(QLabel("Endpoint:"), self.scrapewebsite_endpoint_input)

        wireless_content = QWidget()
        wireless_form = QFormLayout(wireless_content)
        wireless_form.setContentsMargins(8, 8, 8, 8)
        wireless_form.setHorizontalSpacing(12)
        wireless_form.setVerticalSpacing(8)

        wireless_form.addRow(self.use_wifi_host_checkbox)
        wireless_form.addRow(
            QLabel("SSID:"),
            self.wifi_ssid_input,
        )
        wireless_form.addRow(
            QLabel("Password:"),
            self.wifi_password_input,
        )
        wireless_form.addRow(
            QLabel("Router IP:"),
            self.wifi_router_ip_input,
        )
        wireless_form.addRow(
            QLabel("Prefix length:"),
            self.wifi_prefix_length_input,
        )
        wireless_form.addRow(self.wifi_auto_restart_checkbox)
        wireless_form.addRow(
            QLabel("Start timeout:"),
            self.wifi_start_timeout_input,
        )
        wireless_form.addRow(
            QLabel("Adapter timeout:"),
            self.wifi_adapter_timeout_input,
        )

        wireless_exe_label = QLabel(
            "Executable: tools/PythonRouterWirelessHost.exe"
        )
        wireless_exe_label.setWordWrap(True)
        wireless_exe_label.setToolTip(
            "WifiManager searches the application tools directory automatically."
        )
        wireless_form.addRow(wireless_exe_label)

        settings_layout.addWidget(
            self._make_settings_section(
                "Network Presets & Addresses",
                addressing_content,
                expanded=True,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Routing",
                routing_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "PeerInterface P2P",
                peerinterface_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Core Packet Managers",
                core_managers_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Transport Managers",
                transport_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "CodeOutput Interface",
                codeoutput_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "DHCP Server",
                dhcp_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Gateway Manager",
                gateway_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "LAN Manager",
                lan_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Uplink Manager",
                uplink_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Python Server",
                python_server_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Communications",
                comms_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Stratum Connection",
                stratum_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "BlockNet",
                blocknet_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "ScrapeWebsite",
                scrape_content,
            )
        )
        settings_layout.addWidget(
            self._make_settings_section(
                "Wireless Access Point",
                wireless_content,
            )
        )

        self.settings_scroll = QScrollArea()
        self.settings_scroll.setWidgetResizable(True)
        self.settings_scroll.setWidget(self.settings_container)
        self.settings_scroll.setMaximumHeight(430)
        self.settings_scroll.setVisible(False)
        layout.addWidget(self.settings_scroll)

        pane_row = QHBoxLayout()
        pane_row.addWidget(QLabel("Pane:"))
        pane_row.addWidget(self.add_pane_input)
        pane_row.addWidget(self.add_pane_button)
        pane_row.addWidget(self.remove_pane_button)
        pane_row.addStretch(1)
        pane_row.addWidget(QLabel("Presets:"))
        pane_row.addWidget(self.preset_dropdown)

        layout.addLayout(pane_row)
        layout.addWidget(self.console_tabs)

    def _make_settings_section(
        self,
        title: str,
        content: QWidget,
        expanded: bool = False,
    ) -> QWidget:
        wrapper = QWidget()
        wrapper_layout = QVBoxLayout(wrapper)
        wrapper_layout.setContentsMargins(0, 0, 0, 0)
        wrapper_layout.setSpacing(0)

        button = QPushButton(f"▶ {title}")
        button.setCheckable(True)
        button.setChecked(False)
        button.setToolTip(f"Show or hide {title} settings.")

        content.setVisible(False)
        wrapper_layout.addWidget(button)
        wrapper_layout.addWidget(content)

        self._settings_sections[title] = (button, content)
        button.toggled.connect(
            lambda checked, section_title=title:
            self._set_settings_section_expanded(
                section_title,
                checked,
            )
        )

        if expanded:
            button.setChecked(True)

        return wrapper

    def _set_settings_section_expanded(
        self,
        title: str,
        expanded: bool,
    ):
        entry = self._settings_sections.get(title)
        if entry is None:
            return

        button, content = entry

        if expanded:
            for other_title, (other_button, other_content) in (
                self._settings_sections.items()
            ):
                if other_title == title:
                    continue

                if other_button.isChecked():
                    other_button.blockSignals(True)
                    other_button.setChecked(False)
                    other_button.blockSignals(False)

                other_button.setText(f"▶ {other_title}")
                other_content.setVisible(False)

            self._active_settings_section = title
        elif self._active_settings_section == title:
            self._active_settings_section = None

        button.setText(
            f"{'▼' if expanded else '▶'} {title}"
        )
        content.setVisible(expanded)

    def _on_settings_toggled(self, expanded: bool):
        self.settings_toggle_button.setText(
            f"⚙ Settings {'▼' if expanded else '▶'}"
        )
        self.settings_scroll.setVisible(expanded)

    def _detect_observable_lan_ipv4(self):
        """
        Return the IPv4/netmask Windows would currently use for ordinary
        outbound traffic. No configuration is changed.
        """
        import ipaddress
        import os
        import re
        import socket
        import subprocess

        detected_ip = ""
        detected_netmask = ""

        probe = None
        try:
            probe = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            probe.connect(("8.8.8.8", 80))
            detected_ip = str(probe.getsockname()[0] or "").strip()
        except Exception:
            detected_ip = ""
        finally:
            try:
                if probe is not None:
                    probe.close()
            except Exception:
                pass

        # On Windows, confirm the observable address and subnet mask against
        # ipconfig. The UDP route probe chooses the active path; ipconfig
        # supplies the address data the user sees in Windows.
        if os.name == "nt":
            try:
                result = subprocess.run(
                    ["ipconfig"],
                    capture_output=True,
                    text=True,
                    timeout=5.0,
                    creationflags=getattr(
                        subprocess,
                        "CREATE_NO_WINDOW",
                        0,
                    ),
                )
                ipconfig_text = result.stdout or ""
                address_matches = list(
                    re.finditer(
                        r"IPv4[^:\r\n]*:\s*"
                        r"(\d{1,3}(?:\.\d{1,3}){3})"
                        r"(?:\(Preferred\))?"
                        r"(?:(?!IPv4)[\s\S])*?"
                        r"Subnet Mask[^:\r\n]*:\s*"
                        r"(\d{1,3}(?:\.\d{1,3}){3})",
                        ipconfig_text,
                        flags=re.IGNORECASE,
                    )
                )
                ipconfig_addresses = []
                for match in address_matches:
                    candidate_ip = match.group(1)
                    candidate_mask = match.group(2)
                    try:
                        parsed_candidate = ipaddress.IPv4Address(
                            candidate_ip
                        )
                        ipaddress.IPv4Network(
                            f"{candidate_ip}/{candidate_mask}",
                            strict=False,
                        )
                    except Exception:
                        continue
                    if (
                            parsed_candidate.is_loopback
                            or parsed_candidate.is_link_local
                    ):
                        continue
                    ipconfig_addresses.append(
                        (candidate_ip, candidate_mask)
                    )

                if detected_ip:
                    for candidate_ip, candidate_mask in (
                            ipconfig_addresses
                    ):
                        if candidate_ip == detected_ip:
                            detected_netmask = candidate_mask
                            break
                elif ipconfig_addresses:
                    detected_ip, detected_netmask = (
                        ipconfig_addresses[0]
                    )
            except Exception:
                pass

        if detected_ip:
            try:
                import psutil

                for addresses in psutil.net_if_addrs().values():
                    for address in addresses:
                        if (
                            address.family == socket.AF_INET
                            and str(address.address) == detected_ip
                        ):
                            detected_netmask = str(
                                address.netmask or ""
                            ).strip()
                            break
                    if detected_netmask:
                        break
            except Exception:
                pass

        if not detected_ip:
            try:
                for candidate in socket.gethostbyname_ex(
                    socket.gethostname()
                )[2]:
                    parsed = ipaddress.ip_address(candidate)
                    if (
                        parsed.version == 4
                        and not parsed.is_loopback
                        and not parsed.is_link_local
                    ):
                        detected_ip = str(parsed)
                        break
            except Exception:
                pass

        if not detected_netmask:
            detected_netmask = "255.255.255.0"

        return detected_ip, detected_netmask

    def _suggest_pool_for_network(
        self,
        router_ip: str,
        netmask: str,
    ):
        import ipaddress

        try:
            router_address = ipaddress.IPv4Address(
                str(router_ip).strip()
            )
            network = ipaddress.IPv4Network(
                f"{router_address}/{str(netmask).strip()}",
                strict=False,
            )
        except Exception:
            return "", ""

        first_host = int(network.network_address) + 1
        last_host = int(network.broadcast_address) - 1
        if last_host < first_host:
            return "", ""

        router_value = int(router_address)
        above_start = max(first_host, router_value + 1)
        above_end = min(last_host, above_start + 119)

        if above_end - above_start >= 7:
            return (
                str(ipaddress.IPv4Address(above_start)),
                str(ipaddress.IPv4Address(above_end)),
            )

        below_end = min(last_host, router_value - 1)
        below_start = max(first_host, below_end - 119)
        if below_end >= below_start:
            return (
                str(ipaddress.IPv4Address(below_start)),
                str(ipaddress.IPv4Address(below_end)),
            )

        return "", ""

    def _autofill_router_wan_ip(self, log_result: bool = True):
        detected_ip, detected_netmask = (
            self._detect_observable_lan_ipv4()
        )

        if detected_ip:
            self.router_ip_out_input.setText(detected_ip)
            self.router_netmask_out_input.setText(detected_netmask)

            pool_start, pool_end = self._suggest_pool_for_network(
                detected_ip,
                detected_netmask,
            )
            if pool_start and pool_end:
                self.wan_dhcp_pool_start_input.setText(pool_start)
                self.wan_dhcp_pool_end_input.setText(pool_end)

            if log_result:
                self.router_logger.log_message(
                    f"[RouterTab][Preset] 🌐 Detected WAN/LAN address "
                    f"{detected_ip}/{detected_netmask}."
                )
            return True

        if log_result:
            self.router_logger.log_message(
                "[RouterTab][Preset] ⚠️ Could not detect an active "
                "LAN/uplink IPv4 address."
            )
        return False

    def _apply_network_preset(self):
        preset_name = self.network_preset_dropdown.currentText()

        if preset_name == "Custom":
            self.router_logger.log_message(
                "[RouterTab][Preset] ✏️ Custom selected; "
                "manual address and manager settings were preserved."
            )
            return

        # Keep WAN aligned with the address Windows currently exposes.
        self._autofill_router_wan_ip(log_result=False)

        if preset_name == "Detected LAN":
            wan_ip = self.router_ip_out_input.text().strip()
            wan_mask = self.router_netmask_out_input.text().strip()
            pool_start, pool_end = self._suggest_pool_for_network(
                wan_ip,
                wan_mask,
            )
            if pool_start and pool_end:
                self.wan_dhcp_pool_start_input.setText(pool_start)
                self.wan_dhcp_pool_end_input.setText(pool_end)
            if wan_ip:
                self.wan_dhcp_dns_input.setText(
                    f"{wan_ip}, 1.1.1.1, 8.8.8.8"
                )
                self.wan_dhcp_domain_input.setText(
                    "observed.lan"
                )

        elif preset_name == "Personal Network":
            self.router_ip_in_input.setText("192.168.160.1")
            self.router_netmask_in_input.setText("255.255.255.0")
            self.dhcp_pool_start_input.setText("192.168.160.100")
            self.dhcp_pool_end_input.setText("192.168.160.220")
            self.dhcp_dns_input.setText("")
            self.dhcp_domain_input.setText("home.arpa")
            self.dhcp_search_domains_input.setText("home.arpa")
            self.dhcp_lease_seconds_input.setText("86400")
            self.dhcp_max_leases_input.setText("121")
            self.wifi_router_ip_input.setText("192.168.160.1")
            self.wifi_prefix_length_input.setText("24")

        elif preset_name == "Personal 172 Network":
            self.router_ip_in_input.setText("172.16.10.1")
            self.router_netmask_in_input.setText("255.255.255.0")
            self.dhcp_pool_start_input.setText("172.16.10.100")
            self.dhcp_pool_end_input.setText("172.16.10.220")
            self.dhcp_dns_input.setText("")
            self.dhcp_domain_input.setText("home.arpa")
            self.dhcp_search_domains_input.setText("home.arpa")
            self.dhcp_lease_seconds_input.setText("86400")
            self.dhcp_max_leases_input.setText("121")
            self.wifi_router_ip_input.setText("172.16.10.1")
            self.wifi_prefix_length_input.setText("24")

        elif preset_name == "Ole Miss 172.24.56 Lab":
            self.router_ip_in_input.setText("172.24.56.1")
            self.router_netmask_in_input.setText("255.255.255.0")
            self.dhcp_pool_start_input.setText("172.24.56.100")
            self.dhcp_pool_end_input.setText("172.24.56.220")
            self.dhcp_dns_input.setText(
                "172.24.56.1, 1.1.1.1, 8.8.8.8"
            )
            self.dhcp_domain_input.setText("lab.olemiss")
            self.dhcp_search_domains_input.setText("lab.olemiss")
            self.dhcp_lease_seconds_input.setText("28800")
            self.dhcp_max_leases_input.setText("121")
            self.wifi_router_ip_input.setText("172.24.56.1")
            self.wifi_prefix_length_input.setText("24")
            self.router_logger.log_message(
                "[RouterTab][Preset] ⚠️ Ole Miss 172.24.56 is "
                "for an isolated lab/test segment only. WAN DHCP "
                "was not enabled."
            )

        elif preset_name == "Enterprise Network":
            self.router_ip_in_input.setText("172.31.0.1")
            self.router_netmask_in_input.setText("255.255.0.0")
            self.dhcp_pool_start_input.setText("172.31.10.10")
            self.dhcp_pool_end_input.setText("172.31.250.250")
            self.dhcp_dns_input.setText(
                "1.1.1.1, 8.8.8.8, 9.9.9.9"
            )
            self.dhcp_domain_input.setText("corp.internal")
            self.dhcp_search_domains_input.setText("corp.internal")
            self.dhcp_lease_seconds_input.setText("28800")
            self.dhcp_max_leases_input.setText("4096")
            self.wifi_router_ip_input.setText("172.31.0.1")
            self.wifi_prefix_length_input.setText("16")

        self.router_logger.log_message(
            f"[RouterTab][Preset] 🧩 Applied '{preset_name}' values. "
            "No manager or WAN DHCP toggle was enabled automatically."
        )

    def _connect_signals(self):
        self.settings_toggle_button.toggled.connect(
            self._on_settings_toggled
        )
        self.apply_network_preset_button.clicked.connect(
            self._apply_network_preset
        )
        self.detect_wan_ip_button.clicked.connect(
            lambda: self._autofill_router_wan_ip(True)
        )
        self.dhcp_interface_refresh_button.clicked.connect(
            self.refresh_network_interfaces
        )
        self.codeoutput_probe_button.clicked.connect(
            self._emit_codeoutput_probe
        )
        self.codeoutput_create_interface_button.clicked.connect(
            self._emit_codeoutput_interface_create
        )
        self.codeoutput_remove_interface_button.clicked.connect(
            self._emit_codeoutput_interface_remove
        )
        self.codeoutput_interface_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.codeoutput_active_probes_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.codeoutput_enabled_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.add_pane_button.clicked.connect(self._on_add_pane)
        self.remove_pane_button.clicked.connect(self._on_remove_pane)
        self.preset_dropdown.currentTextChanged.connect(self._on_preset_selected)
        self.use_static_checkbox.stateChanged.connect(self._sync_enable_states)
        self.dhcp_out_checkbox.stateChanged.connect(self._sync_enable_states)
        self.dhcp_in_checkbox.stateChanged.connect(self._sync_enable_states)
        self.dhcp_server_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.serve_dhcp_on_wan_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.use_gateway_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.use_lan_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.use_uplink_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.python_server_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.transport_enabled_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.core_handshake_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.core_syn_scanner_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.core_packet_catcher_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.blocknet_checkbox.stateChanged.connect(self._sync_enable_states)
        self.stratum_comm_checkbox.stateChanged.connect(self._sync_enable_states)
        self.stratum_mode_dropdown.currentTextChanged.connect(
            self._sync_enable_states
        )
        self.stratum_proxy_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.use_scrapewebsite_checkbox.stateChanged.connect(self._sync_enable_states)
        self.use_wifi_host_checkbox.stateChanged.connect(
            self._sync_enable_states
        )
        self.use_peerinterface_checkbox.stateChanged.connect(
            self._sync_enable_states
        )

    def _selected_interface_names(self, widget: QListWidget) -> List[str]:
        return [item.text() for item in widget.selectedItems() if item.text().strip()]

    def selected_lan_dhcp_interfaces(self) -> List[str]:
        return self._selected_interface_names(self.dhcp_lan_interfaces_list)

    def selected_wan_dhcp_interfaces(self) -> List[str]:
        return self._selected_interface_names(self.dhcp_wan_interfaces_list)

    @pyqtSlot()
    def refresh_network_interfaces(self):
        previous_lan = set(self.selected_lan_dhcp_interfaces()) if hasattr(self, "dhcp_lan_interfaces_list") else set()
        previous_wan = set(self.selected_wan_dhcp_interfaces()) if hasattr(self, "dhcp_wan_interfaces_list") else set()
        names = sorted(psutil.net_if_addrs().keys(), key=str.casefold)
        for widget in (self.dhcp_lan_interfaces_list, self.dhcp_wan_interfaces_list):
            widget.clear()
            widget.addItems(names)
        self.codeoutput_iface_dropdown.clear()
        self.codeoutput_iface_dropdown.addItem("")
        self.codeoutput_iface_dropdown.addItems(
            names + ["CodeOutput", "ProcessInterface", "PeerInterface", "HyperVManager"]
        )
        for index in range(self.dhcp_lan_interfaces_list.count()):
            item = self.dhcp_lan_interfaces_list.item(index)
            name = item.text()
            default_lan = any(token in name.casefold() for token in ("ethernet", "veth", "bridge", "lan"))
            item.setSelected(name in previous_lan or (not previous_lan and default_lan))
        for index in range(self.dhcp_wan_interfaces_list.count()):
            item = self.dhcp_wan_interfaces_list.item(index)
            name = item.text()
            default_wan = any(token in name.casefold() for token in ("wi-fi", "wifi", "wireless", "wan"))
            item.setSelected(name in previous_wan or (not previous_wan and default_wan))

    @pyqtSlot()
    def _emit_codeoutput_probe(self):
        protocol = self.codeoutput_protocol_dropdown.currentText().strip().lower()
        port = int(self.codeoutput_port_input.value())
        self.codeoutput_probe_requested.emit({
            "target": self.codeoutput_target_input.text().strip(),
            "protocol": protocol,
            "port": None if protocol == "icmp" else port,
            "payload": self.codeoutput_payload_input.text(),
            "timeout": float(self.codeoutput_probe_timeout_input.text().strip() or 3.0),
            "iface": self.codeoutput_iface_dropdown.currentText().strip(),
            "expect_response": True,
        })

    @pyqtSlot()
    def _emit_codeoutput_interface_create(self):
        self.codeoutput_interface_create_requested.emit({
            "switch_name": self.codeoutput_switch_name_input.text().strip() or "CodeOutput",
            "adapter_name": self.codeoutput_adapter_name_input.text().strip() or "CodeOutput",
            "ipv4": self.codeoutput_interface_ip_input.text().strip() or "172.30.253.1",
            "prefix_length": int(self.codeoutput_interface_prefix_input.value()),
        })

    @pyqtSlot()
    def _emit_codeoutput_interface_remove(self):
        self.codeoutput_interface_remove_requested.emit(
            self.codeoutput_force_remove_checkbox.isChecked()
        )

    def _sync_enable_states(self):
        use_static = self.use_static_checkbox.isChecked()

        self.dhcp_out_checkbox.setEnabled(not use_static)
        self.dhcp_in_checkbox.setEnabled(not use_static)
        self.dhcp_out_mode_dropdown.setEnabled(
            not use_static and self.dhcp_out_checkbox.isChecked()
        )
        self.dhcp_in_mode_dropdown.setEnabled(
            not use_static and self.dhcp_in_checkbox.isChecked()
        )

        self.router_ip_out_input.setEnabled(not self.dhcp_out_checkbox.isChecked())
        self.router_netmask_out_input.setEnabled(
            not self.dhcp_out_checkbox.isChecked()
        )
        self.router_ip_in_input.setEnabled(
            not self.dhcp_in_checkbox.isChecked()
        )
        self.router_netmask_in_input.setEnabled(
            not self.dhcp_in_checkbox.isChecked()
        )

        use_lan_dhcp = self.dhcp_server_checkbox.isChecked()
        for widget in (
            self.dhcp_pool_start_input,
            self.dhcp_pool_end_input,
            self.dhcp_dns_input,
            self.dhcp_domain_input,
            self.dhcp_lease_seconds_input,
            self.dhcp_max_leases_input,
            self.dhcp_authoritative_checkbox,
            self.dhcp_allow_out_of_pool_checkbox,
            self.dhcp_enforce_subnet_checkbox,
            self.dhcp_rogue_policy_dropdown,
            self.dhcp_relay_input,
            self.dhcp6_prefix_input,
            self.dhcp6_relay_input,
            self.dhcp_dns_v6_input,
            self.dhcp_search_domains_input,
            self.dhcp_additional_ifaces_input,
            self.dhcp_interface_profiles_input,
            self.dhcp_lan_interfaces_list,
            self.dhcp_interface_refresh_button,
        ):
            widget.setEnabled(use_lan_dhcp)

        use_wan_dhcp = self.serve_dhcp_on_wan_checkbox.isChecked()
        for widget in (
            self.wan_dhcp_pool_start_input,
            self.wan_dhcp_pool_end_input,
            self.wan_dhcp_dns_input,
            self.wan_dhcp_domain_input,
            self.wan_dhcp_lease_seconds_input,
            self.wan_dhcp_max_leases_input,
            self.wan_dhcp_authoritative_checkbox,
            self.wan_dhcp_allow_out_of_pool_checkbox,
            self.wan_dhcp_enforce_subnet_checkbox,
            self.wan_dhcp_rogue_policy_dropdown,
            self.wan_dhcp_relay_input,
            self.dhcp_wan_interfaces_list,
        ):
            widget.setEnabled(use_wan_dhcp)

        codeoutput_enabled = self.codeoutput_enabled_checkbox.isChecked()
        probe_enabled = codeoutput_enabled and self.codeoutput_active_probes_checkbox.isChecked()
        for widget in (
            self.codeoutput_auto_emit_checkbox,
            self.codeoutput_verbose_input,
            self.codeoutput_emit_interval_input,
            self.codeoutput_emit_jitter_input,
            self.codeoutput_min_packets_input,
            self.codeoutput_max_chars_input,
            self.codeoutput_active_probes_checkbox,
        ):
            widget.setEnabled(codeoutput_enabled)
        for widget in (
            self.codeoutput_allow_public_checkbox,
            self.codeoutput_probe_timeout_input,
            self.codeoutput_probe_rate_input,
            self.codeoutput_probe_concurrency_input,
            self.codeoutput_target_input,
            self.codeoutput_protocol_dropdown,
            self.codeoutput_port_input,
            self.codeoutput_payload_input,
            self.codeoutput_iface_dropdown,
            self.codeoutput_probe_button,
        ):
            widget.setEnabled(probe_enabled)

        codeoutput_interface_enabled = codeoutput_enabled and self.codeoutput_interface_checkbox.isChecked()
        self.codeoutput_interface_checkbox.setEnabled(codeoutput_enabled)
        self.codeoutput_create_interface_button.setEnabled(codeoutput_interface_enabled)
        self.codeoutput_remove_interface_button.setEnabled(codeoutput_enabled)
        for widget in (
            self.codeoutput_switch_name_input,
            self.codeoutput_adapter_name_input,
            self.codeoutput_interface_ip_input,
            self.codeoutput_interface_prefix_input,
            self.codeoutput_remove_on_shutdown_checkbox,
            self.codeoutput_force_remove_checkbox,
        ):
            widget.setEnabled(codeoutput_interface_enabled)

        peerinterface_enabled = self.use_peerinterface_checkbox.isChecked()
        for widget in (
            self.peerinterface_segment_input,
            self.peerinterface_bind_ip_input,
            self.peerinterface_discovery_group_input,
            self.peerinterface_discovery_port_input,
            self.peerinterface_data_port_input,
            self.peerinterface_shared_secret_input,
            self.peerinterface_require_auth_checkbox,
        ):
            widget.setEnabled(peerinterface_enabled)

        for widget in (
            self.gateway_health_interval_input,
            self.gateway_dns64_checkbox,
            self.gateway_dns64_prefix_input,
            self.gateway_upstream_dns_input,
            self.gateway_repair_checkbox,
            self.gateway_pin_arp_checkbox,
            self.gateway_probe_budget_input,
        ):
            widget.setEnabled(self.use_gateway_checkbox.isChecked())

        for widget in (
            self.lan_bridge_name_input,
            self.lan_create_bridge_checkbox,
            self.lan_health_interval_input,
            self.lan_handle_icmp_checkbox,
            self.lan_transport_dhcp_client_checkbox,
        ):
            widget.setEnabled(self.use_lan_checkbox.isChecked())

        for widget in (
            self.uplink_health_interval_input,
            self.uplink_preferred_ifaces_input,
            self.uplink_allow_failover_checkbox,
            self.uplink_preserve_wifi_checkbox,
            self.uplink_min_score_input,
        ):
            widget.setEnabled(self.use_uplink_checkbox.isChecked())

        for widget in (
            self.python_server_host_input,
            self.python_server_port_input,
            self.python_server_title_input,
            self.python_server_max_packets_input,
            self.python_server_max_logs_input,
            self.python_server_max_events_input,
            self.python_server_store_raw_checkbox,
            self.python_server_max_raw_bytes_input,
        ):
            widget.setEnabled(self.python_server_checkbox.isChecked())

        transport_enabled = (
            self.transport_enabled_checkbox.isChecked()
        )
        for widget in (
            self.transport_parallel_analysis_checkbox,
            self.transport_stratum_ports_input,
            self.transport_monero_ports_input,
            self.transport_voip_start_input,
            self.transport_voip_end_input,
            self.transport_inspection_rps_input,
            self.transport_inspection_burst_input,
            self.transport_inspection_cooldown_input,
            self.transport_stratum_rps_input,
            self.transport_stratum_burst_input,
            self.transport_stratum_cooldown_input,
            self.transport_monero_rps_input,
            self.transport_monero_burst_input,
            self.transport_monero_cooldown_input,
            self.transport_dns_pending_ttl_input,
            self.transport_dns_gc_interval_input,
            self.transport_dns_rebind_alert_checkbox,
            self.transport_dhcp_transaction_ttl_input,
            self.transport_dhcp_lease_ttl_input,
            self.transport_https_logging_checkbox,
            self.transport_https_certificates_checkbox,
            self.transport_https_quic_crypto_checkbox,
            *self.transport_protocol_checkboxes.values(),
        ):
            widget.setEnabled(transport_enabled)

        handshake_enabled = self.core_handshake_checkbox.isChecked()
        for widget in (
            self.handshake_half_open_timeout_input,
            self.handshake_established_timeout_input,
            self.handshake_rate_threshold_input,
            self.handshake_rate_period_input,
            self.handshake_ban_duration_input,
            self.handshake_log_tcp_checkbox,
            self.handshake_log_non_tls_checkbox,
            self.handshake_log_tls_records_checkbox,
            self.handshake_log_app_data_checkbox,
            self.handshake_log_tls13_keys_checkbox,
        ):
            widget.setEnabled(handshake_enabled)

        self.syn_scan_interval_input.setEnabled(
            self.core_syn_scanner_checkbox.isChecked()
        )
        packet_catcher_enabled = (
            self.core_packet_catcher_checkbox.isChecked()
        )
        for widget in (
            self.packet_catcher_tcp_rate_input,
            self.packet_catcher_udp_rate_input,
            self.packet_catcher_default_rate_input,
        ):
            widget.setEnabled(packet_catcher_enabled)

        use_stratum = self.stratum_comm_checkbox.isChecked()
        use_daemon = (
            self.stratum_mode_dropdown.currentText()
            == "Local Monero Daemon"
        )
        use_direct_pool = use_stratum and not use_daemon
        use_proxy = (
            use_direct_pool
            and self.stratum_proxy_checkbox.isChecked()
        )

        self.stratum_mode_dropdown.setEnabled(use_stratum)
        self.stratum_wallet_input.setEnabled(use_stratum)
        self.stratum_password_input.setEnabled(use_stratum)
        self.stratum_worker_input.setEnabled(use_stratum)
        self.stratum_user_agent_input.setEnabled(use_stratum)

        self.stratum_pool_host_input.setEnabled(use_direct_pool)
        self.stratum_pool_port_input.setEnabled(use_direct_pool)
        self.stratum_tls_dropdown.setEnabled(use_direct_pool)
        self.stratum_sni_input.setEnabled(use_direct_pool)
        self.stratum_proxy_checkbox.setEnabled(use_direct_pool)
        self.stratum_proxy_host_input.setEnabled(use_proxy)
        self.stratum_proxy_port_input.setEnabled(use_proxy)

        self.stratum_daemon_url_input.setEnabled(
            use_stratum and use_daemon
        )
        self.stratum_zmq_address_input.setEnabled(
            use_stratum and use_daemon
        )

        use_blocknet = self.blocknet_checkbox.isChecked()
        self.blocknet_relay_input.setEnabled(use_blocknet)
        self.blocknet_token_input.setEnabled(use_blocknet)
        self.scrapewebsite_endpoint_input.setEnabled(self.use_scrapewebsite_checkbox.isChecked())
        if not use_blocknet:
            self.blocknet_relay_input.setText("")
            self.blocknet_token_input.setText("")

        use_wifi_host = self.use_wifi_host_checkbox.isChecked()

        self.wifi_ssid_input.setEnabled(use_wifi_host)
        self.wifi_password_input.setEnabled(use_wifi_host)
        self.wifi_router_ip_input.setEnabled(use_wifi_host)
        self.wifi_prefix_length_input.setEnabled(use_wifi_host)
        self.wifi_auto_restart_checkbox.setEnabled(use_wifi_host)
        self.wifi_start_timeout_input.setEnabled(use_wifi_host)
        self.wifi_adapter_timeout_input.setEnabled(use_wifi_host)

    def _on_preset_selected(self, preset_name: str):
        self._load_presets(preset_name)

    def _load_presets(self, preset_name: str):
        panes_to_add = self.presets.get(preset_name, [])

        for pane in list(self._console_panes):
            if pane != "General":
                self._remove_console_pane(pane)

        for pane in panes_to_add:
            self._add_console_pane(pane)

        self._rebuild_pane_index()

    def _add_console_pane(self, name: str):
        if name not in self._console_panes:
            console = QPlainTextEdit()
            console.setReadOnly(True)
            console.setCenterOnScroll(False)  # important
            console.document().setMaximumBlockCount(10000 if name == "C++" else 3000)
            self.console_tabs.addTab(console, name)
            self._console_panes[name] = console
            self._rebuild_pane_index()

    def _remove_console_pane(self, name: str):
        if name in self._console_panes and name != "General":
            index = self.console_tabs.indexOf(self._console_panes[name])
            if index >= 0:
                widget = self._console_panes[name]
                self.console_tabs.removeTab(index)
                widget.deleteLater()
            del self._console_panes[name]
            self._rebuild_pane_index()

    def _on_add_pane(self):
        name = self.add_pane_input.text().strip()
        if name:
            self._add_console_pane(name)
            self._append_batch_to_pane("General", [f"[UI] Added pane: {name}"])
            self.add_pane_input.clear()

    def _on_remove_pane(self):
        name = self.add_pane_input.text().strip()
        if name:
            self._remove_console_pane(name)
            self._append_batch_to_pane("General", [f"[UI] Removed pane: {name}"])
            self.add_pane_input.clear()

    def _norm(self, s: str) -> str:
        return "".join(str(s).split()).casefold()

    def _rebuild_pane_index(self):
        idx = {}
        for pane_key in self._console_panes:
            for depth, part in enumerate(pane_key.split("/")):
                n = self._norm(part)
                idx.setdefault(n, []).append((pane_key, depth))
        self._pane_index = idx

    def _extract_prefixes_fast(self, message: str):
        try:
            return [self._norm(p) for p in self._PREFIX_RE.findall(message)]
        except Exception:
            return []

    def _route_message_to_pane(self, message: str) -> str:
        prefixes = self._extract_prefixes_fast(message)
        try:
            if prefixes[0] == self._norm("Transport"):
                return "Transport"
        except Exception:
            if prefixes and prefixes[0] == "transport":
                return "Transport"

        for sprefix in reversed(prefixes):
            pane = self._hot_prefix_to_pane.get(sprefix)
            if pane:
                return pane

        for sprefix in reversed(prefixes):
            hits = self._pane_index.get(sprefix)
            if hits:
                try:
                    return max(hits, key=lambda x: x[1])[0]
                except Exception:
                    return hits[0][0]

        return "General"


    def _append_batch_to_pane(self, category: str, messages: list[str]):
        if self._logging_shutdown or not messages:
            return

        pane = self._console_panes.get(category)
        if pane is None:
            pane = self._console_panes.get("General")
            if pane is None:
                return

        text = "\n".join(messages)
        if not text:
            return

        try:
            scrollbar = pane.verticalScrollBar()
            old_value = scrollbar.value()
            old_max = scrollbar.maximum()

            # only auto-scroll if the user was already basically at the bottom
            bottom_threshold = 4
            was_at_bottom = old_value >= max(0, old_max - bottom_threshold)

            # append without hijacking the visible cursor/selection
            cursor = QTextCursor(pane.document())
            cursor.movePosition(QTextCursor.End)

            if not pane.document().isEmpty():
                cursor.insertText("\n")

            cursor.insertText(text)

            if was_at_bottom:
                scrollbar.setValue(scrollbar.maximum())
            else:
                # keep the user's current reading position
                scrollbar.setValue(min(old_value, scrollbar.maximum()))

        except RuntimeError:
            self._logging_shutdown = True

    @staticmethod
    def _queued_log_size(message: str) -> int:
        return len(message.encode("utf-8", errors="replace")) + 1

    @staticmethod
    def _important_log_message(message: str) -> bool:
        lowered = str(message or "").casefold()
        return any(token in lowered for token in (
            "error", "exception", "failed", "crash", "reject", "drop",
            "dhcp", "lease", "tls", "handshake", "alert", "firewall",
            "route", "gateway", "hyperv", "packet", "warning", "⚠", "❌",
        ))

    @pyqtSlot(str)
    def log_message(self, message: str):
        if self._logging_shutdown:
            return

        try:
            msg = str(message).rstrip()
        except Exception:
            return

        if not msg:
            return

        if len(msg) > 10000:
            msg = msg[:10000] + " ... [truncated]"

        msg_size = self._queued_log_size(msg)
        important = self._important_log_message(msg)
        dropped_now = 0
        while self._log_queue and (
            len(self._log_queue) >= self._max_log_queue
            or self._log_queue_bytes + msg_size > self._max_log_queue_bytes
        ):
            drop_index = 0
            for index, queued in enumerate(self._log_queue):
                queued_msg = queued[0] if isinstance(queued, tuple) else queued
                queued_important = queued[1] if isinstance(queued, tuple) else self._important_log_message(queued_msg)
                if not queued_important:
                    drop_index = index
                    break
            old = self._log_queue[drop_index]
            del self._log_queue[drop_index]
            old_msg = old[0] if isinstance(old, tuple) else old
            self._log_queue_bytes = max(
                0,
                self._log_queue_bytes - self._queued_log_size(old_msg),
            )
            dropped_now += 1

        if dropped_now:
            self._dropped_log_lines += dropped_now
            self._dropping_logs = True
        elif len(self._log_queue) < (self._max_log_queue // 2):
            self._dropping_logs = False

        self._log_queue.append((msg, important))
        self._log_queue_bytes += msg_size

    @pyqtSlot()
    def _flush_log_queue(self):
        if self._logging_shutdown:
            self._log_queue.clear()
            self._log_queue_bytes = 0
            return

        if self._flush_in_progress:
            return

        self._flush_in_progress = True
        started = time.monotonic()
        try:
            per_pane = defaultdict(list)
            processed = 0
            backlog = len(self._log_queue)
            batch_limit = self._flush_batch_size
            if backlog > (self._max_log_queue // 2):
                batch_limit = min(1200, self._flush_batch_size * 4)
            elif backlog > (self._max_log_queue // 4):
                batch_limit = min(750, self._flush_batch_size * 2)

            now = started
            if self._dropped_log_lines and (now - self._last_drop_notice) >= 1.0:
                notice = (
                    "[RouterTab] ⚠️ Dropped "
                    f"{self._dropped_log_lines} oldest GUI log lines under sustained load."
                )
                pane_name = self._route_message_to_pane(notice)
                per_pane[pane_name].append(notice)
                self._dropped_log_lines = 0
                self._last_drop_notice = now

            while self._log_queue and processed < batch_limit:
                queued = self._log_queue.popleft()
                message = queued[0] if isinstance(queued, tuple) else queued
                self._log_queue_bytes = max(
                    0,
                    self._log_queue_bytes - self._queued_log_size(message),
                )
                pane_name = self._route_message_to_pane(message)
                per_pane[pane_name].append(message)
                processed += 1

                # Do not monopolize Qt when thousands of packets arrive at once.
                if processed % 32 == 0 and (
                    time.monotonic() - started
                ) >= self._flush_time_budget_seconds:
                    break

            for pane_name, messages in per_pane.items():
                self._append_batch_to_pane(pane_name, messages)

        finally:
            self._flush_in_progress = False

    def shutdown_logging(self):
        self._logging_shutdown = True

        try:
            if self._log_flush_timer.isActive():
                self._log_flush_timer.stop()
        except Exception:
            pass

        try:
            self.router_logger.message_signal.disconnect(self.log_message)
        except Exception:
            pass

        self._log_queue.clear()
        self._log_queue_bytes = 0
        self._dropped_log_lines = 0






class ProcessTab(QWidget):
    """Dock an existing Windows process and attach its sockets to the router.

    Docking changes only the selected top-level window's parent. It does not start,
    stop, import, or merge the client process. Network routing is delegated to the
    server-owned ProcessInterfaceManager.
    """

    operation_completed = pyqtSignal(str, bool, str, object)

    GWL_STYLE = -16
    GWL_EXSTYLE = -20
    WS_CHILD = 0x40000000
    WS_VISIBLE = 0x10000000
    WS_POPUP = 0x80000000
    WS_CAPTION = 0x00C00000
    WS_THICKFRAME = 0x00040000
    WS_MINIMIZEBOX = 0x00020000
    WS_MAXIMIZEBOX = 0x00010000
    WS_SYSMENU = 0x00080000
    WS_CLIPSIBLINGS = 0x04000000
    WS_CLIPCHILDREN = 0x02000000
    SWP_NOZORDER = 0x0004
    SWP_NOACTIVATE = 0x0010
    SWP_FRAMECHANGED = 0x0020
    SWP_SHOWWINDOW = 0x0040
    SW_RESTORE = 9

    def __init__(self, manager_provider, logger=None, parent=None):
        super().__init__(parent)
        self.manager_provider = manager_provider
        self.logger = logger
        self._operation_thread = None
        self._docked_hwnd = None
        self._docked_pid = None
        self._original_parent = 0
        self._original_style = 0
        self._original_exstyle = 0
        self._original_rect = None
        self._user32 = None
        self._get_window_long = None
        self._set_window_long = None

        self._build_ui()
        self.operation_completed.connect(self._on_operation_completed)

        self._dock_timer = QTimer(self)
        self._dock_timer.setInterval(250)
        self._dock_timer.timeout.connect(self._maintain_docked_window)
        self._dock_timer.start()

        self._status_timer = QTimer(self)
        self._status_timer.setInterval(1000)
        self._status_timer.timeout.connect(self.refresh_status)
        self._status_timer.start()

        self.refresh_processes()
        self.refresh_status()

    def _build_ui(self):
        root = QVBoxLayout(self)
        root.setContentsMargins(10, 10, 10, 10)
        root.setSpacing(8)

        selector_group = QGroupBox("Separate Process Selection")
        selector_layout = QGridLayout(selector_group)
        self.process_combo = QComboBox()
        self.process_combo.setMinimumWidth(360)
        self.process_combo.currentIndexChanged.connect(self.refresh_windows)
        self.refresh_button = QPushButton("Refresh Processes")
        self.refresh_button.clicked.connect(self.refresh_processes)
        self.window_combo = QComboBox()
        self.window_combo.setMinimumWidth(360)
        self.dock_button = QPushButton("Dock Selected Window")
        self.dock_button.clicked.connect(self.dock_selected_window)
        self.detach_button = QPushButton("Detach Window")
        self.detach_button.clicked.connect(self.detach_window)
        self.detach_button.setEnabled(False)

        selector_layout.addWidget(QLabel("Process:"), 0, 0)
        selector_layout.addWidget(self.process_combo, 0, 1)
        selector_layout.addWidget(self.refresh_button, 0, 2)
        selector_layout.addWidget(QLabel("Top-level window:"), 1, 0)
        selector_layout.addWidget(self.window_combo, 1, 1)
        dock_buttons = QHBoxLayout()
        dock_buttons.addWidget(self.dock_button)
        dock_buttons.addWidget(self.detach_button)
        dock_buttons.addStretch(1)
        selector_layout.addLayout(dock_buttons, 1, 2)
        root.addWidget(selector_group)

        self.process_splitter = QSplitter(Qt.Vertical)
        self.process_splitter.setChildrenCollapsible(False)

        self.dock_frame = QFrame()
        self.dock_frame.setFrameShape(QFrame.StyledPanel)
        self.dock_frame.setMinimumHeight(300)
        self.dock_frame.setAttribute(Qt.WA_NativeWindow, True)
        self.dock_frame.setStyleSheet(
            "QFrame { background-color: #111111; border: 1px solid #555555; }"
        )
        dock_layout = QVBoxLayout(self.dock_frame)
        dock_layout.setContentsMargins(0, 0, 0, 0)
        self.dock_placeholder = QLabel(
            "Select a running process and dock one of its visible windows here.\n"
            "The client remains an independent process with its own PID and runtime."
        )
        self.dock_placeholder.setAlignment(Qt.AlignCenter)
        self.dock_placeholder.setWordWrap(True)
        dock_layout.addWidget(self.dock_placeholder)
        self.process_splitter.addWidget(self.dock_frame)

        interface_group = QGroupBox("ProcessInterface Routing")
        interface_layout = QGridLayout(interface_group)
        self.interface_status_label = QLabel("Interface: checking...")
        self.route_status_label = QLabel("Process route: disabled")
        self.switch_name_input = QLineEdit("ProcessInterface")
        self.interface_ip_input = QLineEdit("172.30.254.1")
        self.prefix_spin = QSpinBox()
        self.prefix_spin.setRange(1, 30)
        self.prefix_spin.setValue(30)
        self.create_interface_checkbox = QCheckBox(
            "Create/enable Hyper-V ProcessInterface before routing"
        )
        self.create_interface_checkbox.setChecked(True)
        self.route_mode_combo = QComboBox()
        self.route_mode_combo.addItems([
            "Stratum Only",
            "All TCP/UDP",
            "Observe Only",
        ])
        self.stratum_ports_input = QLineEdit(
            "3333,3334,4444,5555,7777,10001,10128,20128,4242"
        )
        self.stratum_ports_input.setToolTip(
            "In Stratum Only mode, a selected process flow is attached when either "
            "endpoint uses one of these ports."
        )
        self.create_interface_button = QPushButton("Create / Enable Interface")
        self.create_interface_button.clicked.connect(self.create_interface)
        self.remove_interface_button = QPushButton("Remove Interface")
        self.remove_interface_button.clicked.connect(self.remove_interface)
        self.start_route_button = QPushButton("Route Selected Process")
        self.start_route_button.clicked.connect(self.start_process_route)
        self.stop_route_button = QPushButton("Stop Process Routing")
        self.stop_route_button.clicked.connect(self.stop_process_route)

        interface_layout.addWidget(self.interface_status_label, 0, 0, 1, 3)
        interface_layout.addWidget(self.route_status_label, 1, 0, 1, 3)
        interface_layout.addWidget(QLabel("Hyper-V switch:"), 2, 0)
        interface_layout.addWidget(self.switch_name_input, 2, 1)
        interface_layout.addWidget(QLabel("Server IPv4 / prefix:"), 3, 0)
        address_row = QHBoxLayout()
        address_row.addWidget(self.interface_ip_input, 1)
        address_row.addWidget(self.prefix_spin)
        interface_layout.addLayout(address_row, 3, 1)
        interface_buttons = QHBoxLayout()
        interface_buttons.addWidget(self.create_interface_button)
        interface_buttons.addWidget(self.remove_interface_button)
        interface_buttons.addStretch(1)
        interface_layout.addLayout(interface_buttons, 2, 2, 2, 1)
        interface_layout.addWidget(self.create_interface_checkbox, 4, 0, 1, 3)
        interface_layout.addWidget(QLabel("Routing mode:"), 5, 0)
        interface_layout.addWidget(self.route_mode_combo, 5, 1)
        interface_layout.addWidget(QLabel("Stratum ports:"), 6, 0)
        interface_layout.addWidget(self.stratum_ports_input, 6, 1, 1, 2)
        route_buttons = QHBoxLayout()
        route_buttons.addWidget(self.start_route_button)
        route_buttons.addWidget(self.stop_route_button)
        route_buttons.addStretch(1)
        interface_layout.addLayout(route_buttons, 7, 0, 1, 3)

        explanation = QLabel(
            "Routing is PID-scoped by correlating the selected process's live socket "
            "tuples with packets arriving from the router's host WinDivert/loopback "
            "capture. It does not replace the machine-wide default route. Start the "
            "Router first; reconnect an existing network session if it was opened before "
            "the policy was enabled."
        )
        explanation.setWordWrap(True)
        explanation.setStyleSheet("color: #bbbbbb;")
        interface_layout.addWidget(explanation, 8, 0, 1, 3)
        controls_panel = QWidget()
        controls_layout = QVBoxLayout(controls_panel)
        controls_layout.setContentsMargins(0, 0, 0, 0)
        controls_layout.addWidget(interface_group)

        self.process_log = QPlainTextEdit()
        self.process_log.setReadOnly(True)
        self.process_log.setMaximumBlockCount(5000)
        self.process_log.setMinimumHeight(110)
        controls_layout.addWidget(self.process_log)
        self.process_splitter.addWidget(controls_panel)
        self.process_splitter.setSizes([360, 330])
        root.addWidget(self.process_splitter, 1)

    def _append_log(self, message: str):
        text = str(message or "").rstrip()
        if not text:
            return
        self.process_log.appendPlainText(text)
        if self.logger is not None:
            try:
                self.logger.log_message(text)
            except Exception:
                pass

    def _manager(self):
        try:
            return self.manager_provider() if callable(self.manager_provider) else None
        except Exception as exc:
            self._append_log(f"[ProcessTab] Manager lookup failed: {exc}")
            return None

    def refresh_processes(self):
        selected_pid = self.process_combo.currentData()
        processes = []
        for process in psutil.process_iter(["pid", "name", "exe", "username"]):
            try:
                info = process.info
                pid = int(info.get("pid") or 0)
                if pid <= 0 or pid == os.getpid():
                    continue
                name = str(info.get("name") or f"PID {pid}")
                path = str(info.get("exe") or "")
                processes.append((name.casefold(), pid, name, path))
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
            except Exception:
                continue
        processes.sort(key=lambda item: (item[0], item[1]))

        self.process_combo.blockSignals(True)
        self.process_combo.clear()
        restore_index = -1
        for index, (_, pid, name, path) in enumerate(processes):
            label = f"{name}  [PID {pid}]"
            self.process_combo.addItem(label, {"pid": pid, "name": name, "path": path})
            if selected_pid and isinstance(selected_pid, dict) and selected_pid.get("pid") == pid:
                restore_index = index
        if restore_index >= 0:
            self.process_combo.setCurrentIndex(restore_index)
        self.process_combo.blockSignals(False)
        self.refresh_windows()
        self._append_log(f"[ProcessTab] Found {len(processes)} running processes.")

    def _initialize_user32(self):
        if os.name != "nt":
            return False
        if self._user32 is not None:
            return True
        try:
            self._user32 = ctypes.windll.user32
            user32 = self._user32
            user32.SetParent.argtypes = [wintypes.HWND, wintypes.HWND]
            user32.SetParent.restype = wintypes.HWND
            user32.GetParent.argtypes = [wintypes.HWND]
            user32.GetParent.restype = wintypes.HWND
            user32.IsWindow.argtypes = [wintypes.HWND]
            user32.IsWindow.restype = wintypes.BOOL
            user32.IsWindowVisible.argtypes = [wintypes.HWND]
            user32.IsWindowVisible.restype = wintypes.BOOL
            user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
            user32.GetWindowThreadProcessId.restype = wintypes.DWORD
            user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
            user32.GetWindowTextLengthW.restype = ctypes.c_int
            user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
            user32.GetWindowTextW.restype = ctypes.c_int
            user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
            user32.GetWindowRect.restype = wintypes.BOOL
            user32.SetWindowPos.argtypes = [
                wintypes.HWND, wintypes.HWND,
                ctypes.c_int, ctypes.c_int, ctypes.c_int, ctypes.c_int,
                wintypes.UINT,
            ]
            user32.SetWindowPos.restype = wintypes.BOOL
            user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
            user32.ShowWindow.restype = wintypes.BOOL
            pointer_type = ctypes.c_longlong if ctypes.sizeof(ctypes.c_void_p) == 8 else ctypes.c_long
            get_long = getattr(user32, "GetWindowLongPtrW", user32.GetWindowLongW)
            set_long = getattr(self._user32, "SetWindowLongPtrW", self._user32.SetWindowLongW)
            get_long.argtypes = [wintypes.HWND, ctypes.c_int]
            get_long.restype = pointer_type
            set_long.argtypes = [wintypes.HWND, ctypes.c_int, pointer_type]
            set_long.restype = pointer_type
            self._get_window_long = get_long
            self._set_window_long = set_long
            return True
        except Exception as exc:
            self._append_log(f"[ProcessTab] Win32 initialization failed: {exc}")
            return False

    def _enumerate_windows(self, pid: int):
        if not self._initialize_user32():
            return []
        user32 = self._user32
        windows = []
        callback_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        @callback_type
        def callback(hwnd, _):
            try:
                if not user32.IsWindowVisible(hwnd):
                    return True
                owner_pid = wintypes.DWORD()
                user32.GetWindowThreadProcessId(hwnd, ctypes.byref(owner_pid))
                if int(owner_pid.value) != int(pid):
                    return True
                length = int(user32.GetWindowTextLengthW(hwnd))
                if length <= 0:
                    return True
                buffer = ctypes.create_unicode_buffer(length + 1)
                user32.GetWindowTextW(hwnd, buffer, length + 1)
                title = buffer.value.strip()
                if title:
                    windows.append({"hwnd": int(hwnd), "title": title})
            except Exception:
                pass
            return True

        user32.EnumWindows(callback, 0)
        return windows

    def refresh_windows(self):
        self.window_combo.clear()
        process_data = self.process_combo.currentData()
        if not isinstance(process_data, dict):
            self.window_combo.addItem("No process selected", None)
            return
        pid = int(process_data.get("pid") or 0)
        windows = self._enumerate_windows(pid)
        if not windows:
            self.window_combo.addItem(
                "No visible top-level window (routing can still be enabled)",
                None,
            )
            return
        for window in windows:
            self.window_combo.addItem(
                f"{window['title']}  [HWND 0x{window['hwnd']:X}]",
                window,
            )

    def dock_selected_window(self):
        if os.name != "nt" or not self._initialize_user32():
            self._append_log("[ProcessTab] Window docking is available only on Windows.")
            return
        process_data = self.process_combo.currentData()
        window_data = self.window_combo.currentData()
        if not isinstance(process_data, dict) or not isinstance(window_data, dict):
            self._append_log("[ProcessTab] Select a process with a visible window first.")
            return
        if self._docked_hwnd:
            self.detach_window()

        hwnd = int(window_data["hwnd"])
        pid = int(process_data["pid"])
        user32 = self._user32
        if not user32.IsWindow(hwnd):
            self._append_log("[ProcessTab] The selected window no longer exists.")
            self.refresh_windows()
            return

        rect = wintypes.RECT()
        user32.GetWindowRect(hwnd, ctypes.byref(rect))
        self._original_rect = (rect.left, rect.top, rect.right, rect.bottom)
        self._original_parent = int(user32.GetParent(hwnd) or 0)
        self._original_style = int(self._get_window_long(hwnd, self.GWL_STYLE)) & 0xFFFFFFFF
        self._original_exstyle = int(self._get_window_long(hwnd, self.GWL_EXSTYLE)) & 0xFFFFFFFF

        host_hwnd = int(self.dock_frame.winId())
        ctypes.set_last_error(0)
        previous_parent = user32.SetParent(hwnd, host_hwnd)
        error = ctypes.get_last_error()
        if not previous_parent and error:
            self._append_log(
                f"[ProcessTab] SetParent failed with Windows error {error}. "
                "Run both programs at the same integrity level and DPI mode."
            )
            return

        new_style = self._original_style
        new_style &= ~(
            self.WS_POPUP | self.WS_CAPTION | self.WS_THICKFRAME |
            self.WS_MINIMIZEBOX | self.WS_MAXIMIZEBOX | self.WS_SYSMENU
        )
        new_style |= (
            self.WS_CHILD | self.WS_VISIBLE |
            self.WS_CLIPSIBLINGS | self.WS_CLIPCHILDREN
        )
        self._set_window_long(hwnd, self.GWL_STYLE, new_style)
        user32.ShowWindow(hwnd, self.SW_RESTORE)

        self._docked_hwnd = hwnd
        self._docked_pid = pid
        self.dock_placeholder.hide()
        self.detach_button.setEnabled(True)
        self.dock_button.setEnabled(False)
        self._resize_docked_window()
        self._append_log(
            f"[ProcessTab] Docked PID {pid} window '{window_data['title']}'. "
            "The process remains independent."
        )

    def _resize_docked_window(self):
        hwnd = self._docked_hwnd
        if not hwnd or not self._initialize_user32():
            return
        if not self._user32.IsWindow(hwnd):
            return
        width = max(1, int(self.dock_frame.contentsRect().width()))
        height = max(1, int(self.dock_frame.contentsRect().height()))
        self._user32.SetWindowPos(
            hwnd,
            0,
            0,
            0,
            width,
            height,
            self.SWP_NOZORDER | self.SWP_NOACTIVATE |
            self.SWP_FRAMECHANGED | self.SWP_SHOWWINDOW,
        )

    def _maintain_docked_window(self):
        hwnd = self._docked_hwnd
        if not hwnd:
            return
        if not self._initialize_user32() or not self._user32.IsWindow(hwnd):
            self._append_log("[ProcessTab] Docked process window closed.")
            self._clear_dock_state()
            return
        try:
            if self._docked_pid and not psutil.pid_exists(self._docked_pid):
                self._append_log("[ProcessTab] Docked process exited.")
                self._clear_dock_state()
                return
        except Exception:
            pass
        self._resize_docked_window()

    def _clear_dock_state(self):
        self._docked_hwnd = None
        self._docked_pid = None
        self._original_parent = 0
        self._original_style = 0
        self._original_exstyle = 0
        self._original_rect = None
        self.dock_placeholder.show()
        self.detach_button.setEnabled(False)
        self.dock_button.setEnabled(True)

    def detach_window(self):
        hwnd = self._docked_hwnd
        if not hwnd:
            return
        if self._initialize_user32() and self._user32.IsWindow(hwnd):
            try:
                self._user32.SetParent(hwnd, self._original_parent or 0)
                self._set_window_long(hwnd, self.GWL_STYLE, self._original_style)
                self._set_window_long(hwnd, self.GWL_EXSTYLE, self._original_exstyle)
                if self._original_rect:
                    left, top, right, bottom = self._original_rect
                    width = max(200, right - left)
                    height = max(120, bottom - top)
                else:
                    left, top, width, height = 100, 100, 900, 700
                self._user32.SetWindowPos(
                    hwnd,
                    0,
                    left,
                    top,
                    width,
                    height,
                    self.SWP_NOZORDER | self.SWP_FRAMECHANGED | self.SWP_SHOWWINDOW,
                )
                self._user32.ShowWindow(hwnd, self.SW_RESTORE)
            except Exception as exc:
                self._append_log(f"[ProcessTab] Detach warning: {exc}")
        self._append_log("[ProcessTab] Window detached; client process was not stopped.")
        self._clear_dock_state()

    def _parse_ports(self):
        ports = []
        for token in re.split(r"[,;\s]+", self.stratum_ports_input.text().strip()):
            if not token:
                continue
            try:
                port = int(token)
            except ValueError:
                raise ValueError(f"Invalid port: {token}")
            if not 1 <= port <= 65535:
                raise ValueError(f"Port outside 1-65535: {port}")
            ports.append(port)
        return sorted(set(ports))

    def _run_operation(self, name: str, function):
        if self._operation_thread and self._operation_thread.is_alive():
            self._append_log("[ProcessTab] Another ProcessInterface operation is running.")
            return
        self._set_operation_buttons_enabled(False)

        def worker():
            try:
                result = function()
                self.operation_completed.emit(name, True, "", result)
            except Exception as exc:
                self.operation_completed.emit(name, False, str(exc), None)

        self._operation_thread = threading.Thread(
            target=worker,
            name=f"ProcessTab-{name}",
            daemon=True,
        )
        self._operation_thread.start()

    def _set_operation_buttons_enabled(self, enabled: bool):
        for button in (
            self.create_interface_button,
            self.remove_interface_button,
            self.start_route_button,
            self.stop_route_button,
        ):
            button.setEnabled(enabled)

    def create_interface(self):
        manager = self._manager()
        if manager is None:
            self._append_log("[ProcessTab] ProcessInterfaceManager is unavailable.")
            return
        switch_name = self.switch_name_input.text().strip() or "ProcessInterface"
        ipv4 = self.interface_ip_input.text().strip()
        prefix = int(self.prefix_spin.value())
        self._run_operation(
            "create-interface",
            lambda: manager.create_interface(
                switch_name=switch_name,
                ipv4=ipv4,
                prefix_length=prefix,
            ),
        )

    def remove_interface(self):
        manager = self._manager()
        if manager is None:
            return
        self._run_operation(
            "remove-interface",
            lambda: manager.remove_interface(force=False),
        )

    def start_process_route(self):
        process_data = self.process_combo.currentData()
        if not isinstance(process_data, dict):
            self._append_log("[ProcessTab] Select a process first.")
            return
        manager = self._manager()
        if manager is None:
            self._append_log("[ProcessTab] ProcessInterfaceManager is unavailable.")
            return
        router = getattr(manager, "router_manager", None)
        if router is None or not getattr(router, "started", False):
            self._append_log(
                "[ProcessTab] Start the Router first so ProcessInterface packets have "
                "an active forwarding/NAT path."
            )
            return
        pid = int(process_data["pid"])
        mode = self.route_mode_combo.currentText()
        try:
            ports = self._parse_ports()
        except Exception as exc:
            self._append_log(f"[ProcessTab] {exc}")
            return
        create_first = self.create_interface_checkbox.isChecked()
        switch_name = self.switch_name_input.text().strip() or "ProcessInterface"
        ipv4 = self.interface_ip_input.text().strip()
        prefix = int(self.prefix_spin.value())

        def operation():
            status = manager.status()
            if create_first and not status.get("interface_ready"):
                manager.create_interface(
                    switch_name=switch_name,
                    ipv4=ipv4,
                    prefix_length=prefix,
                )
            return manager.enable_process(
                pid,
                mode=mode,
                stratum_ports=ports,
            )

        self._run_operation("enable-route", operation)

    def stop_process_route(self):
        manager = self._manager()
        if manager is None:
            return
        self._run_operation(
            "disable-route",
            lambda: manager.disable_process(),
        )

    @pyqtSlot(str, bool, str, object)
    def _on_operation_completed(self, name, ok, message, result):
        self._operation_thread = None
        self._set_operation_buttons_enabled(True)
        if ok:
            self._append_log(f"[ProcessTab] ✅ {name} completed.")
        else:
            self._append_log(f"[ProcessTab] ❌ {name} failed: {message}")
        self.refresh_status()

    def refresh_status(self):
        manager = self._manager()
        if manager is None:
            self.interface_status_label.setText("Interface: manager unavailable")
            self.route_status_label.setText("Process route: unavailable")
            return
        try:
            status = manager.status()
        except Exception as exc:
            self.interface_status_label.setText(f"Interface: status error ({exc})")
            return
        if status.get("interface_ready"):
            self.interface_status_label.setText(
                f"Interface: {status.get('interface_alias')} | "
                f"{status.get('interface_ipv4')}/{status.get('prefix_length')} | "
                f"ifIndex={status.get('interface_index') or '-'}"
            )
        else:
            self.interface_status_label.setText(
                "Interface: not created (Hyper-V + administrator rights required)"
            )
        if status.get("enabled"):
            self.route_status_label.setText(
                f"Process route: PID {status.get('pid')} {status.get('process_name')} | "
                f"mode={status.get('mode')} | flows={status.get('flow_count')} | "
                f"tagged packets={status.get('packets_tagged')}"
            )
        else:
            self.route_status_label.setText("Process route: disabled")

    def resizeEvent(self, event):
        super().resizeEvent(event)
        self._resize_docked_window()

    def shutdown(self):
        self.detach_window()
        manager = self._manager()
        if manager is not None:
            try:
                manager.disable_process()
            except Exception:
                pass

class CodeOutputChatTab(QWidget):
    """Text-only English chat grounded in live PythonRouter/CodeOutput state."""

    response_ready = pyqtSignal(str)
    error_ready = pyqtSignal(str)

    def __init__(self, router_provider, parent=None):
        super().__init__(parent)
        self.router_provider = router_provider
        self._closing = False
        self._worker = None
        self._chat_history = []

        layout = QVBoxLayout(self)
        header = QHBoxLayout()
        self.status_label = QLabel("CodeOutput Chat: ready (English text only)")
        header.addWidget(self.status_label)
        header.addStretch(1)
        layout.addLayout(header)

        self.chat_output = QPlainTextEdit()
        self.chat_output.setReadOnly(True)
        self.chat_output.setMaximumBlockCount(5000)
        layout.addWidget(self.chat_output, 1)

        prompt_row = QHBoxLayout()
        self.prompt_input = QLineEdit()
        self.prompt_input.setPlaceholderText(
            "Ask in English about endpoints, conversations, protocols, ports, interfaces, routing stages, or recent flows"
        )
        self.ask_button = QPushButton("Ask CodeOutput")
        self.refresh_button = QPushButton("Current Communication Summary")
        self.clear_button = QPushButton("Clear Chat")
        prompt_row.addWidget(self.prompt_input, 1)
        prompt_row.addWidget(self.ask_button)
        prompt_row.addWidget(self.refresh_button)
        prompt_row.addWidget(self.clear_button)
        layout.addLayout(prompt_row)

        self.ask_button.clicked.connect(self._ask)
        self.refresh_button.clicked.connect(self._refresh)
        self.clear_button.clicked.connect(self._clear_chat)
        self.prompt_input.returnPressed.connect(self._ask)
        self.response_ready.connect(self._show_response)
        self.error_ready.connect(self._show_error)

    def _router(self):
        try:
            return self.router_provider() if callable(self.router_provider) else None
        except Exception:
            return None

    def _refresh(self):
        self.prompt_input.setText("Summarize the current communications and routing stages in English.")
        self._ask()

    def _clear_chat(self):
        self._chat_history.clear()
        self.chat_output.clear()
        self.status_label.setText("CodeOutput Chat: ready (English text only)")

    def _ask(self):
        prompt = self.prompt_input.text().strip() or "Summarize current communications in English."
        router = self._router()
        if router is None:
            self._show_error("Router manager is unavailable.")
            return
        if self._worker and self._worker.is_alive():
            self._show_error("A CodeOutput analysis is already running.")
            return
        history_snapshot = list(self._chat_history[-12:])
        self._chat_history.append({"role": "user", "content": prompt})
        self.chat_output.appendPlainText(f"\nYou: {prompt}")
        self.status_label.setText("CodeOutput Chat: analyzing router knowledge...")
        self.ask_button.setEnabled(False)
        self.prompt_input.clear()

        def work():
            try:
                method = getattr(router, "ask_codeoutput", None)
                if not callable(method):
                    raise RuntimeError("The router does not expose ask_codeoutput().")
                try:
                    response = str(method(prompt, chat_history=history_snapshot))
                except TypeError:
                    response = str(method(prompt))
                if not self._closing:
                    self.response_ready.emit(response)
            except Exception as exc:
                if not self._closing:
                    self.error_ready.emit(str(exc))

        self._worker = threading.Thread(target=work, name="CodeOutputTextChat", daemon=True)
        self._worker.start()

    @pyqtSlot(str)
    def _show_response(self, response: str):
        response = str(response or "No response was generated.").strip()
        self._chat_history.append({"role": "assistant", "content": response})
        self.chat_output.appendPlainText(f"\nCodeOutput: {response}\n")
        self.status_label.setText("CodeOutput Chat: ready (English text only)")
        self.ask_button.setEnabled(True)

    @pyqtSlot(str)
    def _show_error(self, error: str):
        self.chat_output.appendPlainText(f"\nCodeOutput error: {error}\n")
        self.status_label.setText("CodeOutput Chat: error")
        self.ask_button.setEnabled(True)

    def shutdown(self):
        self._closing = True


class PacketSenderTab(QWidget):
    """PacketLab: advanced packet construction routed through CodeOutput or a selected interface."""

    # Original signals are retained for external compatibility.
    send_ping_requested = pyqtSignal(str, str, str, int)
    send_tcp_syn_requested = pyqtSignal(str, int, str, str, int)
    send_udp_requested = pyqtSignal(str, int, bytes, str, str, int)
    send_dns_requested = pyqtSignal(str, str, str, str, str, int)
    send_packetlab_requested = pyqtSignal(dict)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._create_widgets()
        self._configure_layout()
        self._connect_signals()
        self._update_protocol_controls()

    def _create_widgets(self):
        self.iface_combo = QComboBox()
        self.iface_combo.setEditable(True)
        self.iface_combo.addItem("CodeOutput", userData="CodeOutput")

        self.route_via_codeoutput_checkbox = QCheckBox(
            "Route through CodeOutputManager and CodeOutput interface"
        )
        self.route_via_codeoutput_checkbox.setChecked(True)

        self.ip_version_combo = QComboBox()
        self.ip_version_combo.addItems(["IPv4", "IPv6"])
        self.protocol_combo = QComboBox()
        self.protocol_combo.addItems(["TCP", "UDP", "ICMP", "DNS", "Raw IP"])

        self.target_input = QLineEdit("example.com")
        self.target_input.setPlaceholderText("Hostname, IPv4, or IPv6 target")
        self.source_input = QLineEdit()
        self.source_input.setPlaceholderText("Optional source IPv4/IPv6")

        self.source_port_input = QSpinBox()
        self.source_port_input.setRange(0, 65535)
        self.source_port_input.setSpecialValueText("Automatic")
        self.dest_port_input = QSpinBox()
        self.dest_port_input.setRange(0, 65535)
        self.dest_port_input.setValue(443)
        self.tcp_flags_input = QLineEdit("S")
        self.tcp_flags_input.setPlaceholderText("S, A, PA, F, R...")
        self.ttl_input = QSpinBox()
        self.ttl_input.setRange(1, 255)
        self.ttl_input.setValue(64)

        self.payload_encoding_combo = QComboBox()
        self.payload_encoding_combo.addItems(["UTF-8", "Hex", "Base64"])
        self.payload_input = QPlainTextEdit()
        self.payload_input.setPlaceholderText("Optional payload")
        self.payload_input.setMaximumHeight(100)

        self.dns_server_input = QLineEdit("8.8.8.8")
        self.dns_domain_input = QLineEdit("google.com")
        self.dns_type_combo = QComboBox()
        self.dns_type_combo.addItems(["A", "AAAA", "MX", "NS", "TXT", "SRV", "PTR", "CAA"])
        self.dns_transport_combo = QComboBox()
        self.dns_transport_combo.addItems(["UDP", "TCP"])

        self.send_packet_button = QPushButton("Build and Route Packet")
        self.send_packet_button.setEnabled(False)
        self.clear_log_button = QPushButton("Clear PacketLab Log")
        self.packet_log = QPlainTextEdit()
        self.packet_log.setReadOnly(True)
        self.packet_log.setMaximumBlockCount(10000)

        # Compatibility aliases expected by older main-window enable/disable code.
        self.send_ping_button = self.send_packet_button
        self.send_tcp_button = self.send_packet_button
        self.send_udp_button = self.send_packet_button
        self.send_dns_button = self.send_packet_button
        self.ping_ip_input = self.target_input
        self.tcp_ip_input = self.target_input
        self.tcp_port_input = self.dest_port_input
        self.udp_ip_input = self.target_input
        self.udp_port_input = self.dest_port_input
        self.udp_payload_input = self.payload_input

    def _configure_layout(self):
        main_layout = QVBoxLayout(self)
        main_layout.setContentsMargins(8, 8, 8, 8)

        group = QGroupBox("PacketLab Builder")
        grid = QGridLayout(group)
        grid.setColumnStretch(1, 1)
        grid.setColumnStretch(3, 1)

        grid.addWidget(QLabel("Send/ingress interface:"), 0, 0)
        grid.addWidget(self.iface_combo, 0, 1)
        grid.addWidget(self.route_via_codeoutput_checkbox, 0, 2, 1, 2)

        grid.addWidget(QLabel("IP version:"), 1, 0)
        grid.addWidget(self.ip_version_combo, 1, 1)
        grid.addWidget(QLabel("Protocol:"), 1, 2)
        grid.addWidget(self.protocol_combo, 1, 3)

        grid.addWidget(QLabel("Target/hostname:"), 2, 0)
        grid.addWidget(self.target_input, 2, 1)
        grid.addWidget(QLabel("Optional source address:"), 2, 2)
        grid.addWidget(self.source_input, 2, 3)

        grid.addWidget(QLabel("Source port:"), 3, 0)
        grid.addWidget(self.source_port_input, 3, 1)
        grid.addWidget(QLabel("Destination port:"), 3, 2)
        grid.addWidget(self.dest_port_input, 3, 3)

        grid.addWidget(QLabel("TCP flags:"), 4, 0)
        grid.addWidget(self.tcp_flags_input, 4, 1)
        grid.addWidget(QLabel("TTL / hop limit:"), 4, 2)
        grid.addWidget(self.ttl_input, 4, 3)

        self.dns_group = QGroupBox("DNS Query")
        dns_grid = QGridLayout(self.dns_group)
        dns_grid.addWidget(QLabel("DNS server:"), 0, 0)
        dns_grid.addWidget(self.dns_server_input, 0, 1)
        dns_grid.addWidget(QLabel("Query name:"), 0, 2)
        dns_grid.addWidget(self.dns_domain_input, 0, 3)
        dns_grid.addWidget(QLabel("Record type:"), 1, 0)
        dns_grid.addWidget(self.dns_type_combo, 1, 1)
        dns_grid.addWidget(QLabel("Transport:"), 1, 2)
        dns_grid.addWidget(self.dns_transport_combo, 1, 3)
        grid.addWidget(self.dns_group, 5, 0, 1, 4)

        grid.addWidget(QLabel("Payload encoding:"), 6, 0)
        grid.addWidget(self.payload_encoding_combo, 6, 1)
        grid.addWidget(QLabel("Payload:"), 6, 2)
        grid.addWidget(self.payload_input, 6, 3)

        buttons = QHBoxLayout()
        buttons.addWidget(self.send_packet_button)
        buttons.addWidget(self.clear_log_button)
        buttons.addStretch(1)
        grid.addLayout(buttons, 7, 0, 1, 4)

        main_layout.addWidget(group)
        main_layout.addWidget(QLabel("PacketLab and router output"))
        main_layout.addWidget(self.packet_log, 1)

    def _connect_signals(self):
        self.send_packet_button.clicked.connect(self._on_send_packet)
        self.clear_log_button.clicked.connect(self.packet_log.clear)
        self.protocol_combo.currentTextChanged.connect(self._update_protocol_controls)
        self.route_via_codeoutput_checkbox.toggled.connect(self._update_interface_mode)

    def _update_interface_mode(self):
        routed = self.route_via_codeoutput_checkbox.isChecked()
        self.iface_combo.setEnabled(not routed)
        if routed:
            index = self.iface_combo.findData("CodeOutput")
            if index >= 0:
                self.iface_combo.setCurrentIndex(index)

    def _update_protocol_controls(self):
        protocol = self.protocol_combo.currentText().strip().upper()
        uses_ports = protocol in {"TCP", "UDP", "DNS"}
        self.source_port_input.setEnabled(uses_ports)
        self.dest_port_input.setEnabled(uses_ports)
        self.tcp_flags_input.setEnabled(protocol == "TCP")
        self.dns_group.setVisible(protocol == "DNS")
        if protocol == "DNS":
            self.dest_port_input.setValue(53)
        elif protocol == "TCP" and self.dest_port_input.value() == 53:
            self.dest_port_input.setValue(443)
        self._update_interface_mode()

    def _get_selected_interface(self) -> str:
        value = self.iface_combo.currentData()
        return str(value or self.iface_combo.currentText() or "CodeOutput").strip()

    @pyqtSlot()
    def _on_send_packet(self):
        config = {
            "iface": self._get_selected_interface(),
            "route_via_codeoutput": self.route_via_codeoutput_checkbox.isChecked(),
            "ip_version": self.ip_version_combo.currentText(),
            "protocol": self.protocol_combo.currentText(),
            "target": self.target_input.text().strip(),
            "source": self.source_input.text().strip(),
            "source_port": int(self.source_port_input.value()),
            "dest_port": int(self.dest_port_input.value()),
            "tcp_flags": self.tcp_flags_input.text().strip(),
            "ttl": int(self.ttl_input.value()),
            "payload_encoding": self.payload_encoding_combo.currentText(),
            "payload": self.payload_input.toPlainText(),
            "dns_server": self.dns_server_input.text().strip(),
            "dns_name": self.dns_domain_input.text().strip(),
            "dns_type": self.dns_type_combo.currentText(),
            "dns_transport": self.dns_transport_combo.currentText(),
        }
        self.log_message(
            f"[PacketLab GUI] Queued {config['ip_version']} {config['protocol']} "
            f"target={config['dns_server'] if config['protocol'] == 'DNS' else config['target']} "
            f"via={'CodeOutput' if config['route_via_codeoutput'] else config['iface']}"
        )
        self.send_packetlab_requested.emit(config)

    # Compatibility handlers now translate into PacketLab requests.
    def _on_send_ping(self):
        self.protocol_combo.setCurrentText("ICMP")
        self._on_send_packet()

    def _on_send_tcp_syn(self):
        self.protocol_combo.setCurrentText("TCP")
        self.tcp_flags_input.setText("S")
        self._on_send_packet()

    def _on_send_udp(self):
        self.protocol_combo.setCurrentText("UDP")
        self._on_send_packet()

    def _on_send_dns(self):
        self.protocol_combo.setCurrentText("DNS")
        self._on_send_packet()

    @pyqtSlot(list)
    def populate_interfaces(self, interfaces: List[dict]):
        current = self._get_selected_interface()
        self.iface_combo.clear()
        self.iface_combo.addItem("CodeOutput", userData="CodeOutput")
        self.iface_combo.addItem("ProcessInterface", userData="ProcessInterface")
        seen = {"codeoutput", "processinterface"}
        for iface in interfaces or []:
            friendly = str(iface.get("friendly_name") or iface.get("full_name") or "").strip()
            full = str(iface.get("full_name") or friendly).strip()
            if not friendly or full.casefold() in seen:
                continue
            seen.add(full.casefold())
            self.iface_combo.addItem(friendly, userData=full)
        index = self.iface_combo.findData(current)
        if index >= 0:
            self.iface_combo.setCurrentIndex(index)
        self.iface_combo.setEnabled(not self.route_via_codeoutput_checkbox.isChecked())

    @pyqtSlot(str)
    def log_message(self, message: str):
        self.packet_log.appendPlainText(str(message))
        self.packet_log.verticalScrollBar().setValue(self.packet_log.verticalScrollBar().maximum())

