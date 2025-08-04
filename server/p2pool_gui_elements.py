import logging
import os
import re
import webbrowser
from typing import List, Dict
import queue
import threading
import asyncio
from urllib.parse import urljoin, urlparse, quote_plus, parse_qs

import requests
from PyQt5.QtGui import QTextCursor, QIcon, QPixmap
from PyQt5.QtWidgets import QWidget, QLineEdit, QLabel, QComboBox, QGroupBox, QFormLayout, QPushButton, QPlainTextEdit, \
    QVBoxLayout, QHBoxLayout, QTextEdit, QListWidget, QCheckBox, QTreeWidgetItem, QTreeWidget, QTabWidget, QHeaderView, \
    QGridLayout, QProgressBar, QMessageBox, QFileDialog, QSizePolicy, QMenu, QApplication, QListWidgetItem, QSpinBox
from PyQt5.QtCore import QObject, pyqtSignal, pyqtSlot, QThread, QTimer, Qt
from pygments.formatters.html import HtmlFormatter

from p2pool_managers import PacketManager, AsyncNmapManager, AsyncGobusterManager, AsyncScrapingManager
from p2pool_ai import GeminiChatBot
from pygments import highlight
from pygments.lexers import get_lexer_by_name, guess_lexer

import xml.etree.ElementTree as ET
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
        self.pygments_formatter = HtmlFormatter(noclasses=True, style="monokai", nowrap=True)

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
            try:
                lexer = get_lexer_by_name(lang) if lang else guess_lexer(code)
            except Exception:
                lexer = get_lexer_by_name("text")
            # Using <pre><code> for code blocks for better formatting and copy-pasteability
            # Added inline styles for code block appearance, and extra margin for spacing
            highlighted_code = highlight(code, lexer, self.pygments_formatter)
            formatted_response_parts.append(
                f"<div style='margin-top:10px; margin-bottom:10px;'>"  # Add vertical spacing around code block
                f"<pre style='background-color:#2a2a2a; color:#f8f8f2; padding:15px; border-radius:8px; overflow-x:auto; border:1px solid #444;'>"
                f"<div style='font-family:Consolas, Courier New, monospace; font-size:11px; white-space:pre-wrap;'>{highlighted_code}</div>"
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
        self.gemini_logger.log_message(error_message, "error")

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
            f"{prefix}{content}</div><br>"  # Add <br> outside to force newline
        )

        self.chat_output.moveCursor(QTextCursor.End)  # Always move to end before inserting
        self.chat_output.insertHtml(final_html)
        self.chat_output.insertHtml("<br>")  # Optional: extra newline
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
    A QWidget that encapsulates all UI elements and logic for the Router tab,
    including categorized console panes and log filtering based on message prefixes.
    """

    def __init__(self, logger, parent=None):
        super().__init__(parent)
        self.router_logger = logger
        self._console_panes = {}  # name → QPlainTextEdit

        self.presets = {
            "Full": ["General", "Router", "DHCP", "Transport", "Python", "Signing", "TCP/TLS/HTTPS/DNS/mDNS",
                     "Handshake", "PacketWriter", "PacketCatcher", "Notifier", "NAT/RIP/ARP/Bridge", "Firewall"],
            "Minimal": ["General"],
        }

        self._create_widgets()
        self._configure_layout()
        self._connect_signals()
        self.router_logger.message_signal.connect(self.log_message)

    def _create_widgets(self):
        self.start_router_button = QPushButton("Start Router")
        self.stop_router_button = QPushButton("Stop Router")

        self.dhcp_out_checkbox = QCheckBox("Use DHCP for OUT interface")
        self.dhcp_out_checkbox.setChecked(True)

        self.dhcp_in_checkbox = QCheckBox("Use DHCP for IN interface")
        self.dhcp_in_checkbox.setChecked(True)

        self.router_ip_in_input = QLineEdit()
        self.router_ip_in_input.setPlaceholderText("(optional)")

        self.router_netmask_in_input = QLineEdit()
        self.router_netmask_in_input.setText("255.255.255.0")  # Default netmask

        self.add_pane_input = QLineEdit()
        self.add_pane_input.setPlaceholderText("Add Pane")

        self.add_pane_button = QPushButton("➕")
        self.remove_pane_button = QPushButton("➖")

        self.console_tabs = QTabWidget()

        self.preset_dropdown = QComboBox()
        self.preset_dropdown.addItems(self.presets.keys())

        self._load_presets("Full")

    def _configure_layout(self):
        layout = QVBoxLayout(self)

        # --- Top Control Row ---
        control_layout = QHBoxLayout()
        control_layout.addWidget(self.start_router_button)
        control_layout.addWidget(self.stop_router_button)
        control_layout.addWidget(QLabel("Manual LAN IP:"))
        control_layout.addWidget(self.router_ip_in_input)
        control_layout.addWidget(QLabel("Netmask:"))
        control_layout.addWidget(self.router_netmask_in_input)
        control_layout.addWidget(self.dhcp_out_checkbox)
        control_layout.addWidget(self.dhcp_in_checkbox)
        control_layout.addStretch(1)



        # --- Pane Add/Remove Row ---
        pane_layout = QHBoxLayout()
        pane_layout.addWidget(QLabel("Pane:"))
        pane_layout.addWidget(self.add_pane_input)
        pane_layout.addWidget(self.add_pane_button)
        pane_layout.addWidget(self.remove_pane_button)
        pane_layout.addStretch(1)

        # --- Preset Dropdown Row ---
        preset_layout = QHBoxLayout()
        preset_layout.addWidget(QLabel("Presets:"))
        preset_layout.addWidget(self.preset_dropdown)
        preset_layout.addStretch(1)

        # --- Final Layout ---
        layout.addLayout(control_layout)
        layout.addLayout(pane_layout)
        layout.addLayout(preset_layout)
        layout.addWidget(self.console_tabs)

    def _connect_signals(self):
        self.start_router_button.clicked.connect(self._on_start_router)
        self.add_pane_button.clicked.connect(self._on_add_pane)
        self.remove_pane_button.clicked.connect(self._on_remove_pane)
        self.preset_dropdown.currentTextChanged.connect(self._on_preset_selected)

    def _load_presets(self, preset_name: str):
        panes_to_add = self.presets.get(preset_name, [])

        # Remove all non-General panes
        for pane in list(self._console_panes):
            if pane != "General":
                self._remove_console_pane(pane)

        # Add new panes
        for pane in panes_to_add:
            self._add_console_pane(pane)

    def _on_preset_selected(self, preset_name: str):
        self._load_presets(preset_name)

    def _add_console_pane(self, name: str):
        if name not in self._console_panes:
            console = QPlainTextEdit()
            console.setReadOnly(True)
            self.console_tabs.addTab(console, name)
            self._console_panes[name] = console

    def _remove_console_pane(self, name: str):
        if name in self._console_panes and name != "General":
            index = self.console_tabs.indexOf(self._console_panes[name])
            self.console_tabs.removeTab(index)
            del self._console_panes[name]

    def _on_add_pane(self):
        name = self.add_pane_input.text().strip()
        if name:
            self._add_console_pane(name)
            self._log("General", f"[UI] Added pane: {name}")
            self.add_pane_input.clear()

    def _on_remove_pane(self):
        name = self.add_pane_input.text().strip()
        if name:
            self._remove_console_pane(name)
            self._log("General", f"[UI] Removed pane: {name}")
            self.add_pane_input.clear()

    def _on_start_router(self):
        self.start_router_button.setEnabled(False)
        self.stop_router_button.setEnabled(True)
        self._log("General", "Router started!")

    @pyqtSlot(str)
    def log_message(self, message: str):
        """
        Routes log messages to a pane based on the prefix. If no matching pane, logs to 'General'.
        """
        prefixes = re.findall(r'\[(.*?)\]', message)


        target_pane = None
        longest_prefix_len = 1000

        # Find the best possible match by checking all prefixes against all keys
        for prefix in reversed(prefixes):
            for pane_key in self._console_panes:
                cleaned_pane_key = re.sub(r'[^a-zA-Z0-9\s]', '', pane_key)
                # Check if the prefix is a substring of the key
                if prefix.lower() in cleaned_pane_key.lower():
                    # If this prefix is longer than our previous best match, it's the new best one.
                    if len(prefix) < longest_prefix_len:
                        longest_prefix_len = len(prefix)
                        target_pane = pane_key

        self._log(target_pane or "General", message)

    def _log(self, category: str, message: str):
        if category in self._console_panes:
            self._console_panes[category].appendPlainText(message)
        else:
            if "General" not in self._console_panes:
                self._add_console_pane("General")
            self._console_panes["General"].appendPlainText(message)



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