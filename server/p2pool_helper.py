# p2pool_helper.py

import threading
from p2pool_data import P2poolData, EventProcessor, RawLogProcessor, P2PoolProcessor
from client_data import ClientData
from p2pool_managers import WiresharkManager  # Import the new manager


class _PrintLogger:
    """A simple, GUI-agnostic fallback logger that uses the standard print() function."""

    def log_message(self, msg):
        print(str(msg))


class _PrintNetworkLogger:
    """A fallback logger specifically for network messages."""

    def log_message(self, msg):
        # Add a prefix to distinguish network logs in the console before the GUI is ready
        print(f"[Net] {str(msg)}")


class P2PoolHelper:
    def __init__(self):
        # --- Constants and State ---
        self.ELECTRICITY_RATE_PER_KWH = 0.13
        self.COMMAND_QUEUE = {}
        self.asyncio_main_loop = None

        # --- Instantiate with safe, temporary loggers FIRST ---
        self.logger = _PrintLogger()
        self.network_logger = _PrintNetworkLogger()

        # Event to signal P2Pool-related threads to stop
        self.p2pool_stop_event = threading.Event()

        # --- Pass the appropriate loggers to all child classes ---
        self.p2pooldata = P2poolData(self.logger)
        self.clientdata = ClientData(self.logger)
        self.event_processor = EventProcessor(self.p2pooldata, self.logger, self.p2pool_stop_event)
        self.raw_log_processor = RawLogProcessor(self.p2pooldata, self.logger, self.p2pool_stop_event)
        self.processor = P2PoolProcessor(self.p2pooldata, self.logger)

        # --- Pass the dedicated network logger to the Wireshark Manager ---
        self.wireshark_manager = WiresharkManager(self.p2pooldata, self.network_logger)

    def set_gui_logger(self, gui_logger):
        """Replaces the temporary main logger with the real GUI logger."""
        print("[+] GUI Logger activated.")
        self.logger = gui_logger
        # Propagate the real logger to all relevant child objects
        self.p2pooldata.logger = gui_logger
        self.clientdata.logger = gui_logger
        self.event_processor.logger = gui_logger
        self.raw_log_processor.logger = gui_logger
        self.processor.logger = gui_logger

    def set_network_logger(self, network_logger):
        """Replaces the temporary network logger with the real GUI network logger."""
        print("[+] GUI Network Logger activated.")
        self.network_logger = network_logger
        # Propagate the real network logger to the Wireshark Manager
        self.wireshark_manager.logger = network_logger

    def queue_command(self, client_id, command_data):
        if client_id not in self.COMMAND_QUEUE:
            self.COMMAND_QUEUE[client_id] = []
        self.COMMAND_QUEUE[client_id].append(command_data)
        self.logger.log_message(f"[+] Queued command for '{client_id}': {command_data}")

    def clear_file_contents(self, filepath):
        try:
            with open(filepath, 'w', encoding='utf-8') as f:
                f.truncate(0)
            self.logger.log_message(f"[+] Cleared contents of: {filepath}")
        except Exception as e:
            self.logger.log_message(f"[!] Error clearing file {filepath}: {e}")

    def clear_all_client_data(self):
        self.logger.log_message("[!] Clearing all existing client data on startup...")
        self.clientdata.client_hashrates.clear()
        self.clientdata.client_newjobs.clear()
        self.clientdata.client_costs.clear()
        self.COMMAND_QUEUE.clear()
        self.p2pooldata.log_event_now("System Startup", "All client data cleared.")
        self.logger.log_message("[+] Client data cleared successfully.")


# Create a single, importable instance of the now-independent helper
p2pool_helper = P2PoolHelper()
