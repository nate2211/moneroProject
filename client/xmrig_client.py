import multiprocessing
import sys
import os
import ctypes
import traceback
import signal
from datetime import datetime

from xmrig_managers import WinRingManager

# ==============================================================================
#  SIMPLE FILE LOGGER FOR STARTUP DEBUGGING
# ==============================================================================
LOG_FILE = "startup_debug.log"
# Clear the log file at the start of each run
if os.path.exists(LOG_FILE):
    os.remove(LOG_FILE)


def log_to_file(message):
    """A simple, dependency-free logger that writes to a file."""
    try:
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        # If logging itself fails, we can't do much, but we try.
        with open(LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[!!!] LOGGING FAILED: {e}\n")


# ==============================================================================
#  MODIFIED STARTUP SEQUENCE
# ==============================================================================
log_to_file("--- Application Starting ---")
log_to_file("Step 1: Initial imports processed.")

# Import your modules AFTER setting up the logger
try:
    from PyQt5.QtWidgets import QApplication, QMessageBox

    log_to_file("Step 2: PyQt5 imported successfully.")

    from xmrig_gui import MinerGui, ConsoleLogger, NetworkLogger, LinuxLogger

    log_to_file("Step 3: xmrig_gui imported successfully.")

    from xmrig_miner import XmrigMiner

    log_to_file("Step 4: xmrig_miner imported successfully.")

    from xmrig_data import XmrigData
    log_to_file("Step 5: xmrig_data imported successfully.")

except Exception as import_error:
    log_to_file(f"[!!!] FATAL IMPORT ERROR: {import_error}")
    log_to_file(''.join(traceback.format_exception(type(import_error), import_error, import_error.__traceback__)))
    sys.exit(1)

# Prevent system from sleeping on Windows
if os.name == 'nt':
    log_to_file("Step 6: Configuring Windows sleep prevention.")
    ES_CONTINUOUS = 0x80000000
    ES_SYSTEM_REQUIRED = 0x00000001
    ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)
    log_to_file("Step 7: Windows sleep prevention set.")

# Initialize core components
logger = None
xmrig_data = None
xmrig_miner = None


def main():
    """Main function to initialize and run the application."""
    global logger, xmrig_data, xmrig_miner  # Make sure we're using the globally defined instances

    log_to_file("Step 8: main() function started.")
    app = QApplication(sys.argv)
    app.setQuitOnLastWindowClosed(False)
    log_to_file("Step 9: QApplication initialized.")

    # We now initialize components inside main() after QApplication is up
    logger = ConsoleLogger()
    network_logger = NetworkLogger()
    linux_logger = LinuxLogger()
    log_to_file("Step 10: ConsoleLogger, NetworkLogger and LinuxLogger initialized.")

    xmrig_data = XmrigData(logger)

    log_to_file("Step 11: XmrigData initialized.")

    xmrig_miner = XmrigMiner(xmrig_data, logger)
    log_to_file("Step 13: XmrigMiner initialized.")

    log_to_file("Step 14: Starting HardwareMonitor thread...")
    xmrig_data.hardware_monitor.start()
    log_to_file("Step 15: HardwareMonitor thread started.")

    gui = MinerGui(xmrig_data=xmrig_data, xmrig_miner=xmrig_miner, logger=logger, network_logger=network_logger, linux_logger=linux_logger)
    log_to_file("Step 16: MinerGui initialized.")
    gui.show()
    log_to_file("Step 17: GUI shown. Entering event loop.")


    xmrig_data.winring_manager = WinRingManager(os.path.join(xmrig_data.tools_dir, "WinRing0x64.sys"), logger)
    # Graceful shutdown for Ctrl+C in console
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    sys.exit(app.exec_())


# Top-level exception handler to catch critical errors on startup
if __name__ == "__main__":
    try:
        multiprocessing.freeze_support()
        main()
    except Exception as e:
        # Format the exception traceback
        error_msg = ''.join(traceback.format_exception(type(e), e, e.__traceback__))
        log_to_file(f"[!!!] FATAL STARTUP CRASH in __main__:\n{error_msg}")

        if xmrig_data and xmrig_data.hardware_monitor:
            xmrig_data.hardware_monitor.deinitialize()

        # Try to log the crash to a file (redundant but safe)
        try:
            with open("fatal_boot_crash.log", "w", encoding="utf-8") as f:
                f.write(error_msg)
        except IOError:
            pass

        # Display a critical error message box to the user
        QMessageBox.critical(None, "Fatal Crash", "An unrecoverable error occurred on startup.\n"
                                                  "Please see fatal_boot_crash.log and startup_debug.log for details.")
        sys.exit(1)