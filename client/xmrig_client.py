import sys
import os
import ctypes
import traceback
import signal

from PyQt5.QtWidgets import QApplication, QMessageBox

from xmrig_gui import MinerGui, ConsoleLogger
from xmrig_miner import XmrigMiner
from xmrig_data import XmrigData

# Prevent system from sleeping on Windows
if os.name == 'nt':
    ES_CONTINUOUS = 0x80000000
    ES_SYSTEM_REQUIRED = 0x00000001
    ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)

# Initialize core components
logger = ConsoleLogger()
xmrig_data = XmrigData(logger)
xmrig_miner = XmrigMiner(xmrig_data, logger)


def main():
    """Main function to initialize and run the application."""
    app = QApplication(sys.argv)

    gui = MinerGui(xmrig_data=xmrig_data, xmrig_miner=xmrig_miner, logger=logger)
    gui.show()

    # Graceful shutdown for Ctrl+C in console
    signal.signal(signal.SIGINT, signal.SIG_DFL)

    sys.exit(app.exec_())


# Top-level exception handler to catch critical errors on startup
if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        # Format the exception traceback
        error_msg = ''.join(traceback.format_exception(type(e), e, e.__traceback__))
        print(f"[!] Fatal startup crash:\n{error_msg}")

        # Try to log the crash to a file
        try:
            with open("fatal_boot_crash.log", "w", encoding="utf-8") as f:
                f.write(error_msg)
        except IOError:
            pass  # Can't write the log file

        # Display a critical error message box to the user
        QMessageBox.critical(None, "Fatal Crash", "An unrecoverable error occurred on startup.\n"
                                                  "Please see fatal_boot_crash.log for details.")
        sys.exit(1)