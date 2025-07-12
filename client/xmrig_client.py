
import asyncio
import ctypes
import sys
import os
from PyQt5.QtWidgets import QApplication

from xmrig_gui import MinerGui, ConsoleLogger
from xmrig_miner import XmrigMiner
from xmrig_data import XmrigData
logger = ConsoleLogger()
xmrig_data = XmrigData(logger)
xmrig_miner = XmrigMiner(xmrig_data, logger)
# How often (in seconds) to send stats to the Flask server


# Prevent system from sleeping (This is synchronous, keep as is for now at startup)
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)







async def main():


    if not os.path.exists(xmrig_data.XMRIG_PATH):
        logger.log_message(f"[!] XMRig not found at {xmrig_data.XMRIG_PATH}")
        sys.exit(1)

        # 2. Initialize the PyQt5 Application
    app = QApplication(sys.argv)

    # 3. Create the GUI, passing the logic components to it
    gui = MinerGui(xmrig_data=xmrig_data, xmrig_miner=xmrig_miner, logger=logger)

    gui.show()

    # 4. Start the application event loop
    sys.exit(app.exec_())

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.log_message("\n[!] Interrupted. Exiting.")