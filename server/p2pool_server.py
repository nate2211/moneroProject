# p2pool_server.py

import asyncio
import atexit
import datetime
import os
import sys
import threading
from socket import AF_INET, SOCK_DGRAM, socket

from PyQt5.QtWidgets import QApplication
from waitress import serve
from flask import Flask, send_from_directory
from flask_cors import CORS
from p2pool_data import AsyncEventLogger

# --- Import components ---
from p2pool_helper import p2pool_helper
from p2pool_endpoints import api_b
from p2pool_gui import P2PoolGUI, ConsoleLogger, NetworkLogger  # Import NetworkLogger

# === FLASK APP SETUP ===
app = Flask(__name__, static_folder='p2pool-dashboard/dist')
CORS(app)
app.register_blueprint(api_b)


@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        return send_from_directory(app.static_folder, 'index.html')


def start_flask():
    """Starts the Flask server using Waitress."""
    serve(app, host="0.0.0.0", port=5000)


def log_to_file(message):
    """A simple, dependency-free logger that writes to a file."""
    try:
        with open("p2pool.log", "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"File logging failed: {e}")


def get_local_ip():
    """Finds the primary local IP address of the machine."""
    s = socket(AF_INET, SOCK_DGRAM)
    try:
        s.connect(('10.255.255.255', 1))
        IP = s.getsockname()[0]
    except Exception:
        IP = '127.0.0.1'
    finally:
        s.close()
    return IP


async def application_main_loop(stop_event=None):
    """The main async logic for the application's background services."""
    print("[+] Initializing background services...")

    p2pool_helper.clear_all_client_data()
    p2pool_helper.clear_file_contents(p2pool_helper.p2pooldata.EVENT_LOG)
    p2pool_helper.clear_file_contents(p2pool_helper.p2pooldata.RAW_LOG)

    asyncio_main_loop = asyncio.get_running_loop()
    p2pool_helper.asyncio_main_loop = asyncio_main_loop

    async_event_logger = AsyncEventLogger(p2pool_helper.p2pooldata, asyncio_main_loop, p2pool_helper.logger)

    # Start core background threads (Web Server, etc.)
    threading.Thread(target=async_event_logger.start, daemon=True).start()
    threading.Thread(target=start_flask, daemon=True).start()

    local_ip = get_local_ip()
    port = 5000
    print("=======================================================================")
    print(f"[*] Dashboard running. Access it at:")
    print(f"    - On this machine: http://127.0.0.1:{port}")
    print(f"    - On your local network: http://{local_ip}:{port}")
    print("=======================================================================")
    print("[+] Background services are running. Use the GUI to start P2Pool.")

    try:
        # This loop now just keeps the background services alive until shutdown.
        while not (stop_event and stop_event.is_set()):
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal (Ctrl+C) received...")
    finally:
        # Signal P2Pool-related threads to stop
        p2pool_helper.p2pool_stop_event.set()
        # Stop the P2Pool process if it's running
        await p2pool_helper.processor.stop_p2pool()
        print("[+] Shutdown complete.")


def cleanup_on_exit():
    """
    This function is registered to run when the application exits.
    It ensures that all subprocesses are terminated.
    """
    print("Running final cleanup on application exit...")
    proc = p2pool_helper.p2pooldata.p2pool_proc
    if proc and proc.returncode is None:
        print(f"[atexit] Failsafe: Terminating p2pool process (PID: {proc.pid}).")
        proc.terminate()

    # Also terminate Wireshark if it's running
    wireshark_proc = p2pool_helper.wireshark_manager.tshark_proc
    if wireshark_proc and wireshark_proc.poll() is None:
        print(f"[atexit] Failsafe: Terminating Wireshark process (PID: {wireshark_proc.pid}).")
        wireshark_proc.terminate()


if __name__ == "__main__":
    try:
        atexit.register(cleanup_on_exit)
        qapp = QApplication(sys.argv)

        # Create both the main and network loggers
        gui_logger = ConsoleLogger()
        network_logger = NetworkLogger()

        # Inject both loggers into the helper
        p2pool_helper.set_gui_logger(gui_logger)
        p2pool_helper.set_network_logger(network_logger)

        # Pass the p2pool_helper instance to the GUI
        window = P2PoolGUI(gui_logger, network_logger, application_main_loop, p2pool_helper)

        window.show()
        sys.exit(qapp.exec_())
    except Exception as e:
        log_to_file(f"[FATAL] Unhandled top-level exception: {e}")
