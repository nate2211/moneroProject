# p2pool_server.py

import asyncio
import atexit
import datetime
import os
import subprocess
import sys
import threading
from PyQt5.QtWidgets import QApplication
from waitress import serve
from flask import Flask, send_from_directory
from flask_cors import CORS
from p2pool_data import AsyncEventLogger

# --- Import components ---
from p2pool_helper import p2pool_helper, ProcessManager
from p2pool_endpoints import api_b
from p2pool_gui import P2PoolGUI, ConsoleLogger, WiresharkLogger, PacketLogger, RouterLogger  # Import NetworkLogger
from p2pool_managers import PythonRouterManager

# === FLASK APP SETUP ===
app = Flask(__name__, static_folder='p2pool-dashboard/dist')
CORS(app)
app.register_blueprint(api_b)

router_logger = RouterLogger()

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



async def application_main_loop(stop_event=None):
    """The main async logic for the application's background services."""
    print("[+] Initializing background services...")

    p2pool_helper.clear_all_client_data()
    p2pool_helper.clear_file_contents(p2pool_helper.p2pooldata.EVENT_LOG)
    p2pool_helper.clear_file_contents(p2pool_helper.p2pooldata.RAW_LOG)

    asyncio_main_loop = asyncio.get_running_loop()
    p2pool_helper.asyncio_main_loop = asyncio_main_loop

    async_event_logger = AsyncEventLogger(p2pool_helper.p2pooldata, asyncio_main_loop, p2pool_helper.logger)

    threading.Thread(target=async_event_logger.start, daemon=True).start()
    threading.Thread(target=start_flask, daemon=True).start()
    p2pool_helper.router_manager = PythonRouterManager(router_logger)
    p2pool_helper.set_router_logger(router_logger)
    p2pool_helper.process_manager = ProcessManager(
        p2pool_helper.p2pooldata,
        start_flask,
        p2pool_helper.processor,
        p2pool_helper.logger
    )
    p2pool_helper.process_manager.start()
    local_ip = p2pool_helper.get_local_ip()
    public_ip_at_start = p2pool_helper.get_public_ip()
    port = 5000
    print("=======================================================================")
    print(f"[*] Dashboard running. Access it at:")
    print(f"    - On this machine: http://127.0.0.1:{port}")
    print(f"    - On your local network: http://{local_ip}:{port}")
    if public_ip_at_start:
        print(f"    - On the internet (if port forwarded): http://{public_ip_at_start}:{port}")
    print("=======================================================================")
    print("[+] Background services are running. Use the GUI to start P2Pool.")

    try:
        while not (stop_event and stop_event.is_set()):
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal (Ctrl+C) received...")
    finally:
        p2pool_helper.router_manager.stop_routing()
        p2pool_helper.p2pool_stop_event.set()
        await p2pool_helper.processor.stop_p2pool()
        print("[+] Shutdown complete.")


def cleanup_on_exit():
    # Use p2pool_helper.logger for consistency
    if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
        p2pool_helper.logger.log_message("Running final cleanup on application exit...")
    else:
        print("Running final cleanup on application exit...")

    if hasattr(p2pool_helper, 'p2pooldata') and p2pool_helper.p2pooldata and p2pool_helper.p2pooldata.p2pool_proc:
        proc = p2pool_helper.p2pooldata.p2pool_proc
        if proc and proc.returncode is None:
            if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
                p2pool_helper.logger.log_message(f"[atexit] Failsafe: Terminating p2pool process (PID: {proc.pid}).")
            else:
                print(f"[atexit] Failsafe: Terminating p2pool process (PID: {proc.pid}).")
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()

    # Correctly stop WiresharkManager by calling its method
    if hasattr(p2pool_helper, 'wireshark_manager') and p2pool_helper.wireshark_manager:
        p2pool_helper.wireshark_manager.stop_capture()
        if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
            p2pool_helper.logger.log_message("[atexit] Wireshark capture stopped via manager.")
        else:
            print("[atexit] Wireshark capture stopped via manager.")


if __name__ == "__main__":
    try:
        atexit.register(cleanup_on_exit)
        qapp = QApplication(sys.argv)

        gui_logger = ConsoleLogger()
        wireshark_logger = WiresharkLogger()
        packet_logger = PacketLogger()
        sys.stdout = gui_logger
        sys.stderr = gui_logger
        p2pool_helper.set_gui_logger(gui_logger)
        p2pool_helper.set_wireshark_logger(wireshark_logger)
        p2pool_helper.set_packet_logger(packet_logger)
        window = P2PoolGUI(gui_logger, wireshark_logger, packet_logger, router_logger, application_main_loop, p2pool_helper)

        window.show()
        sys.exit(qapp.exec_())
    except Exception as e:
        log_to_file(f"[FATAL] Unhandled top-level exception: {e}")
