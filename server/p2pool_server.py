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
# Import all loggers, including the new GeminiLogger
from p2pool_gui import P2PoolGUI, ConsoleLogger, WiresharkLogger, PacketLogger, RouterLogger, GeminiLogger, \
    NmapLogger, GobusterLogger, ScrapingLogger  # Ensure GeminiLogger is imported
from p2pool_managers import PythonRouterManager

# Global variable to hold references to non-Qt background threads for cleanup
# This is a simple way to manage them for atexit.
_non_qt_background_threads = []
_flask_server_instance = None  # To hold the waitress server object if needed for explicit shutdown

# === FLASK APP SETUP ===
app = Flask(__name__, static_folder='p2pool-dashboard/dist')
CORS(app)
app.register_blueprint(api_b)

router_logger = RouterLogger()  # Global instance for router logging
gui_logger = ConsoleLogger()
sys.stdout = gui_logger
sys.stderr = gui_logger
# --- Routes for serving the React frontend ---
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>')
def serve_react(path):
    # Check if the requested path corresponds to an existing file in the static folder
    # This handles direct requests for static assets like CSS, JS, images, etc.
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    else:
        # If no specific file is found, or if it's the root path, serve index.html.
        # This is crucial for Single Page Applications (SPAs) where client-side routing
        # handles different "pages" within the single index.html file.
        return send_from_directory(app.static_folder, 'index.html')

def start_flask():
    """Starts the Flask server using Waitress."""
    # The serve function from waitress runs indefinitely, serving the Flask app.
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


    p2pool_helper.set_p2pool_stop_event(stop_event)
    p2pool_helper.clear_all_client_data()
    p2pool_helper.clear_file_contents(p2pool_helper.p2pooldata.EVENT_LOG)
    p2pool_helper.clear_file_contents(p2pool_helper.p2pooldata.RAW_LOG)

    asyncio_main_loop = asyncio.get_running_loop()
    p2pool_helper.asyncio_main_loop = asyncio_main_loop

    async_event_logger = AsyncEventLogger(p2pool_helper.p2pooldata, asyncio_main_loop, p2pool_helper.logger)

    # Start and track non-Qt threads for proper cleanup
    async_event_logger_thread = threading.Thread(target=async_event_logger.start, daemon=True,
                                                 name="AsyncEventLoggerThread")
    async_event_logger_thread.start()
    _non_qt_background_threads.append(
        (async_event_logger_thread, async_event_logger))  # Store thread and its target object

    flask_thread = threading.Thread(target=start_flask, daemon=True, name="FlaskServerThread")
    flask_thread.start()
    _non_qt_background_threads.append((flask_thread, None)) # Flask target doesn't have a direct stop() method

    p2pool_helper.router_manager = PythonRouterManager(router_logger)
    p2pool_helper.set_router_logger(router_logger)
    p2pool_helper.process_manager = ProcessManager(
        p2pool_helper.p2pooldata,
        start_flask,  # This argument might be for internal process management, not the actual thread
        p2pool_helper.processor,
        p2pool_helper.logger
    )
    p2pool_helper.process_manager.start()  # This might start its own subprocesses/threads.
    # Ensure ProcessManager has its own cleanup.

    # Start the RawLogProcessor and EventProcessor threads
    raw_log_processor_thread = threading.Thread(target=p2pool_helper.raw_log_processor.run_in_background, daemon=True,
                                                name="RawLogProcessorThread")
    raw_log_processor_thread.start()
    _non_qt_background_threads.append((raw_log_processor_thread, p2pool_helper.raw_log_processor))

    event_processor_thread = threading.Thread(target=p2pool_helper.event_processor.run_in_background, daemon=True,
                                              name="EventProcessorThread")
    event_processor_thread.start()
    _non_qt_background_threads.append((event_processor_thread, p2pool_helper.event_processor))


    try:
        while not (stop_event and stop_event.is_set()):
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        print("\n[!] Shutdown signal (Ctrl+C) received...")
    finally:
        # These are now handled by cleanup_on_exit, but keeping them here
        # ensures they are called if application_main_loop exits before atexit.
        # For full robustness, ensure these managers have proper stop methods.
        p2pool_helper.router_manager.stop_routing()
        p2pool_helper.p2pool_stop_event.set()
        # This call needs to be awaited in an async context.
        # It's better to ensure `stop_p2pool` is robustly handled in cleanup_on_exit.
        # For now, keeping it as is, but noting the async context.
        await p2pool_helper.processor.stop_p2pool()
        print("[+] Async shutdown complete.")


def cleanup_on_exit():
    """
    Ensures all background services and threads are cleanly shut down on application exit.
    This function is registered with atexit.
    """
    if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
        p2pool_helper.logger.log_message("Running final cleanup on application exit...")
    else:
        print("Running final cleanup on application exit...")

    # --- Stop and join non-Qt background threads ---
    global _non_qt_background_threads
    for thread, target_obj in _non_qt_background_threads:
        if thread.is_alive():
            if target_obj and hasattr(target_obj, 'stop'):  # Check if target object has a stop method
                try:
                    target_obj.stop()
                    if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
                        p2pool_helper.logger.log_message(f"[atexit] Signaled {thread.name} to stop.")
                    else:
                        print(f"[atexit] Signaled {thread.name} to stop.")
                except Exception as e:
                    if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
                        p2pool_helper.logger.log_message(f"[atexit] Error signaling {thread.name} to stop: {e}")
                    else:
                        print(f"[atexit] Error signaling {thread.name} to stop: {e}")

            thread.join(timeout=5)  # Give thread 5 seconds to finish
            if thread.is_alive():
                if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
                    p2pool_helper.logger.log_message(
                        f"[atexit] WARNING: {thread.name} did not terminate gracefully. It might be forcefully terminated.")
                else:
                    print(
                        f"[atexit] WARNING: {thread.name} did not terminate gracefully. It might be forcefully terminated.")
        else:
            if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
                p2pool_helper.logger.log_message(f"[atexit] {thread.name} was already stopped.")
            else:
                print(f"[atexit] {thread.name} was already stopped.")

    # --- Stop P2Pool process if running ---
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
                if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
                    p2pool_helper.logger.log_message(f"[atexit] P2Pool process (PID: {proc.pid}) killed after timeout.")
                else:
                    print(f"[atexit] P2Pool process (PID: {proc.pid}) killed after timeout.")

    # --- Stop WiresharkManager ---
    if hasattr(p2pool_helper, 'wireshark_manager') and p2pool_helper.wireshark_manager:
        p2pool_helper.wireshark_manager.stop_capture()
        if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
            p2pool_helper.logger.log_message("[atexit] Wireshark capture stopped via manager.")
        else:
            print("[atexit] Wireshark capture stopped via manager.")

    # --- Stop RouterManager ---
    if hasattr(p2pool_helper, 'router_manager') and p2pool_helper.router_manager:
        p2pool_helper.router_manager.stop_routing()
        if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
            p2pool_helper.logger.log_message("[atexit] Router stopped via manager.")
        else:
            print("[atexit] Router stopped via manager.")

    # --- Final message ---
    if hasattr(p2pool_helper, 'logger') and p2pool_helper.logger:
        p2pool_helper.logger.log_message("[atexit] All background services cleanup attempted.")
    else:
        print("[atexit] All background services cleanup attempted.")


if __name__ == "__main__":
    try:
        atexit.register(cleanup_on_exit)
        qapp = QApplication(sys.argv)


        wireshark_logger = WiresharkLogger()
        packet_logger = PacketLogger()
        router_logger = RouterLogger()  # Ensure router_logger is instantiated
        gemini_logger = GeminiLogger()  # Instantiate GeminiLogger here
        nmap_logger = NmapLogger()
        scraping_logger = ScrapingLogger()
        gobuster_logger = GobusterLogger()
        # Redirect stdout/stderr to the GUI console logger


        # Set loggers in p2pool_helper
        p2pool_helper.set_gui_logger(gui_logger)
        p2pool_helper.set_wireshark_logger(wireshark_logger)
        p2pool_helper.set_packet_logger(packet_logger)
        # Note: router_logger is set via p2pool_helper.set_router_logger in application_main_loop
        # GeminiLogger is passed directly to P2PoolGUI and then to GeminiChatTab/Bot

        window = P2PoolGUI(gui_logger, wireshark_logger, packet_logger, router_logger, gemini_logger, nmap_logger, gobuster_logger, scraping_logger, application_main_loop,
                           p2pool_helper)

        window.show()
        sys.exit(qapp.exec_())
    except Exception as e:
        log_to_file(f"[FATAL] Unhandled top-level exception: {e}")