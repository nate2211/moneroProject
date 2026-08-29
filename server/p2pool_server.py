from __future__ import annotations

import asyncio
import atexit
import ctypes
import datetime
import multiprocessing
import os
import subprocess
import sys
import threading
from typing import Optional

from PyQt5.QtWidgets import QApplication
from flask import Flask, send_from_directory
from flask_cors import CORS
from waitress import serve

from p2pool_data import AsyncEventLogger
from p2pool_endpoints import api_b
from p2pool_gui import (
    P2PoolGUI,
    ConsoleLogger,
    WiresharkLogger,
    PacketLogger,
    RouterLogger,
    GeminiLogger,
    NmapLogger,
    GobusterLogger,
    ScrapingLogger,
)
from p2pool_helper import p2pool_helper
from p2pool_managers import PythonRouterManager
from p2pool_managers import PacketManager

_non_qt_background_threads: list[threading.Thread] = []
_flask_thread: Optional[threading.Thread] = None
_async_event_logger: Optional[AsyncEventLogger] = None

app = Flask(__name__, static_folder="p2pool-dashboard/dist")
CORS(app)
app.register_blueprint(api_b)

router_logger = RouterLogger()
gui_logger = ConsoleLogger()
sys.stdout = gui_logger
sys.stderr = gui_logger


@app.route("/", defaults={"path": ""})
@app.route("/<path:path>")
def serve_react(path):
    if path != "" and os.path.exists(os.path.join(app.static_folder, path)):
        return send_from_directory(app.static_folder, path)
    return send_from_directory(app.static_folder, "index.html")


def start_flask():
    """
    Run Flask/Waitress in-process so the API shares the same live p2pool_helper
    state as the GUI and background managers.
    """
    serve(app, host="0.0.0.0", port=5000, threads=8)


def ensure_flask_thread_started():
    global _flask_thread

    if _flask_thread is not None and _flask_thread.is_alive():
        return

    _flask_thread = threading.Thread(
        target=start_flask,
        daemon=True,
        name="FlaskServerThread",
    )
    _flask_thread.start()
    _non_qt_background_threads.append(_flask_thread)

    if getattr(p2pool_helper, "logger", None):
        p2pool_helper.logger.log_message("[Main] Flask server thread started.")


def ensure_background_thread(target, name: str) -> Optional[threading.Thread]:
    for thread in _non_qt_background_threads:
        if thread.name == name and thread.is_alive():
            return thread

    thread = threading.Thread(target=target, daemon=True, name=name)
    thread.start()
    _non_qt_background_threads.append(thread)
    return thread


def log_to_file(message):
    try:
        with open("p2pool.log", "a", encoding="utf-8") as f:
            timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
            f.write(f"[{timestamp}] {message}\n")
    except Exception as e:
        print(f"File logging failed: {e}")


async def application_main_loop(stop_event=None):
    """
    Main async logic for the application's background services.

    Important:
      - Flask/API starts
      - background log/event workers start
      - ProcessManager starts watching IP transitions
      - P2Pool itself does NOT auto-start here
    """
    global _async_event_logger

    if stop_event is None:
        stop_event = threading.Event()

    p2pool_helper.set_p2pool_stop_event(stop_event)
    p2pool_helper.clear_all_client_data()
    p2pool_helper.clear_file_contents(p2pool_helper.p2pooldata.EVENT_LOG)
    p2pool_helper.clear_file_contents(p2pool_helper.p2pooldata.RAW_LOG)

    asyncio_main_loop = asyncio.get_running_loop()
    p2pool_helper.set_asyncio_main_loop(asyncio_main_loop)

    _async_event_logger = AsyncEventLogger(
        p2pool_helper.p2pooldata,
        asyncio_main_loop,
        p2pool_helper.logger,
        stop_event=stop_event,
    )
    _async_event_logger.start()

    ensure_flask_thread_started()

    # Router construction is optional to the rest of the application startup.
    # A native helper or packet-analysis mismatch must not kill the asyncio worker
    # and permanently leave the GUI with "Router manager not available."
    p2pool_helper.set_router_logger(router_logger)
    router_manager = p2pool_helper.ensure_router_manager(router_logger)
    if router_manager is None:
        status = p2pool_helper.router_manager_status()
        p2pool_helper.logger.log_message(
            "[Main] ⚠️ Router manager is not ready yet; the GUI Start Router "
            f"worker may retry initialization. Last error: {status.get('last_error') or 'unknown'}"
        )

    p2pool_helper.create_process_manager(
        flask_restart_callback=None,
        asyncio_main_loop=asyncio_main_loop,
    )
    p2pool_helper.process_manager.start()

    ensure_background_thread(
        p2pool_helper.raw_log_processor.run_in_background,
        "RawLogProcessorThread",
    )
    ensure_background_thread(
        p2pool_helper.event_processor.run_in_background,
        "EventProcessorThread",
    )

    p2pool_helper.logger.log_message("[Main] Background services started. P2Pool will not auto-start.")

    try:
        while not stop_event.is_set():
            await asyncio.sleep(1)
    except KeyboardInterrupt:
        p2pool_helper.logger.log_message("[Main] Shutdown signal received.")
    finally:
        p2pool_helper.logger.log_message("[Main] Beginning async shutdown...")

        try:
            if p2pool_helper.process_manager is not None:
                p2pool_helper.process_manager.stop()
        except Exception as e:
            p2pool_helper.logger.log_message(f"[Main] ProcessManager stop error: {e}")

        try:
            stop_event.set()
            p2pool_helper.p2pool_stop_event.set()
        except Exception:
            pass

        try:
            if p2pool_helper.router_manager is not None:
                shutdown = getattr(p2pool_helper.router_manager, "shutdown", None)
                if callable(shutdown):
                    shutdown(final=True)
                else:
                    p2pool_helper.router_manager.stop_routing()
        except Exception as e:
            p2pool_helper.logger.log_message(f"[Main] Router shutdown error: {e}")

        try:
            await p2pool_helper.processor.stop_p2pool(reason="application_shutdown")
        except Exception as e:
            p2pool_helper.logger.log_message(f"[Main] P2Pool shutdown error: {e}")

        try:
            if _async_event_logger is not None:
                _async_event_logger.stop()
        except Exception as e:
            p2pool_helper.logger.log_message(f"[Main] AsyncEventLogger stop error: {e}")

        p2pool_helper.logger.log_message("[Main] Async shutdown complete.")


def cleanup_on_exit():
    logger = getattr(p2pool_helper, "logger", None)
    if logger:
        logger.log_message("[atexit] Running final cleanup on application exit...")
    else:
        print("[atexit] Running final cleanup on application exit...")

    try:
        p2pool_helper.p2pool_stop_event.set()
    except Exception:
        pass

    try:
        if p2pool_helper.process_manager is not None:
            p2pool_helper.process_manager.stop()
    except Exception as e:
        if logger:
            logger.log_message(f"[atexit] ProcessManager stop error: {e}")

    try:
        if p2pool_helper.wireshark_manager is not None:
            p2pool_helper.wireshark_manager.stop_capture()
    except Exception as e:
        if logger:
            logger.log_message(f"[atexit] Wireshark stop error: {e}")

    try:
        if p2pool_helper.router_manager is not None:
            shutdown = getattr(p2pool_helper.router_manager, "shutdown", None)
            if callable(shutdown):
                shutdown(final=True)
            else:
                p2pool_helper.router_manager.stop_routing()
    except Exception as e:
        if logger:
            logger.log_message(f"[atexit] Router stop error: {e}")

    try:
        if _async_event_logger is not None:
            _async_event_logger.stop()
    except Exception as e:
        if logger:
            logger.log_message(f"[atexit] AsyncEventLogger stop error: {e}")

    proc = None
    try:
        proc = p2pool_helper.p2pooldata.p2pool_proc
    except Exception:
        proc = None

    if proc and proc.returncode is None:
        try:
            if logger:
                logger.log_message(f"[atexit] Failsafe: terminating P2Pool process PID {proc.pid}.")
            proc.terminate()
        except Exception:
            pass

        try:
            import psutil
            psutil.Process(proc.pid).wait(timeout=5)
        except Exception:
            try:
                proc.kill()
            except Exception:
                pass

    for thread in _non_qt_background_threads:
        if thread.is_alive() and thread.name != "FlaskServerThread":
            thread.join(timeout=2)

    if logger:
        logger.log_message("[atexit] Cleanup attempted.")

def is_admin() -> bool:
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def relaunch_as_admin() -> bool:
    """
    Relaunch the current program elevated on Windows.
    Returns True if an elevation request was launched.
    Returns False if launch failed.
    """
    try:
        if os.name != "nt":
            return False

        # Prevent accidental relaunch loops
        if os.environ.get("P2POOL_ELEVATED_RELAUNCH") == "1":
            return False

        params = sys.argv[:]

        if getattr(sys, "frozen", False):
            # PyInstaller / frozen exe
            exe = sys.executable
            arg_str = subprocess.list2cmdline(params[1:])
        else:
            # Running from python script
            exe = sys.executable
            arg_str = subprocess.list2cmdline(params)

        env_flag = "set P2POOL_ELEVATED_RELAUNCH=1 && "
        cmd = f'/c {env_flag}"{exe}" {arg_str}'

        rc = ctypes.windll.shell32.ShellExecuteW(
            None,
            "runas",
            "cmd.exe",
            cmd,
            os.getcwd(),
            1,
        )

        return rc > 32
    except Exception as e:
        log_to_file(f"[FATAL] Elevation relaunch failed: {e}")
        return False


def ensure_admin_or_relaunch() -> None:
    if is_admin():
        return

    launched = relaunch_as_admin()
    if launched:
        sys.exit(0)

    raise RuntimeError("Administrator privileges are required, and elevation was cancelled or failed.")

if __name__ == "__main__":
    try:
        multiprocessing.freeze_support()
        atexit.register(cleanup_on_exit)

        qapp = QApplication(sys.argv)

        wireshark_logger = WiresharkLogger()
        packet_logger = PacketLogger()
        router_logger = RouterLogger()
        gemini_logger = GeminiLogger()
        nmap_logger = NmapLogger()
        gobuster_logger = GobusterLogger()
        scraping_logger = ScrapingLogger()

        p2pool_helper.set_gui_logger(gui_logger)
        p2pool_helper.set_wireshark_logger(wireshark_logger)
        p2pool_helper.set_packet_logger(packet_logger)

        window = P2PoolGUI(
            gui_logger,
            wireshark_logger,
            packet_logger,
            router_logger,
            gemini_logger,
            nmap_logger,
            gobuster_logger,
            scraping_logger,
            application_main_loop,
            p2pool_helper,
        )
        window.show()
        sys.exit(qapp.exec_())

    except Exception as e:
        log_to_file(f"[FATAL] Unhandled top-level exception: {e}")
        raise