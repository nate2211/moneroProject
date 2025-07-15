import os
import sys
import subprocess
import threading
import queue
import datetime
import re
import time
from collections import deque


class RawLogProcessor:
    """
    Tails the raw P2Pool log file, parses its output, and queues structured
    events to be written to the main event log by the log_writer.
    """

    def __init__(self, p2pooldata_instance):
        """
        Initializes the raw log processor.

        Args:
            p2pooldata_instance (P2poolData): The main data object.
        """
        self.p2pool_data = p2pooldata_instance

    def run_in_background(self):
        """
        The main loop for this thread. Tails the raw P2Pool log file continuously.
        """
        raw_log_path = self.p2pool_data.RAW_LOG
        print(f"[*] RawLogProcessor thread started. Tailing: {raw_log_path}")

        while not os.path.exists(raw_log_path):
            print("[!] Raw log file does not exist yet, waiting...")
            time.sleep(2)

        try:
            with open(raw_log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)
                miner_data_block = []
                in_miner_data = False

                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)  # Wait for new content
                        continue

                    clean_line = line.strip()
                    if not clean_line:
                        continue

                    lower_line = clean_line.lower()

                    if "p2pool new miner data" in lower_line:
                        in_miner_data = True
                        miner_data_block = [clean_line]
                        continue

                    if in_miner_data:
                        if clean_line == "" or clean_line.startswith("-"):
                            full_block = "\n".join(miner_data_block).strip()
                            self.p2pool_data.log_event_now("New Miner Data", full_block)
                            in_miner_data = False
                        else:
                            miner_data_block.append(clean_line)
                        continue

                    if "sent new job" in lower_line:
                        self.p2pool_data.log_event_now("Sent Jobs", clean_line)
                    elif "share found" in lower_line:
                        self.p2pool_data.log_event_now("Found Share", clean_line)
                    elif "block found" in lower_line:
                        self.p2pool_data.log_event_now("Found Block", clean_line)
                    elif "sidechain add_block" in lower_line:
                        self.p2pool_data.log_event_now("Sidechain Block Added", clean_line)
                    elif "p2pool caught sigint" in lower_line or "p2pool stopping" in lower_line:
                        self.p2pool_data.log_event_now("P2Pool Stopped", clean_line)

        except Exception as e:
            error_msg = f"RawLogProcessor thread terminated with error: {e}"
            print(f"[!] {error_msg}")
            self.p2pool_data.log_event_now("RawLogProcessor Error", error_msg)


class EventProcessor:
    """
    Tails the event log file in a background thread, parsing and categorizing
    events into in-memory deques for fast API access.
    """
    def __init__(self, P2poolData, max_events_per_category=50):
        """
        Initializes the event processor.

        Args:
            p2pooldata_instance (P2poolData): The main data object.
            max_events_per_category (int): Max number of events to keep for each category.
        """
        self.p2pool_data = P2poolData
        self.max_events = max_events_per_category
        self.lock = threading.Lock()

        # Use deque with maxlen for efficient, automatically capped lists
        self.shares_found = deque(maxlen=self.max_events)
        self.jobs_sent = deque(maxlen=self.max_events)
        self.miner_data = deque(maxlen=self.max_events)
        self.blocks_found = deque(maxlen=self.max_events)
        self.other_events = deque(maxlen=self.max_events)

    def _parse_and_categorize_line(self, line):
        """Parses a single log line and adds it to the correct category deque."""
        match = re.match(r"\[(.*?)\] \[(.*?)\] (.*)", line, re.DOTALL)
        if not match:
            return

        event = {
            "time": match.group(1),
            "type": match.group(2),
            "message": match.group(3).strip()
        }

        # Use a lock to ensure thread-safe writes to the deques
        with self.lock:
            event_type = event["type"]
            if event_type == "Found Share":
                self.shares_found.appendleft(event)
            elif event_type == "Sent Jobs":
                self.jobs_sent.appendleft(event)
            elif event_type == "New Miner Data":
                self.miner_data.appendleft(event)
            elif event_type == "Found Block":
                self.blocks_found.appendleft(event)
            else:
                self.other_events.appendleft(event)

    def run_in_background(self):
        """
        The main loop for this thread. Tails the event log file continuously.
        """
        event_log_path = self.p2pool_data.EVENT_LOG
        print(f"[*] EventProcessor thread started. Tailing: {event_log_path}")

        while not os.path.exists(event_log_path):
            print("[!] Event log does not exist yet, waiting...")
            time.sleep(2)

        try:
            with open(event_log_path, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)  # Start at the end of the file
                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.2)  # No new lines, wait a bit
                        continue
                    self._parse_and_categorize_line(line)
        except Exception as e:
            error_msg = f"EventProcessor thread terminated with error: {e}"
            print(f"[!] {error_msg}")
            self.p2pool_data.log_event_now("EventProcessor Error", error_msg)

    def get_all_events(self, limit=10):
        """Returns a snapshot of the current events for the API."""
        with self.lock:
            return {
                "shares_found": list(self.shares_found)[:limit],
                "jobs_sent": list(self.jobs_sent)[:limit],
                "miner_data": list(self.miner_data)[:limit],
                "blocks_found": list(self.blocks_found)[:limit],
                "other_events": list(self.other_events)[:limit]
            }


class P2poolData:

    def __init__(self):
        self.P2POOL_DIR = os.path.dirname(sys.executable)
        self.P2POOL_EXE = "p2pool.exe"
        self.WALLET = "46NctiVJGQgRPoFq84xqZkhQTbrkPnp9KGpcewpKQkyoMu3FsQifcWdRT5RdUoH9QsBUxUPowGUw7Ns44RCRByWwPCBkmgk"
        self.p2pool_proc = None
        self.p2pool_status_output = {"message": "P2Pool status not yet available."}  # Initialize with a message
        self.EVENT_LOG = os.path.join(self.P2POOL_DIR, "event_log.txt")
        self.RAW_LOG = os.path.join(self.P2POOL_DIR, "p2pool_raw_output.txt")
        self.log_queue = queue.Queue()

    def start_p2pool_direct(self):

        exe_path = os.path.join(self.P2POOL_DIR, self.P2POOL_EXE)
        if not os.path.exists(exe_path):
            print(f"[!] Executable not found at: {exe_path}")
            return None

        args = [
            exe_path, "--host", "127.0.0.1", "--wallet", self.WALLET,
            "--mini", "--stratum", "192.168.0.10:3333", "--no-upnp", "--no-color", "--p2p", "0.0.0.0:37888"
        ]

        try:
            self.p2pool_proc = subprocess.Popen(
                args,
                cwd=self.P2POOL_DIR,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1
            )

            def redirect_output(proc):
                # 'a' mode creates the file if it doesn't exist
                with open(self.RAW_LOG, "a", encoding="utf-8") as log_file:
                    for line in proc.stdout:
                        try:
                            clean_line = self.strip_ansi_codes(line.strip())
                            log_file.write(clean_line + "\n")
                            log_file.flush()
                            print("[P2Pool]", clean_line)
                        except Exception as e:
                            self.log_event_now("P2pool Process", "Failed to redirect output to log file")
                # Log that the process ended, if this function exits
                self.log_event_now("P2Pool Process", "P2Pool stdout stream ended.")

            threading.Thread(target=redirect_output, args=(self.p2pool_proc,), daemon=True).start()
            return True
        except Exception as e:
            print(f"[!] Failed to launch P2Pool: {e}")
            return False

    # In the P2poolData class
    def handle_user_input(self, proc):
        """
        Waits for user input in a dedicated thread and forwards it to the p2pool process.
        """
        while proc.poll() is None:  # Loop only while the process is running
            try:
                user_input = input()
                if proc.poll() is None:  # Check again before writing
                    proc.stdin.write(user_input + '\n')
                    proc.stdin.flush()
                else:
                    break  # Exit loop if process has stopped
            except (IOError, OSError, ValueError):
                break
            except Exception as e:
                break

    def time_ago(self, timestamp):
        """Converts a Unix timestamp into a 'time ago' string."""
        now = datetime.datetime.now()
        dt = datetime.datetime.fromtimestamp(timestamp)
        diff = now - dt

        seconds = diff.total_seconds()

        if seconds < 60:
            return f"{int(seconds)} seconds ago"
        elif seconds < 3600:
            minutes = int(seconds / 60)
            return f"{minutes} minute{'s' if minutes > 1 else ''} ago"
        elif seconds < 86400:
            hours = int(seconds / 3600)
            return f"{hours} hour{'s' if hours > 1 else ''} ago"
        else:
            days = int(seconds / 86400)
            return f"{days} day{'s' if days > 1 else ''} ago"

    def log_writer(self, ):
        """
        Waits for log entries in the queue and writes them to the event log file.
        This function will block efficiently until a log is available.
        """
        with open(self.EVENT_LOG, "a", encoding="utf-8") as evlog:
            while True:
                try:
                    # block=True makes it wait indefinitely until an item is available.
                    # This is more efficient than polling with a timeout.
                    log_entry = self.log_queue.get(block=True)
                    evlog.write(log_entry + "\n")
                    evlog.flush()
                except Exception as e:
                    # Log an error if writing fails for some reason
                    print(f"[!] Log writer failed: {e}")

    def strip_ansi_codes(self, text):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    def log_event_now(self, event_type, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"[{timestamp}] [{event_type}] {message}")