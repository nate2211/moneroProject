import os
import sys
import subprocess
import threading
import queue
import datetime
import re
import time

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

    def tail_p2pool_log(self,):
        try:
            with open(self.RAW_LOG, "r", encoding="utf-8") as f:
                f.seek(0, os.SEEK_END)  # Start reading from the end

                miner_data_block = []
                in_miner_data = False

                while True:
                    line = f.readline()
                    if not line:
                        time.sleep(0.1)  # Wait for new content
                        continue

                    clean_line = line.strip()
                    lower_line = clean_line.lower()

                    if "p2pool new miner data" in lower_line:
                        in_miner_data = True
                        miner_data_block = [clean_line]
                        continue

                    if in_miner_data:
                        if clean_line == "" or clean_line.startswith("-"):
                            full_block = "\n".join(miner_data_block).strip()
                            self.log_event_now("New Miner Data", full_block)
                            in_miner_data = False
                        else:
                            miner_data_block.append(clean_line)
                        continue

                    if "sent new job" in lower_line:
                        self.log_event_now("Sent Jobs", clean_line)
                    elif "share found" in lower_line:
                        self.log_event_now("Found Share", clean_line)
                    elif "block found" in lower_line:
                        self.log_event_now("Found Block", clean_line)
                    # NEW: Specific classification for sidechain add_block messages
                    elif "sidechain add_block" in lower_line:
                        self.log_event_now("Sidechain Block Added", clean_line)
                    # FIX: Corrected boolean logic for "p2pool stopping"
                    elif "p2pool caught sigint" in lower_line or "p2pool stopping" in lower_line:
                        self.log_event_now("P2Pool Stopped", clean_line)
                    else:  # Fallback for any other messages
                        self.log_event_now("Other P2Pool Event", clean_line)
        except Exception as e:
            self.log_event_now("P2pool Process","Failed to tail p2pool log")
            pass

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

    def log_writer(self,):
        # 'a' mode creates the file if it doesn't exist
        with open(self.EVENT_LOG, "a", encoding="utf-8") as evlog:
            while True:
                # Continuously try to get items from the queue without blocking indefinitely
                try:
                    log_entry = self.log_queue.get(timeout=0.5)  # Wait up to 0.5 seconds
                    evlog.write(log_entry + "\n")
                    evlog.flush()
                except queue.Empty:
                    self.log_event_now("P2Pool Process", "P2Pool log queue empty")
                    pass  # No logs in queue, continue loop
                time.sleep(0.1)  # Short delay to prevent busy-waiting

    def strip_ansi_codes(self, text):
        ansi_escape = re.compile(r'\x1B\[[0-?]*[ -/]*[@-~]')
        return ansi_escape.sub('', text)

    def log_event_now(self, event_type, message):
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.log_queue.put(f"[{timestamp}] [{event_type}] {message}")