import asyncio
import json
import os
import re
import subprocess
import time
from typing import Any, Dict

from flask import Blueprint, jsonify, request, send_from_directory

from p2pool_helper import p2pool_helper

p2pooldata = p2pool_helper.p2pooldata
clientdata = p2pool_helper.clientdata
processor = p2pool_helper.processor
event_processor = p2pool_helper.event_processor
queue_command = p2pool_helper.queue_command
COMMAND_QUEUE = p2pool_helper.COMMAND_QUEUE
ELECTRICITY_RATE_PER_KWH = p2pool_helper.ELECTRICITY_RATE_PER_KWH
clear_file_contents = p2pool_helper.clear_file_contents

api_b = Blueprint("api", __name__)

STATUS_CACHE_PATH = os.path.join(p2pooldata.P2POOL_DIR, "last_status_snapshot.json")
JOB_CACHE_PATH = os.path.join(p2pooldata.P2POOL_DIR, "last_client_jobs.json")
STATUS_SECTION_RE = re.compile(r"^\s*(.*?)\s*=\s*(.*)$")
STATUS_HEADER_NAME_RE = re.compile(r"^(SideChain status|StratumServer status|P2PServer status)\s*$", re.IGNORECASE)

# Matches prefixes like:
# [P2Pool] 2026-03-22 15:56:05.2425
# [P2Pool]
LOG_STATUS_PREFIX_RE = re.compile(
    r"^\s*(?:\[P2Pool\]\s*)?(?:\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}(?:\.\d+)?\s+)?"
)



def _safe_float(value, default=0.0):
    try:
        return float(value)
    except (TypeError, ValueError):
        return float(default)



def _safe_int(value, default=0):
    try:
        return int(value)
    except (TypeError, ValueError):
        return int(default)



def _ensure_parent_dir(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)



def _read_json_file(path: str, default: Any):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return default



def _write_json_file(path: str, payload: Any) -> None:
    try:
        _ensure_parent_dir(path)
        tmp_path = f"{path}.tmp"
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, ensure_ascii=False)
        os.replace(tmp_path, path)
    except Exception as e:
        try:
            p2pooldata.log_event_now("API Cache", f"Failed to write cache {path}: {e}")
        except Exception:
            pass



def _sanitize_job_payload(job: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "difficulty": job.get("difficulty"),
        "height": job.get("height"),
        "algo": job.get("algo"),
        "tx_count": job.get("tx_count"),
        "ip": job.get("ip"),
        "updated_at": job.get("updated_at") or int(time.time()),
    }



def _get_persisted_jobs() -> Dict[str, Dict[str, Any]]:
    data = _read_json_file(JOB_CACHE_PATH, {})
    return data if isinstance(data, dict) else {}



def _persist_job_snapshot(client_id: str, job_payload: Dict[str, Any]) -> None:
    current = _get_persisted_jobs()
    current[client_id] = _sanitize_job_payload(job_payload)
    _write_json_file(JOB_CACHE_PATH, current)



def _get_combined_jobs() -> Dict[str, Dict[str, Any]]:
    persisted = _get_persisted_jobs()
    live = clientdata.client_newjobs if isinstance(clientdata.client_newjobs, dict) else {}

    combined: Dict[str, Dict[str, Any]] = {}
    combined.update(persisted)

    for cid, payload in live.items():
        combined[cid] = _sanitize_job_payload(payload or {})

    for cid, payload in combined.items():
        if cid not in live:
            clientdata.client_newjobs[cid] = dict(payload)

    return combined



def _persist_status_snapshot(status_payload: Dict[str, Any]) -> None:
    wrapped = {
        "saved_at": int(time.time()),
        "status": status_payload,
    }
    _write_json_file(STATUS_CACHE_PATH, wrapped)



def _get_cached_status_snapshot() -> Dict[str, Any]:
    cached = _read_json_file(STATUS_CACHE_PATH, {})
    if isinstance(cached, dict) and isinstance(cached.get("status"), dict):
        return cached
    return {}



def _normalize_status_line(line: str) -> str:
    line = (line or "").strip("\r\n")
    line = LOG_STATUS_PREFIX_RE.sub("", line, count=1).strip()
    return line


def parse_p2pool_status(raw_text: str) -> Dict[str, Any]:
    if not (raw_text or "").strip():
        return {"error": "Received empty status from P2Pool."}

    data = {"sidechain": {}, "stratum": {}, "p2p": {}}
    current_section = None

    for raw_line in raw_text.splitlines():
        line = _normalize_status_line(raw_line)
        if not line:
            continue

        line_lower = line.lower()

        if line_lower == "sidechain status":
            current_section = "sidechain"
            continue
        if line_lower == "stratumserver status":
            current_section = "stratum"
            continue
        if line_lower == "p2pserver status":
            current_section = "p2p"
            continue

        if not current_section:
            continue

        match = STATUS_SECTION_RE.match(line)
        if match:
            key = match.group(1).strip()
            value = match.group(2).strip()
            data[current_section][key] = value

    if not any(bool(section) for section in data.values()):
        return {"error": "Could not parse status output from P2Pool."}

    return data


def _extract_latest_status_block(log_content: str) -> str:
    if not log_content:
        return ""

    raw_lines = log_content.splitlines()
    normalized_lines = [_normalize_status_line(line) for line in raw_lines]

    # Find the most recent SideChain status header, because that starts a full status snapshot
    start_idx = -1
    for i, line in enumerate(normalized_lines):
        if line.lower() == "sidechain status":
            start_idx = i

    if start_idx < 0:
        return ""

    collected: list[str] = []
    started = False
    sections_seen = set()

    for i in range(start_idx, len(normalized_lines)):
        line = normalized_lines[i]

        if not line:
            if started and sections_seen:
                continue
            else:
                continue

        lower = line.lower()

        if lower == "sidechain status":
            if started and collected:
                # a newer snapshot started; stop current one
                break
            started = True
            sections_seen.add("sidechain")
            collected.append("SideChain status")
            continue

        if not started:
            continue

        if lower == "stratumserver status":
            sections_seen.add("stratum")
            collected.append("StratumServer status")
            continue

        if lower == "p2pserver status":
            sections_seen.add("p2p")
            collected.append("P2PServer status")
            continue

        if STATUS_SECTION_RE.match(line):
            collected.append(line)
            continue

        # If we already started collecting and hit a non-status line, end the snapshot
        if collected:
            break

    if not collected:
        return ""

    # Require at least SideChain + Stratum to consider it a real snapshot
    if "sidechain" not in sections_seen or "stratum" not in sections_seen:
        return ""

    return "\n".join(collected).strip()

@api_b.route("/connect_wifi", methods=["POST"])
def connect_wifi():
    data = request.get_json() or {}
    ssid = data.get("ssid")
    password = data.get("password")
    if not ssid or not password:
        return jsonify({"status": "error", "message": "SSID and password are required."}), 400

    temp_xml_path = os.path.join(p2pooldata.P2POOL_DIR, f"{ssid}_profile.xml")
    try:
        delete_command = f'netsh wlan delete profile name="{ssid}"'
        delete_result = subprocess.run(delete_command, shell=True, capture_output=True, text=True)
        if delete_result.returncode == 0:
            p2pooldata.log_event_now("Network Control", f"Deleted existing Wi-Fi profile for '{ssid}'.")
        else:
            stderr_text = (delete_result.stderr or "")
            if f'profile "{ssid}" is not found' not in stderr_text:
                p2pooldata.log_event_now(
                    "Network Control",
                    f"Warning: Failed to delete Wi-Fi profile for '{ssid}': {stderr_text.strip()}",
                )

        profile_xml = f"""<?xml version=\"1.0\"?>
<WLANProfile xmlns=\"http://www.microsoft.com/networking/WLAN/profile/v1\">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>"""

        with open(temp_xml_path, "w", encoding="utf-8") as f:
            f.write(profile_xml)

        subprocess.run(f'netsh wlan add profile filename="{temp_xml_path}"', shell=True, check=True)
        subprocess.run(f'netsh wlan connect name="{ssid}" ssid="{ssid}"', shell=True, check=True)
        p2pooldata.log_event_now("Network Control", f"Attempted to connect to Wi-Fi network: '{ssid}'.")
        return jsonify({"status": "success", "message": f"Attempted to connect to Wi-Fi network: {ssid}. Check network status."})

    except subprocess.CalledProcessError as e:
        error_msg = f"Failed to connect to Wi-Fi network '{ssid}'. Error: {(e.stderr or '').strip()}. Ensure script is run as administrator."
        p2pooldata.log_event_now("Network Control", error_msg)
        return jsonify({"status": "error", "message": error_msg}), 500
    except Exception as e:
        error_msg = f"An unexpected error occurred during Wi-Fi connection: {e}"
        p2pooldata.log_event_now("Network Control", error_msg)
        return jsonify({"status": "error", "message": error_msg}), 500
    finally:
        try:
            if os.path.exists(temp_xml_path):
                os.remove(temp_xml_path)
        except Exception:
            pass


@api_b.route("/restart_p2pool", methods=["POST"])
def restart_p2pool():
    async def restart_async():
        if p2pooldata.p2pool_proc and p2pooldata.p2pool_proc.returncode is None:
            try:
                await processor.stop_p2pool(reason="frontend_restart")
                clear_file_contents(p2pooldata.RAW_LOG)
            except Exception as e:
                p2pooldata.log_event_now("P2Pool Control", f"Error terminating existing P2Pool process: {e}")

        try:
            success = await processor.start_p2pool()
            if success:
                p2pooldata.log_event_now("P2Pool Control", "P2Pool restarted successfully.")
            else:
                p2pooldata.log_event_now("P2Pool Control", "P2Pool restart failed: start_p2pool returned False.")
        except Exception as e:
            p2pooldata.log_event_now("P2Pool Control", f"Failed to restart P2Pool process: {e}")

    try:
        p2pool_helper.asyncio_main_loop.create_task(restart_async())
        return jsonify({"status": "pending", "message": "Restart initiated in background."})
    except RuntimeError:
        p2pool_helper.asyncio_main_loop.run(restart_async())
        return jsonify({"status": "success", "message": "Restart completed synchronously."})


@api_b.route("/status", methods=["POST"])
def get_status_output():
    cached = _get_cached_status_snapshot()

    proc = p2pooldata.p2pool_proc
    is_running = bool(proc and proc.returncode is None)

    if not is_running:
        if cached:
            return jsonify(
                {
                    "cached": True,
                    "message": "P2Pool is not running. Showing last cached status.",
                    "saved_at": cached.get("saved_at"),
                    **cached.get("status", {}),
                }
            )
        return jsonify({"error": "P2Pool is not running."}), 503

    try:
        future = asyncio.run_coroutine_threadsafe(
            processor.write_to_stdin("status"),
            p2pool_helper.asyncio_main_loop,
        )
        success = future.result(timeout=5)
        if not success:
            raise RuntimeError("Failed to write to P2Pool stdin. Pipe may be closed.")

        latest_status_block = ""
        deadline = time.time() + 3.0

        while time.time() < deadline:
            if os.path.exists(p2pooldata.RAW_LOG):
                with open(p2pooldata.RAW_LOG, "r", encoding="utf-8", errors="ignore") as f:
                    log_content = f.read()
                latest_status_block = _extract_latest_status_block(log_content)
                if latest_status_block:
                    break
            time.sleep(0.15)

        if not latest_status_block:
            if cached:
                return jsonify(
                    {
                        "cached": True,
                        "message": "Status not found in current logs. Showing last cached status.",
                        "saved_at": cached.get("saved_at"),
                        **cached.get("status", {}),
                    }
                )
            return jsonify({"error": "Status not found in logs. P2Pool may be starting."}), 404

        parsed = parse_p2pool_status(latest_status_block)
        if "error" not in parsed:
            _persist_status_snapshot(parsed)
        return jsonify(parsed)

    except Exception as e:
        if cached:
            return jsonify(
                {
                    "cached": True,
                    "message": f"Status fetch failed ({e}). Showing last cached status.",
                    "saved_at": cached.get("saved_at"),
                    **cached.get("status", {}),
                }
            )
        return jsonify({"error": str(e)}), 500


@api_b.route("/api/memory", methods=["GET"])
def get_memory():
    return jsonify(
        {
            "cpu_usage": processor.cpu_usage,
            "ram_usage": processor.ram_usage_mb,
            "vms_usage": processor.vms_usage_mb,
            "num_page_faults": processor.num_page_faults,
            "paged_pool": processor.paged_pool_mb,
            "page_file": processor.page_file_mb,
        }
    )


@api_b.route("/api/clients", methods=["GET"])
def get_clients():
    combined_jobs = _get_combined_jobs()
    client_last_seen_formatted = {
        cid: p2pooldata.time_ago(ts) for cid, ts in clientdata.client_last_seen.items()
    }

    return jsonify(
        {
            "hashrates": clientdata.client_hashrates,
            "threads": clientdata.client_threads,
            "temps": clientdata.client_temps,
            "power_draws": clientdata.client_power_draws,
            "costs": clientdata.client_costs,
            "status": clientdata.client_status,
            "cpu_shares": clientdata.client_cpu_shares,
            "nvidia_shares": clientdata.client_nvidia_shares,
            "gpu_stats": clientdata.client_gpu_stats,
            "last_seen": client_last_seen_formatted,
            "pl1_pl2s": clientdata.client_pl1_pl2s,
            "newjobs": {cid: _sanitize_job_payload(payload) for cid, payload in combined_jobs.items()},
        }
    )


@api_b.route("/miners_gui_settings/<client_id>", methods=["POST"])
def update_miner_gui_settings(client_id):
    data = request.get_json() or {}
    clientdata.client_pl1_pl2s[client_id] = data.get("pl1_pl2")
    return jsonify({"message": "Received GUI settings"}), 200


@api_b.route("/miners/<client_id>", methods=["POST"])
def update_miner_status(client_id):
    data = request.get_json() or {}
    if "status" not in data:
        return jsonify({"error": "Invalid payload. 'status' is required."}), 400
    clientdata.client_status[client_id] = str(data["status"]).strip().capitalize()
    clientdata.client_last_seen[client_id] = time.time()
    return jsonify({"message": "Status updated successfully"}), 200


@api_b.route("/start_miner/<client_id>", methods=["POST"])
def start_miner(client_id):
    pool = request.form.get("pool")
    threads = request.form.get("threads")
    if not pool or not threads:
        return "Pool and threads are required.", 400
    queue_command(client_id, {"command": "start", "pool": pool, "threads": int(threads)})
    return jsonify({"status": "success", "message": f"Start command queued for {client_id}"})


@api_b.route("/stop_miner/<client_id>", methods=["POST"])
def stop_miner(client_id):
    queue_command(client_id, {"command": "stop"})
    return jsonify({"status": "ok", "message": f"Stop command queued for {client_id}"})


@api_b.route("/set_threads/<client_id>", methods=["POST"])
def set_threads(client_id):
    try:
        new_threads = int(request.form["threads"])
    except (ValueError, KeyError):
        return jsonify({"status": "error", "message": "Invalid thread count provided"}), 400
    queue_command(client_id, {"command": "set_threads", "threads": new_threads})
    return jsonify({"status": "ok", "message": f"Set thread command queued for {client_id}"})


@api_b.route("/set_pl1_pl2/<client_id>", methods=["POST"])
def set_pl1_pl2(client_id):
    try:
        new_pl1_pl2 = int(request.form["pl1_pl2"])
    except (ValueError, KeyError):
        return jsonify({"status": "error", "message": "Invalid PL1/PL2 value provided"}), 400
    queue_command(client_id, {"command": "set_pl1_pl2", "pl1_pl2": new_pl1_pl2})
    return jsonify({"status": "ok", "message": f"Set pl1/pl2 command queued for {client_id}"})


@api_b.route("/get_command/<client_id>", methods=["GET"])
def get_command(client_id):
    if client_id in COMMAND_QUEUE and COMMAND_QUEUE[client_id]:
        command = COMMAND_QUEUE[client_id].pop(0)
        p2pooldata.log_event_now("Command", f"sent command to '{client_id}': {command}")
        return jsonify(command)
    return jsonify({})


@api_b.route("/api/lastseen", methods=["GET"])
def get_last_seen():
    return jsonify({"client_last_seen_formatted": {cid: p2pooldata.time_ago(ts) for cid, ts in clientdata.client_last_seen.items()}})


@api_b.route("/api/totals", methods=["GET"])
def get_totals():
    total_hashrate = round(sum(_safe_float(v, 0.0) for v in clientdata.client_hashrates.values()), 2)
    total_cpu_shares = sum(_safe_int(v, 0) for v in clientdata.client_cpu_shares.values())
    total_gpu_shares = sum(_safe_int(v, 0) for v in clientdata.client_nvidia_shares.values())

    total_power_draw_values = [
        _safe_float(p, 0.0)
        for p in clientdata.client_power_draws.values()
        if isinstance(p, (int, float)) or (isinstance(p, str) and p not in {"", "N/A"})
    ]
    total_power_draw = round(sum(total_power_draw_values), 2) if total_power_draw_values else "N/A"

    valid_cpu_temps = []
    for temp_value in clientdata.client_temps.values():
        if isinstance(temp_value, str) and "°C" in temp_value:
            try:
                valid_cpu_temps.append(float(temp_value.split("°C")[0].strip()))
            except ValueError:
                pass

    average_temp = round(sum(valid_cpu_temps) / len(valid_cpu_temps), 1) if valid_cpu_temps else "N/A"
    total_cost = round(sum(_safe_float(v, 0.0) for v in clientdata.client_costs.values()), 4)
    summary = event_processor.get_summary()

    return jsonify(
        {
            "total_hashrate": total_hashrate,
            "total_cpu_shares": total_cpu_shares,
            "total_gpu_shares": total_gpu_shares,
            "total_temp": average_temp,
            "total_cost": total_cost,
            "total_power_draw": total_power_draw,
            "p2pool_share_candidates": summary["share_candidates"],
            "p2pool_credited_shares": summary["credited_shares"],
            "p2pool_not_credited_shares": summary["not_credited_shares"],
            "p2pool_payout_context": summary["payout_context"],
            "p2pool_peer_events": summary["peer_events"],
            "p2pool_peer_blocks": summary["peer_blocks"],
            "p2pool_stratum_work": summary["stratum_work"],
            "p2pool_stratum_shares": summary["stratum_shares"],
            "p2pool_mainchain_blocks": summary["mainchain_blocks"],
            "p2pool_sidechain_blocks": summary["sidechain_blocks"],
        }
    )


@api_b.route("/api/events", methods=["GET"])
def get_events():
    try:
        limit = int(request.args.get("limit", 25))
    except (ValueError, TypeError):
        limit = 25
    limit = max(1, min(limit, 100))
    return jsonify(event_processor.get_all_events(limit=limit))


@api_b.route("/hashrate", methods=["POST"])
def receive_hashrate():
    data = request.get_json() or {}
    if "client_id" not in data:
        return "Bad Request", 400

    client_id = data["client_id"]
    if client_id not in clientdata.client_start_times:
        clientdata.client_start_times[client_id] = time.time()

    power_watts = 0.0
    power_draw_raw = data.get("power_draw", "0.0")
    if isinstance(power_draw_raw, str):
        cleaned_str = power_draw_raw.replace("W", "", 2).strip()
        try:
            power_watts = float(cleaned_str)
        except (ValueError, TypeError):
            power_watts = 0.0
    elif isinstance(power_draw_raw, (int, float)):
        power_watts = float(power_draw_raw)

    clientdata.client_hashrates[client_id] = data.get("hashrate", 0)
    clientdata.client_threads[client_id] = data.get("threads", 0)
    clientdata.client_temps[client_id] = data.get("cpu_temp", "N/A")
    clientdata.client_last_seen[client_id] = time.time()
    clientdata.client_cpu_shares[client_id] = data.get("cpu_accepted_shares", 0)
    clientdata.client_nvidia_shares[client_id] = data.get("nvidia_accepted_shares", 0)
    clientdata.client_gpu_stats[client_id] = {"temp": data.get("gpu_temp", "N/A"), "fan": data.get("gpu_fan", "N/A")}
    clientdata.client_power_draws[client_id] = power_watts

    start_time = clientdata.client_start_times.get(client_id)
    if start_time:
        total_uptime_hours = (time.time() - start_time) / 3600
        if power_watts > 0 and total_uptime_hours > 0:
            clientdata.client_costs[client_id] = (power_watts / 1000) * total_uptime_hours * ELECTRICITY_RATE_PER_KWH

    if client_id in _get_persisted_jobs() and client_id not in clientdata.client_newjobs:
        clientdata.client_newjobs[client_id] = _get_persisted_jobs()[client_id]

    return jsonify({"message": "ok"})


@api_b.route("/newjob", methods=["POST"])
def receive_newjob():
    data = request.get_json() or {}
    client_id = data.get("client_id")
    if not client_id:
        return "Bad Request", 400

    payload = _sanitize_job_payload(data)
    clientdata.client_newjobs[client_id] = payload
    clientdata.client_last_seen[client_id] = time.time()
    _persist_job_snapshot(client_id, payload)
    return "OK", 200


@api_b.route("/update_client/<client_id>", methods=["POST"])
def update_client(client_id):
    if client_id not in clientdata.client_status:
        return jsonify({"status": "error", "message": "Client not found."}), 404
    download_url = "http://192.168.0.10:5000/download/client"
    queue_command(client_id, {"command": "update", "url": download_url})
    return jsonify({"status": "success", "message": f"Update command queued for client '{client_id}'."})


@api_b.route("/download/client")
def download_client():
    directory = r"X:\Users\natem\PycharmProjects\moneroProject\dist"
    filename = "client.exe"
    if not os.path.exists(os.path.join(directory, filename)):
        p2pooldata.log_event_now("File Server", f"Error: Client download failed. File not found at {directory}\\{filename}")
        return "File not found.", 404
    p2pooldata.log_event_now("File Server", f"Client download initiated for {filename}.")
    return send_from_directory(directory, filename, as_attachment=True)
