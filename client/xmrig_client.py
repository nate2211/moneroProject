
import asyncio
import ctypes
import sys
import os
import aiohttp

from xmrig_miner import XmrigMiner
from xmrig_data import XmrigData

xmrig_data = XmrigData()
xmrig_miner = XmrigMiner(xmrig_data)
# How often (in seconds) to send stats to the Flask server
REPORT_INTERVAL_SECONDS = 5

# Prevent system from sleeping (This is synchronous, keep as is for now at startup)
ES_CONTINUOUS = 0x80000000
ES_SYSTEM_REQUIRED = 0x00000001
ctypes.windll.kernel32.SetThreadExecutionState(ES_CONTINUOUS | ES_SYSTEM_REQUIRED)


async def periodic_reporter(session: aiohttp.ClientSession):

    while True:
        await asyncio.sleep(REPORT_INTERVAL_SECONDS)

        current_cpu_temp = await xmrig_data.get_cpu_temperature_async()
        current_power_draw = await xmrig_data.get_power_draw_async()
        current_threads = await xmrig_miner.get_current_threads_from_config_async()

        payload = {
            "client_id": xmrig_data.client_id,
            "hashrate": xmrig_data._latest_hashrate,
            "threads": current_threads,
            "cpu_temp": current_cpu_temp,
            "gpu_temp": xmrig_data._latest_gpu_temp,
            "gpu_fan": xmrig_data._latest_gpu_fan,
            "cpu_accepted_shares": xmrig_data._latest_cpu_accepted_shares,
            "nvidia_accepted_shares": xmrig_data._latest_nvidia_accepted_shares,
            "power_draw": current_power_draw
        }

        try:

            await session.post(f"{xmrig_data.FLASK_SERVER_URL}/hashrate", json=payload,
                               timeout=aiohttp.ClientTimeout(total=10))
        except aiohttp.ClientError as e:
            print(f"[!] Error sending periodic hashrate report: {e}")
        except Exception as e:
            print(f"[!] Unexpected error during periodic hashrate report send: {e}")

async def command_loop():
    print("Type 'start' to launch miner, 'stop' to terminate it, 'exit' to quit.")
    while True:
        cmd = await asyncio.to_thread(input, "> ")
        cmd = cmd.strip().lower()
        print(cmd)
        if cmd == "start":
            await xmrig_miner.start_miner()
        elif cmd == "stop":
            await xmrig_miner.stop_miner()
        elif cmd == "exit":
            await xmrig_miner.stop_miner()
            break
        else:
            print("Unknown command.")




async def main():


    if not os.path.exists(xmrig_data.XMRIG_PATH):
        print(f"[!] XMRig not found at {xmrig_data.XMRIG_PATH}")
        sys.exit(1)

    xmrig_data.FLASK_SERVER_URL = await asyncio.to_thread(input,
                                               "Enter Flask server URL to send requests (e.g., http://192.168.0.10:5000): ")
    xmrig_data.FLASK_SERVER_URL = xmrig_data.FLASK_SERVER_URL.strip()
    if not xmrig_data.FLASK_SERVER_URL:
        print("[!] No URL provided. Exiting.")
        sys.exit(1)

    xmrig_data.client_id = await asyncio.to_thread(input, "Enter a unique client ID (e.g., Miner1): ")
    xmrig_data.client_id = xmrig_data.client_id.strip()
    if not xmrig_data.client_id:
        print("[!] No client ID provided. Exiting.")
        sys.exit(1)

    # Initialize the single aiohttp ClientSession
    xmrig_data.aiohttp_client_session = aiohttp.ClientSession()

    # Start the background tasks, passing the shared session
    asyncio.create_task(xmrig_miner.poll_server(xmrig_data.aiohttp_client_session))
    asyncio.create_task(periodic_reporter(xmrig_data.aiohttp_client_session))

    try:
        await command_loop()
    finally:
        # Ensure the aiohttp session is closed when the main loop finishes or is interrupted
        await xmrig_data.aiohttp_client_session.close()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Exiting.")