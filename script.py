import requests
from datetime import datetime, timedelta

def get_monero_price_at_datetime_est(target_datetime_str):
    # Convert EST to UTC
    est_offset = timedelta(hours=5)
    target_datetime = datetime.strptime(target_datetime_str, "%Y-%m-%d %H:%M:%S") + est_offset
    date_str = target_datetime.strftime("%d-%m-%Y")

    url = f"https://api.coingecko.com/api/v3/coins/monero/history?date={date_str}&localization=false"
    response = requests.get(url)

    if response.status_code != 200:
        print(f"Error: {response.status_code}")
        return

    data = response.json()
    try:
        price = data['market_data']['current_price']['usd']
        print(f"XMR price on {target_datetime_str} EST was approximately ${price:.2f}")
    except KeyError:
        print("Price data not available for the given date.")

# Example usage
get_monero_price_at_datetime_est("2025-06-21 15:56:38")
