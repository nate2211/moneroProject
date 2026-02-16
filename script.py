import pandas as pd
import requests
import time
from datetime import datetime, timedelta


def get_xmr_price(date_str):
    """Fetches Monero price from CoinGecko for a specific date (DD-MM-YYYY)."""
    # CoinGecko Demo API has a rate limit (~30 calls/min).
    # We add a small delay and error handling to manage this.
    url = f"https://api.coingecko.com/api/v3/coins/monero/history?date={date_str}&localization=false"
    try:
        response = requests.get(url)
        if response.status_code == 429:
            print("Rate limit hit, waiting 30 seconds...")
            time.sleep(30)
            return get_xmr_price(date_str)

        data = response.json()
        return data['market_data']['current_price']['usd']
    except Exception as e:
        print(f"Could not fetch price for {date_str}: {e}")
        return 0


def process_monero_taxes(input_file, output_file):
    # Load the CSV
    df = pd.read_csv(input_file)

    # Convert 'date' column to datetime objects
    df['date'] = pd.to_datetime(df['date'])

    prices = []
    print("Fetching historical prices (this may take a minute)...")

    for index, row in df.iterrows():
        # Format date for CoinGecko API: DD-MM-YYYY
        api_date = row['date'].strftime("%d-%m-%Y")
        price = get_xmr_price(api_date)
        prices.append(price)
        # Small sleep to respect free API limits
        time.sleep(1.5)

        # Add new columns
    df['xmr_price_usd'] = prices
    df['total_value_usd'] = df['amount'] * df['xmr_price_usd']

    # Calculate the grand total
    grand_total_xmr = df['amount'].sum()
    grand_total_usd = df['total_value_usd'].sum()

    # Create a summary row to append at the bottom
    summary_data = {
        'date': 'TOTAL',
        'amount': grand_total_xmr,
        'total_value_usd': grand_total_usd
    }

    # Use concat to add the summary row
    df = pd.concat([df, pd.DataFrame([summary_data])], ignore_index=True)

    # Save the updated file
    df.to_csv(output_file, index=False)
    print(f"Success! Tax-ready file saved as: {output_file}")
    print(f"Grand Total: ${grand_total_usd:.2f}")


# Run the script
process_monero_taxes('C:\\Users\\natem\\Downloads\\monero-txs_1771199687.csv', 'monero_taxes_final.csv')