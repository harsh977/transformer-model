import pandas as pd
from datetime import datetime

def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
    """
    Filter the DataFrame to keep only the latest entry for each unique asset (MAC Address).
    """
    df = df.copy()
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    
    # Sort by date, then keep only the latest for each (MAC Address)
    df = df.sort_values(by='Plugin Modification Date', ascending=False)
    latest_df = df.drop_duplicates(subset=['MAC Address'], keep='first')
    
    return latest_df

async def display_total_assets(records: list) -> dict:
    """
    Compute total number of unique assets based on the latest scan data.
    """
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    latest_assets = get_latest_assets(df)
    total_assets = latest_assets[['MAC Address']].drop_duplicates().shape[0]

    return {
        "intent": "display_total_assets",
        "type": "numeric",
        "description": "Total number of unique assets (based on latest scan)",
        "data": {
            "asset_count": total_assets
        }
    }
