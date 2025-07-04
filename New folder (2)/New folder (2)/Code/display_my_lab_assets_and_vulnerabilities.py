import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
from typing import List, Dict

def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['Plugin Modification Date'])
    df['vuln_id'] = df['IP Address'] + "|" + df['Port'].astype(str) + "|" + df['Plugin'].astype(str)
    df = df.sort_values('Plugin Modification Date', ascending=False)
    return df.drop_duplicates(subset=['vuln_id'], keep='first')

def enrich_asset_data(df: pd.DataFrame) -> pd.DataFrame:
    asset_stats = df.groupby(['MAC Address', 'IP Address', 'Port', 'DNS Name']).agg(
        total_vulns=('Plugin', 'count'),
        critical=('Severity', lambda x: (x == 'Critical').sum()),
        high=('Severity', lambda x: (x == 'High').sum()),
        last_scan=('Plugin Modification Date', 'max')
    ).reset_index()

    asset_stats['risk_score'] = (
        asset_stats['critical'] * 4 +
        asset_stats['high'] * 3 +
        (asset_stats['total_vulns'] - asset_stats['critical'] - asset_stats['high']) * 1
    )

    return asset_stats.sort_values('risk_score', ascending=False)

def generate_table_image(table_df: pd.DataFrame, title: str = "") -> str:
    fig, ax = plt.subplots(figsize=(12, len(table_df) * 0.5 + 1))
    ax.axis('tight')
    ax.axis('off')

    # Add title above table
    if title:
        plt.title(title, fontsize=14, weight='bold', pad=20)

    table = ax.table(
        cellText=table_df.values,
        colLabels=table_df.columns,
        cellLoc='left',
        loc='center'
    )
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.2)

    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')


async def display_my_lab_assets_and_vulnerabilities(records: List[Dict]) -> Dict:
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    df = get_latest_assets(df)
    asset_data = enrich_asset_data(df)

    # Get top 10
    table_data = asset_data[[
    'IP Address',
    'Port',
    'DNS Name',
    'total_vulns',
    'critical',
    'high',
    'risk_score',
    'last_scan'
    ]].head(10).rename(columns={
    'IP Address': 'IP',
    'DNS Name': 'Hostname',
    'total_vulns': 'Total Vulns',
    'critical': 'Critical',
    'high': 'High',
    'risk_score': 'Risk Score',
    'last_scan': 'Last Scanned'
})

    table_data['Last Scanned'] = table_data['Last Scanned'].dt.strftime('%Y-%m-%d %H:%M')

    # Title with total count
    total_assets = len(asset_data)
    title = f"Out of {total_assets} - 10 last scanned assets and vulnerabilities"

    # Generate image with title
    table_plot_base64 = generate_table_image(table_data, title)



    return {
        "type": "image",
        "graph": table_plot_base64 
    }
