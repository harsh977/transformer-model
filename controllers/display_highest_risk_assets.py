import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from typing import List, Dict

def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
    """Consistent with other intents - gets latest records for each unique asset"""
    df = df.copy()
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['Plugin Modification Date'])
    df['vuln_id'] = df['IP Address'] + "|" + df['Port'].astype(str) + "|" + df['Plugin'].astype(str)
    df = df.sort_values('Plugin Modification Date', ascending=False)
    return df.drop_duplicates(subset=['vuln_id'], keep='first')

def calculate_asset_risk(df: pd.DataFrame) -> pd.DataFrame:
    """
    Calculates risk score for each asset (IP+Port combination) based on:
    - Number of vulnerabilities
    - Severity weights (Critical=4, High=3, Medium=2, Low=1)
    - Recentness (last 30 days get 1.5x multiplier)
    """
    # Create asset identifier
    df['asset_id'] = df['IP Address'] + ":" + df['Port'].astype(str)
    
    # Calculate severity weights
    severity_weights = {'Critical': 4, 'High': 3, 'Medium': 2, 'Low': 1}
    df['severity_weight'] = df['Severity'].map(severity_weights)
    
    # Apply recentness multiplier
    recent_threshold = pd.Timestamp.now() - pd.Timedelta(days=30)
    df['recent_multiplier'] = df['Plugin Modification Date'].apply(
        lambda x: 1.5 if x >= recent_threshold else 1.0
    )
    
    # Calculate weighted risk score
    df['weighted_risk'] = df['severity_weight'] * df['recent_multiplier']
    
    # Aggregate by asset
    asset_risk = df.groupby(['asset_id', 'IP Address', 'Port']).agg(
        total_vulnerabilities=('Plugin', 'count'),
        critical_count=('Severity', lambda x: (x == 'Critical').sum()),
        weighted_risk_score=('weighted_risk', 'sum')
    ).reset_index()
    
    return asset_risk.sort_values('weighted_risk_score', ascending=False)

async def display_highest_risk_assets(records: List[Dict], top_n: int = 10) -> Dict:
    """
    Identifies and visualizes highest risk assets using a heatmap of:
    - Vulnerability counts by severity
    - Weighted risk scores
    """
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    # Get latest records for each vulnerability
    df = get_latest_assets(df)
    
    # Calculate asset risk scores
    asset_risk = calculate_asset_risk(df)
    
    if asset_risk.empty:
        return {"message": "No risk data available"}
    
    # Get top N risky assets
    top_assets = asset_risk.head(top_n)
    
    # Get vulnerability details for these assets
    top_assets_vulns = df[df['asset_id'].isin(top_assets['asset_id'])]
    
    # Prepare heatmap data
    heatmap_data = top_assets_vulns.groupby(
        ['asset_id', 'Severity']
    ).size().unstack(fill_value=0)[['Critical', 'High', 'Medium', 'Low']]
    
    # Normalize for better heatmap visualization
    normalized_data = heatmap_data.div(heatmap_data.sum(axis=1), axis=0)
    
    # Create visualization
    plt.figure(figsize=(12, 8))
    
    # Heatmap
    sns.heatmap(
        normalized_data,
        annot=heatmap_data,  # Show raw counts
        fmt='d',
        cmap='YlOrRd',
        linewidths=0.5,
        cbar_kws={'label': 'Normalized Risk Proportion'}
    )
    
    plt.title(f'Top {top_n} Highest Risk Assets\n(Vulnerability Distribution by Severity)', pad=20)
    plt.xlabel('Severity Level')
    plt.ylabel('Asset (IP:Port)')
    plt.tight_layout()
    
    # Save visualization
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=120)
    buffer.seek(0)
    heatmap_image = base64.b64encode(buffer.read()).decode('utf-8')
    buffer.close()
    plt.close()
    
    # Prepare response data
    response_data = {
        "top_assets": top_assets.to_dict('records'),
        "risk_metrics": {
            "highest_risk_score": float(top_assets['weighted_risk_score'].max()),
            "average_risk_score": float(top_assets['weighted_risk_score'].mean()),
            "critical_vulnerabilities": int(top_assets['critical_count'].sum())
        },
        "vulnerability_distribution": {
            "asset_ids": heatmap_data.index.tolist(),
            "critical": heatmap_data['Critical'].values.tolist(),
            "high": heatmap_data['High'].values.tolist(),
            "medium": heatmap_data['Medium'].values.tolist(),
            "low": heatmap_data['Low'].values.tolist()
        }
    }
    
    return {
        "intent": "display_highest_risk_assets",
        "task_type": "list",
        "plot_type": "heatmap",
        "description": f"Top {top_n} highest risk assets with vulnerability distribution",
        "data": response_data,
        "graph": heatmap_image
    }