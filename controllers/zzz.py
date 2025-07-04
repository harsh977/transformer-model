import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from datetime import datetime

# Ensure backend doesn't try to open GUI window
plt.switch_backend('Agg')

def get_latest_scan_data(df: pd.DataFrame) -> pd.DataFrame:
    """Filter to keep only the latest entry for each unique asset (IP + DNS Name + Lab Name)."""
    df = df.copy()
    df['datetime'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['datetime'])
    
    # Create unique asset identifier combining IP, DNS Name, and Lab Name
    df['asset_id'] = (
        df['IP Address'].astype(str) + "|" + 
        df['DNS Name'].astype(str) + "|" + 
        df['Lab name'].astype(str)
    )
    
    # Get the most recent scan for each asset
    latest_df = df.sort_values('datetime').groupby('asset_id').tail(1)
    
    return latest_df

def categorize_asset(row: pd.Series) -> str:
    """Categorize assets based on services and other characteristics."""
    plugin_name = str(row['Plugin Name']).lower()
    port = row['Port']
    
    # Web servers
    if any(x in plugin_name for x in ['http', 'web', 'tomcat', 'apache']) or port in [80, 443, 8080, 8443]:
        return 'Web Server'
    
    # Databases
    elif any(x in plugin_name for x in ['sql', 'database', 'mssql', 'mysql']) or port in [1433, 3306, 5432]:
        return 'Database'
    
    # Windows hosts
    elif (any(x in plugin_name for x in ['windows', 'smb', 'netbios']) or 
          port in [135, 139, 445, 3389]):
        return 'Windows Host'
    
    # Network devices
    elif any(x in plugin_name for x in ['router', 'switch', 'firewall']) or port in [22, 23]:
        return 'Network Device'
    
    # Virtualization
    elif any(x in plugin_name for x in ['vmware', 'vcenter', 'esxi', 'hyper-v']):
        return 'Virtualization'
    
    # Security services
    elif any(x in plugin_name for x in ['ssl', 'tls', 'ldap', 'radius']):
        return 'Security Service'
    
    # Custom lab-specific categorization
    elif 'lab' in str(row['Lab name']).lower():
        return 'Lab Equipment'
    
    else:
        return 'Other'

async def display_asset_type_breakdown(records: list) -> dict:
    """Generate a bar chart showing breakdown of asset types."""
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    # Get only the latest scan data for each asset
    latest_data = get_latest_scan_data(df)
    
    # Categorize each asset using multiple fields
    latest_data['Asset Type'] = latest_data.apply(categorize_asset, axis=1)
    
    # Count assets by type and sort by count
    asset_counts = latest_data['Asset Type'].value_counts().sort_values(ascending=False)
    
    # Create visualization
    plt.figure(figsize=(10, 6))
    ax = sns.barplot(
        x=asset_counts.index,
        y=asset_counts.values,
        palette=sns.color_palette('husl', len(asset_counts))
    )
    
    # Customize the plot
    plt.title('Asset Type Distribution\n(Grouped by IP + DNS + Lab)', pad=20)
    plt.xlabel('Asset Type', labelpad=10)
    plt.ylabel('Count', labelpad=10)
    
    # Add value labels and rotate x-ticks
    for p in ax.patches:
        ax.annotate(
            f'{int(p.get_height())}', 
            (p.get_x() + p.get_width() / 2., p.get_height()),
            ha='center', va='center', 
            xytext=(0, 5), 
            textcoords='offset points',
            fontsize=10
        )
    
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    # Save image to buffer
    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=120, bbox_inches='tight')
    buffer.seek(0)
    image_base64 = base64.b64encode(buffer.read()).decode('utf-8')
    buffer.close()
    plt.close()
    
    # Prepare response data
    return {
        "intent": "display_asset_type_breakdown",
        "task_type": "plot",
        "plot_type": "bar",
        "description": "Distribution of asset types grouped by IP+DNS+Lab",
        "data": {
            "type": "image",
            "title": "Asset Type Distribution",
            "image_base64": image_base64,
            "asset_count": len(latest_data),
            "breakdown": asset_counts.to_dict()
        }
    }