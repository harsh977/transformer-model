import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from datetime import datetime, timedelta
from typing import List, Dict

def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
    """Gets latest records for each unique asset."""
    df = df.copy()
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['Plugin Modification Date'])
    df['vuln_id'] = df['IP Address'] + "|" + df['Port'].astype(str) + "|" + df['Plugin'].astype(str)
    df = df.sort_values('Plugin Modification Date', ascending=False)
    return df.drop_duplicates(subset=['vuln_id'], keep='first')

def categorize_complexity(plugin_name):
    name = str(plugin_name).lower()
    if any(x in name for x in ['windows update', 'os upgrade', 'kernel']):
        return 'OS-Level'
    elif any(x in name for x in ['emergency', 'zero-day', 'exploit']):
        return 'Emergency'
    elif any(x in name for x in ['java', '.net', 'runtime']):
        return 'Runtime'
    else:
        return 'Application'

async def display_time_to_patch_critical_vulnerabilities(records: List[Dict], time_window: str = '90D') -> Dict:
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    df = get_latest_assets(df)
    critical_vulns = df[df['Severity'] == 'Critical'].copy()
    if critical_vulns.empty:
        return {"message": "No critical vulnerabilities found"}

    critical_vulns['Plugin Modification Date'] = pd.to_datetime(critical_vulns['Plugin Modification Date'])
    critical_vulns['Patch Date'] = pd.to_datetime(critical_vulns.get('Patch Date', datetime.now()), errors='coerce')
    patched_vulns = critical_vulns[critical_vulns['Patch Date'].notna()]
    patched_vulns['Days to Patch'] = (patched_vulns['Patch Date'] - patched_vulns['Plugin Modification Date']).dt.days

    if patched_vulns.empty:
        return {"message": "No patched critical vulnerabilities found"}

    time_window_days = int(time_window[:-1]) if time_window.endswith('D') else 90
    recent_threshold = datetime.now() - timedelta(days=time_window_days)
    patched_vulns = patched_vulns[patched_vulns['Patch Date'] >= recent_threshold]

    patched_vulns['Patch Complexity'] = patched_vulns['Plugin Name'].apply(categorize_complexity)

    # Create both plots and return both images
    def save_plot_as_base64(fig):
        buffer = io.BytesIO()
        fig.savefig(buffer, format='png', dpi=120)
        buffer.seek(0)
        img_base64 = base64.b64encode(buffer.read()).decode('utf-8')
        buffer.close()
        plt.close(fig)
        return img_base64

    # Plot 1: Boxplot + Swarmplot
    fig1, ax1 = plt.subplots(figsize=(12, 8))
    sns.boxplot(
        data=patched_vulns,
        x='Patch Complexity',
        y='Days to Patch',
        order=['Emergency', 'OS-Level', 'Runtime', 'Application'],
        palette='Set2',
        ax=ax1,
        showfliers=False
    )
    sns.swarmplot(
        data=patched_vulns,
        x='Patch Complexity',
        y='Days to Patch',
        color='black',
        size=4,
        alpha=0.5,
        ax=ax1
    )
    ax1.set_title(f'Box-Plot : Time-to-Patch for Critical Vulnerabilities (Last {time_window_days} Days)')
    ax1.set_xlabel('Patch Complexity Category')
    ax1.set_ylabel('Days from Discovery to Patch')
    ax1.grid(axis='y', linestyle='--', alpha=0.5)
    box_swarm_base64 = save_plot_as_base64(fig1)

    # Plot 2: Violin Plot
    fig2, ax2 = plt.subplots(figsize=(12, 8))
    sns.violinplot(
        data=patched_vulns,
        x='Patch Complexity',
        y='Days to Patch',
        order=['Emergency', 'OS-Level', 'Runtime', 'Application'],
        palette='Set1',
        inner='box',
        ax=ax2
    )
    ax2.set_title(f'Violin Graph : Distribution of Patch Times for Critical Vulnerabilities (Last {time_window_days} Days)')
    ax2.set_xlabel('Patch Complexity Category')
    ax2.set_ylabel('Days from Discovery to Patch')
    ax2.grid(axis='y', linestyle='--', alpha=0.5)
    violin_base64 = save_plot_as_base64(fig2)

    stats = patched_vulns.groupby('Patch Complexity')['Days to Patch'].describe()[['count', 'mean', '50%', 'min', 'max']]
    stats.columns = ['count', 'average_days', 'median_days', 'min_days', 'max_days']

    return {
        "type": "image",
        "graph": box_swarm_base64,
        "graph1": violin_base64
    }
