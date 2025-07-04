import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns
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

def categorize_vulnerability(plugin_name: str) -> str:
    plugin_name = str(plugin_name).lower()

    os_keywords = [
        'windows', 'linux', 'unix', 'kernel', 'microsoft', 'red hat', 'debian',
        'ubuntu', 'macos', 'centos', 'os x', 'suse', 'aix', 'solaris', 'vmware tools'
    ]

    app_keywords = [
        'http', 'https', 'ssl', 'tls', 'apache', 'nginx', 'iis', 'tomcat',
        'wordpress', 'drupal', 'php', 'java', 'dotnet', 'ftp', 'mysql',
        'oracle', 'mongodb', 'postgres', 'samba', 'dns', 'email', 'smtp'
    ]

    if any(keyword in plugin_name for keyword in os_keywords):
        return 'OS'
    elif any(keyword in plugin_name for keyword in app_keywords):
        return 'Application'
    return 'Other'

async def display_os_vs_application_vulnerabilities(records: List[Dict]) -> Dict:
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    df = get_latest_assets(df)

    df['Vulnerability Type'] = df['Plugin Name'].apply(categorize_vulnerability)

    filtered_df = df[df['Vulnerability Type'].isin(['OS', 'Application'])]

    if filtered_df.empty:
        return {"message": "No OS/Application vulnerabilities found"}

    vuln_counts = filtered_df.groupby(['Vulnerability Type', 'Severity']).size().unstack(fill_value=0)

    for severity in ['Critical', 'High', 'Medium', 'Low']:
        if severity not in vuln_counts.columns:
            vuln_counts[severity] = 0

    vuln_counts = vuln_counts[['Critical', 'High', 'Medium', 'Low']]

    plt.figure(figsize=(12, 6))
    ax = vuln_counts.plot(kind='bar', stacked=True,
                          color={'Critical': '#d62728', 'High': '#ff7f0e',
                                 'Medium': '#f7e11a', 'Low': '#2ca02c'},
                          figsize=(10, 6))

    # Add value labels on each segment of stacked bars
    for idx, bar in enumerate(ax.containers):
        for rect in bar:
            height = rect.get_height()
            if height > 0:
                ax.text(rect.get_x() + rect.get_width()/2,
                        rect.get_y() + height/2,
                        str(int(height)),
                        ha='center', va='center', fontsize=9)

    plt.title('OS vs Application Vulnerabilities by Severity')
    plt.xlabel('Vulnerability Type')
    plt.ylabel('Number of Vulnerabilities')
    plt.xticks(rotation=0)
    plt.grid(axis='y', linestyle='--', alpha=0.7)
    plt.legend(title='Severity Level')
    plt.tight_layout()

    buffer = io.BytesIO()
    plt.savefig(buffer, format='png', dpi=120)
    buffer.seek(0)
    plot_image = base64.b64encode(buffer.read()).decode('utf-8')
    buffer.close()
    plt.close()

    response_data = {
        "os_vulnerabilities": {
            "Critical": int(vuln_counts.loc['OS', 'Critical']),
            "High": int(vuln_counts.loc['OS', 'High']),
            "Medium": int(vuln_counts.loc['OS', 'Medium']),
            "Low": int(vuln_counts.loc['OS', 'Low']),
            "Total": int(vuln_counts.loc['OS'].sum())
        },
        "application_vulnerabilities": {
            "Critical": int(vuln_counts.loc['Application', 'Critical']),
            "High": int(vuln_counts.loc['Application', 'High']),
            "Medium": int(vuln_counts.loc['Application', 'Medium']),
            "Low": int(vuln_counts.loc['Application', 'Low']),
            "Total": int(vuln_counts.loc['Application'].sum())
        },
        "ratio": {
            "os_percentage": round(vuln_counts.loc['OS'].sum() / vuln_counts.sum().sum() * 100, 2),
            "app_percentage": round(vuln_counts.loc['Application'].sum() / vuln_counts.sum().sum() * 100, 2)
        }
    }

    return {
        "type": "image",
        "graph": plot_image
    }
