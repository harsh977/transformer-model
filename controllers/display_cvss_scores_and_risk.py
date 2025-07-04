import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64
from datetime import datetime

def calculate_risk_level(cvss_score: float) -> str:
    """Categorize CVSS scores into risk levels."""
    if pd.isna(cvss_score):
        return "Not Available"
    if cvss_score >= 9.0:
        return "Critical"
    elif cvss_score >= 7.0:
        return "High"
    elif cvss_score >= 4.0:
        return "Medium"
    elif cvss_score > 0.0:
        return "Low"
    else:
        return "Informational"

async def display_cvss_scores_and_risk(records: list) -> dict:
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    df['datetime'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['datetime'])
    df['vuln_id'] = df['IP Address'] + "|" + df['Plugin'].astype(str) + "|" + df['Port'].astype(str)
    latest_vulns = df.sort_values('datetime').groupby('vuln_id').tail(1)

    latest_vulns['CVSS_Score'] = latest_vulns['CVSS V3 Base Score'].fillna(latest_vulns['CVSS V2 Base Score'])
    latest_vulns['CVSS_Version'] = np.where(
        latest_vulns['CVSS V3 Base Score'].notna(),
        'v3.0',
        np.where(latest_vulns['CVSS V2 Base Score'].notna(), 'v2.0', 'N/A')
    )
    latest_vulns['Risk_Level'] = latest_vulns['CVSS_Score'].apply(calculate_risk_level)

    cvss_data = latest_vulns[latest_vulns['CVSS_Score'].notna()].copy()
    cvss_data = cvss_data.sort_values('CVSS_Score', ascending=False)
    if len(cvss_data) > 50:
        cvss_data = cvss_data.head(50)

    # ✅ Heatmap with safe bins
    plt.figure(figsize=(10, 6))
    heatmap_data = pd.pivot_table(
        cvss_data,
        values='CVSS_Score',
        index='Risk_Level',
        columns=pd.cut(cvss_data['CVSS_Score'], bins=[-0.1, 4, 7, 9, 10]),  # safe for 0s
        aggfunc='count',
        fill_value=0
    )
    risk_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
    heatmap_data = heatmap_data.reindex([r for r in risk_order if r in heatmap_data.index])

    if not heatmap_data.empty:
        sns.heatmap(
            heatmap_data,
            annot=True,
            fmt='g',
            cmap='YlOrRd',
            cbar_kws={'label': 'Number of Vulnerabilities'}
        )
        plt.title('CVSS Score Distribution by Risk Level', pad=20)
        plt.xlabel('CVSS Score Range', labelpad=10)
        plt.ylabel('Risk Level', labelpad=10)
        plt.tight_layout()

        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=120)
        buffer.seek(0)
        heatmap_image = base64.b64encode(buffer.read()).decode('utf-8')
        buffer.close()
        plt.close()
    else:
        heatmap_image = None

    # ✅ Comparison chart
    comparison_data = latest_vulns[
        latest_vulns['CVSS V2 Base Score'].notna() & latest_vulns['CVSS V3 Base Score'].notna()
    ].copy()

    if not comparison_data.empty:
        comparison_data = comparison_data.sort_values('CVSS V3 Base Score', ascending=False).head(20)
        comparison_data['Label'] = comparison_data['IP Address'] + ":" + comparison_data['Port'].astype(str)

        plt.figure(figsize=(12, 8))
        y_pos = np.arange(len(comparison_data))
        bar_width = 0.35

        plt.barh(
            y_pos - bar_width/2,
            comparison_data['CVSS V2 Base Score'],
            height=bar_width,
            color='skyblue',
            label='CVSS V2'
        )
        plt.barh(
            y_pos + bar_width/2,
            comparison_data['CVSS V3 Base Score'],
            height=bar_width,
            color='salmon',
            label='CVSS V3'
        )

        for i, (v2, v3) in enumerate(zip(
            comparison_data['CVSS V2 Base Score'],
            comparison_data['CVSS V3 Base Score']
        )):
            plt.text(v2 + 0.2, i - bar_width/2, f"{v2:.1f}", va='center')
            plt.text(v3 + 0.2, i + bar_width/2, f"{v3:.1f}", va='center')

        plt.yticks(y_pos, comparison_data['Label'])
        plt.xlabel('CVSS Score')
        plt.title('Comparison of CVSS V2 and V3 Scores')
        plt.legend()
        plt.tight_layout()

        buffer = io.BytesIO()
        plt.savefig(buffer, format='png', dpi=120)
        buffer.seek(0)
        comparison_image = base64.b64encode(buffer.read()).decode('utf-8')
        buffer.close()
        plt.close()
    else:
        comparison_image = None

    return {
        "type": "image",
        "graph": heatmap_image,
        "graph1": comparison_image
    }





# import pandas as pd
# import numpy as np
# import matplotlib.pyplot as plt
# import seaborn as sns
# import io
# import base64
# from datetime import datetime

# # Set backend to avoid GUI window
# plt.switch_backend('Agg')

# def calculate_risk_level(cvss_score: float) -> str:
#     """Categorize CVSS scores into risk levels."""
#     if pd.isna(cvss_score):
#         return "Not Available"
#     if cvss_score >= 9.0:
#         return "Critical"
#     elif cvss_score >= 7.0:
#         return "High"
#     elif cvss_score >= 4.0:
#         return "Medium"
#     elif cvss_score > 0.0:
#         return "Low"
#     else:
#         return "Informational"

# async def display_cvss_scores_and_risk(records: list) -> dict:
#     """Generate a table of vulnerabilities with CVSS scores and risk levels."""
#     if not records:
#         return {"message": "No records found"}

#     df = pd.DataFrame(records)
#     if df.empty:
#         return {"message": "Data is empty"}

#     # Get latest vulnerabilities (IP+Plugin+Port combination)
#     df['datetime'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
#     df = df.dropna(subset=['datetime'])
#     df['vuln_id'] = df['IP Address'] + "|" + df['Plugin'].astype(str) + "|" + df['Port'].astype(str)
#     latest_vulns = df.sort_values('datetime').groupby('vuln_id').tail(1)

#     # Prepare CVSS data - handle both V2 and V3 scores
#     latest_vulns['CVSS_Score'] = latest_vulns['CVSS V3 Base Score'].fillna(latest_vulns['CVSS V2 Base Score'])
#     latest_vulns['CVSS_Version'] = np.where(
#         latest_vulns['CVSS V3 Base Score'].notna(), 
#         'v3.0', 
#         np.where(latest_vulns['CVSS V2 Base Score'].notna(), 'v2.0', 'N/A')
#     )
    
#     # Calculate risk levels
#     latest_vulns['Risk_Level'] = latest_vulns['CVSS_Score'].apply(calculate_risk_level)
    
#     # Filter only vulnerabilities with CVSS scores
#     cvss_data = latest_vulns[latest_vulns['CVSS_Score'].notna()].copy()
    
#     # Sort by CVSS score (descending) and select top 50 if too many
#     cvss_data = cvss_data.sort_values('CVSS_Score', ascending=False)
#     if len(cvss_data) > 50:
#         cvss_data = cvss_data.head(50)
    
#     # Prepare table data
#     table_data = cvss_data[[
#         'IP Address',
#         'DNS Name',
#         'Plugin Name',
#         'Port',
#         'CVSS_Score',
#         'CVSS_Version',
#         'Risk_Level',
#         'Synopsis'
#     ]].rename(columns={
#         'IP Address': 'IP',
#         'DNS Name': 'Hostname',
#         'Plugin Name': 'Vulnerability',
#         'CVSS_Score': 'CVSS Score',
#         'CVSS_Version': 'CVSS Version',
#         'Risk_Level': 'Risk Level'
#     })
    
#     # Convert to list of dictionaries for frontend
#     table_records = table_data.to_dict('records')
    
#     # Generate a summary heatmap image
#     plt.figure(figsize=(10, 6))
    
#     # Create pivot table for heatmap
#     heatmap_data = pd.pivot_table(
#         cvss_data,
#         values='CVSS_Score',
#         index='Risk_Level',
#         columns=pd.cut(cvss_data['CVSS_Score'], bins=[0, 4, 7, 9, 10]),
#         aggfunc='count',
#         fill_value=0
#     )
    
#     # Reorder risk levels for visualization
#     risk_order = ['Critical', 'High', 'Medium', 'Low', 'Informational']
#     heatmap_data = heatmap_data.reindex([r for r in risk_order if r in heatmap_data.index])
    
#     sns.heatmap(
#         heatmap_data, 
#         annot=True, 
#         fmt='g',
#         cmap='YlOrRd',
#         cbar_kws={'label': 'Number of Vulnerabilities'}
#     )
    
#     plt.title('CVSS Score Distribution by Risk Level', pad=20)
#     plt.xlabel('CVSS Score Range', labelpad=10)
#     plt.ylabel('Risk Level', labelpad=10)
#     plt.tight_layout()
    
#     # Save heatmap image
#     buffer = io.BytesIO()
#     plt.savefig(buffer, format='png', dpi=120)
#     buffer.seek(0)
#     heatmap_image = base64.b64encode(buffer.read()).decode('utf-8')
#     buffer.close()
#     plt.close()
    
#     # Prepare response
#     return {
#         "intent": "display_cvss_scores_and_risk",
#         "task_type": "list",
#         "plot_type": "table",
#         "description": "Table of vulnerabilities with CVSS scores and risk assessment",
#         "data": {
#             "table_headers": list(table_data.columns),
#             "table_rows": table_records,
#             "summary": {
#                 "total_vulnerabilities": len(cvss_data),
#                 "critical_count": len(cvss_data[cvss_data['Risk_Level'] == 'Critical']),
#                 "high_count": len(cvss_data[cvss_data['Risk_Level'] == 'High']),
#                 "average_cvss": round(cvss_data['CVSS_Score'].mean(), 2),
#                 "heatmap_image": heatmap_image
#             }
#         }
#     }