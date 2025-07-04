import pandas as pd
import matplotlib.pyplot as plt
import matplotlib.patches as patches
import numpy as np
import io
import base64
from datetime import datetime

def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['Plugin Modification Date'])
    df = df.sort_values(by='Plugin Modification Date', ascending=False)
    return df.drop_duplicates(subset=['IP Address', 'Port'], keep='first')

def generate_gauge_image(percent: float, vulnerable: int, total: int, 
                        severity_breakdown: dict = None) -> str:
    """
    Generates a detailed gauge chart with:
    - Main vulnerability percentage gauge
    - Severity breakdown pie chart
    - Risk level indicator
    - Key metrics summary
    """
    import matplotlib.pyplot as plt
    import numpy as np
    from matplotlib.patches import Wedge
    from matplotlib.colors import LinearSegmentedColormap
    
    # Setup figure with custom layout
    fig = plt.figure(figsize=(12, 8), facecolor='#f5f5f5')
    fig.suptitle('Asset Vulnerability Dashboard', 
                fontsize=16, fontweight='bold', y=0.95)
    
    # Custom color gradients
    gauge_cmap = LinearSegmentedColormap.from_list(
        'gauge', ['#2ecc71', '#f1c40f', '#e74c3c'])
    severity_colors = {
        'Critical': '#e74c3c',
        'High': '#e67e22',
        'Medium': '#f1c40f',
        'Low': '#2ecc71'
    }
    
    # --- Main Gauge ---
    ax_gauge = fig.add_axes([0.1, 0.3, 0.5, 0.5], polar=True)
    ax_gauge.set_theta_offset(np.pi/2)
    ax_gauge.set_theta_direction(-1)
    
    # Draw colored arcs
    for i in range(0, 101, 5):
        theta = np.radians(i * 1.8)
        ax_gauge.bar(theta, 1, width=np.radians(1.8*5), 
                    color=gauge_cmap(i/100),
                    alpha=0.8, linewidth=0)
    
    # Add risk level zones
    ax_gauge.text(np.radians(0), 1.2, "Low Risk", ha='center', 
                 fontsize=10, color='#27ae60')
    ax_gauge.text(np.radians(90), 1.2, "Medium Risk", ha='center', 
                 fontsize=10, color='#f39c12')
    ax_gauge.text(np.radians(180), 1.2, "High Risk", ha='center', 
                 fontsize=10, color='#c0392b')
    
    # Add needle
    theta = np.radians(percent * 1.8)
    ax_gauge.plot([theta, theta], [0, 0.9], color='#34495e', 
                 linewidth=4, solid_capstyle='round')
    ax_gauge.plot(theta, 0.9, marker='o', markersize=15, 
                 color='#34495e', markeredgecolor='white', linewidth=2)
    
    # Add center text
    ax_gauge.text(0, 0, f"{percent:.1f}%\nVulnerable", 
                 ha='center', va='center', 
                 fontsize=18, fontweight='bold', 
                 color='#2c3e50')
    
    # --- Severity Breakdown ---
    if severity_breakdown:
        ax_pie = fig.add_axes([0.6, 0.4, 0.35, 0.35])
        wedges, texts = ax_pie.pie(
            severity_breakdown.values(),
            colors=[severity_colors[s] for s in severity_breakdown.keys()],
            startangle=90,
            wedgeprops={'width': 0.4, 'edgecolor': 'white', 'linewidth': 2}
        )
        
        # Add legend
        ax_pie.legend(
            wedges, 
            [f"{k} ({v})" for k, v in severity_breakdown.items()],
            title="Vulnerability Severity",
            loc="center left",
            bbox_to_anchor=(1, 0, 0.5, 1)
        )
        ax_pie.set_title('Severity Distribution', pad=20)
    
    # --- Metrics Summary ---
    ax_text = fig.add_axes([0.1, 0.1, 0.8, 0.15])
    ax_text.axis('off')
    
    metrics_text = [
        f"• Vulnerable Assets: {vulnerable:,} of {total:,}",
        f"• Risk Level: {'Low' if percent < 30 else 'Medium' if percent < 70 else 'High'}",
        f"• Last Scanned: {datetime.now().strftime('%Y-%m-%d')}",
        f"• Critical Assets: {severity_breakdown.get('Critical', 0) if severity_breakdown else 'N/A'}"
    ]
    
    ax_text.text(
        0.02, 0.8, "\n".join(metrics_text),
        fontsize=12,
        linespacing=1.5,
        color='#34495e'
    )
    
    # Add risk indicator
    risk_color = '#27ae60' if percent < 30 else '#f39c12' if percent < 70 else '#e74c3c'
    ax_text.add_patch(
        plt.Rectangle((0.8, 0.7), 0.15, 0.2, 
                     color=risk_color, alpha=0.2)
    )
    ax_text.text(
        0.875, 0.8, "RISK", 
        ha='center', va='center', 
        fontsize=14, fontweight='bold',
        color=risk_color
    )
    
    # Export image
    buf = io.BytesIO()
    plt.savefig(buf, format='png', dpi=120, bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')



async def show_vulnerable_asset_percentage(records):
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    df = get_latest_assets(df)

    df['is_vulnerable'] = df['Severity'].str.lower().isin(['low', 'medium', 'high', 'critical'])

    unique_assets = df[['IP Address', 'Port']].drop_duplicates()
    total_assets = unique_assets.shape[0]

    vulnerable_assets = df[df['is_vulnerable']][['IP Address', 'Port']].drop_duplicates()
    vulnerable_count = vulnerable_assets.shape[0]

    percent = round((vulnerable_count / total_assets) * 100, 2) if total_assets > 0 else 0.0

    # Generate gauge plot image
    gauge_img  = generate_gauge_image(percent, vulnerable_count, total_assets)

    return {
        "type": "image",
        "graph": gauge_img  # For frontend: <img src="..." />
    }
