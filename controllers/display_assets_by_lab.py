import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
import matplotlib.cm as cm
import numpy as np

def generate_lab_bar_chart(df: pd.DataFrame) -> str:
    lab_counts = df['Lab name'].value_counts().sort_values(ascending=False)

    fig, ax = plt.subplots(figsize=(10, 6))

    # Generate a color for each bar using a colormap
    colors = cm.get_cmap('tab20')(np.linspace(0, 1, len(lab_counts)))

    bars = ax.bar(lab_counts.index, lab_counts.values, color=colors)
    ax.set_title("Number of Assets per Lab")
    ax.set_xlabel("Lab")
    ax.set_ylabel("Number of Assets")
    ax.tick_params(axis='x', rotation=45)

    for bar in bars:
        yval = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2, yval + 0.5, int(yval), ha='center', va='bottom')

    plt.tight_layout()
    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    return base64.b64encode(buf.read()).decode('utf-8')

async def display_assets_by_lab(records):
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)

    if 'Lab name' not in df.columns:
        return {"message": "Missing 'Lab' column in records"}

    lab_counts = df['Lab name'].value_counts().sort_values(ascending=False)
    chart_image = generate_lab_bar_chart(df)

    data = [{"Lab name": lab, "Asset Count": count} for lab, count in lab_counts.items()]

    return {
        "type": "image",
        "graph": chart_image
    }
