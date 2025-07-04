import pandas as pd
import matplotlib.pyplot as plt
import io
import base64
from datetime import datetime, timedelta

def generate_table_plot(df: pd.DataFrame) -> str:
    fig, ax = plt.subplots(figsize=(12, len(df) * 0.5 + 1))
    ax.axis('tight')
    ax.axis('off')

    table = ax.table(
        cellText=df.values,
        colLabels=df.columns,
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
    return f"data:image/png;base64,{base64.b64encode(buf.read()).decode()}"

async def show_assets_not_scanned_recently(records):
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['Plugin Modification Date'])

    cutoff_date = datetime.now() - timedelta(days=30)
    df = df.sort_values(by='Plugin Modification Date', ascending=False)
    latest_scans = df.drop_duplicates(subset=['IP Address', 'Port'], keep='first')
    not_recent = latest_scans[latest_scans['Plugin Modification Date'] < cutoff_date]

    result = not_recent[['IP Address', 'Port', 'Plugin Modification Date']]
    result = result.sort_values(by='Plugin Modification Date')  # Optional: sort ascending by date

    table_plot_base64 = generate_table_plot(result)

    return {
        "intent": "show_assets_not_scanned_recently",
        "type": "table",
        "plot_type": "table",
        "title": "Assets Not Scanned in Last 30 Days",
        "columns": list(result.columns),
        "data": result.to_dict(orient='records'),
        "graph": table_plot_base64
    }
