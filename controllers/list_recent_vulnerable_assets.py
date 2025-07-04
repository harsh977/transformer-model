import pandas as pd
import matplotlib.pyplot as plt
import io
import base64

def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['Plugin Modification Date'])
    df = df.sort_values(by='Plugin Modification Date', ascending=False)
    latest_df = df.drop_duplicates(subset=['IP Address', 'Port'], keep='first')
    return latest_df

def generate_vulnerability_table_plot(df: pd.DataFrame) -> str:
    fig, ax = plt.subplots(figsize=(14, len(df) * 0.5 + 1))
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

async def list_recent_vulnerable_assets(records):
    if not records:
        return {"message": "No records found"}
    
    df = pd.DataFrame(records)
    df = get_latest_assets(df)

    vulnerable_df = df[df['Severity'].isin(['High', 'Critical'])]

    result = vulnerable_df[['IP Address', 'Port', 'Severity', 'Plugin Name', 'Plugin Modification Date']]
    result = result.sort_values(by='Plugin Modification Date', ascending=False)

    table_plot_base64 = generate_vulnerability_table_plot(result)

    return {
        "intent": "list_recent_vulnerable_assets",
        "type": "image",
        "plot_type": "table",
        "title": "Recent High/Critical Vulnerable Assets",
        "columns": list(result.columns),
        "data": result.to_dict(orient='records'),
        "graph": table_plot_base64  # You can render this using <img src=...>
    }
