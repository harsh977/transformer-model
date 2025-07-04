import pandas as pd
import matplotlib.pyplot as plt
import io
import base64

def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
    df = df.copy()
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['Plugin Modification Date'])
    df = df.sort_values(by='Plugin Modification Date', ascending=False)
    latest_df = df.drop_duplicates(subset=['MAC Address'], keep='first')
    return latest_df

def generate_table_image(table_df: pd.DataFrame) -> str:
    fig, ax = plt.subplots(figsize=(10, len(table_df) * 0.5 + 1))
    ax.axis('tight')
    ax.axis('off')
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
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    return img_base64

async def display_last_scanned_date(records):
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty or 'Plugin Modification Date' not in df.columns:
        return {"message": "Required column not found"}

    df = get_latest_assets(df)

    result_df = df[['MAC Address', 'Plugin Modification Date']].copy()
    result_df = result_df.rename(columns={'Plugin Modification Date': 'Last Scanned'})

    # Sort by Last Scanned (latest on top)
    result_df = result_df.sort_values(by='Last Scanned', ascending=False).head(10)

    # Generate table graph image
    table_image = generate_table_image(result_df)

    return {
        "type": "image",
        "graph": table_image
    }
