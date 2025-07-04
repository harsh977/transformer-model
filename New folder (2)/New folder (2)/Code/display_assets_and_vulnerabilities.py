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
    fig, ax = plt.subplots(figsize=(12, len(table_df)*0.5 + 1))  # Dynamically adjust height
    ax.axis('tight')
    ax.axis('off')
    table = ax.table(cellText=table_df.values,
                     colLabels=table_df.columns,
                     cellLoc='left',
                     loc='center')
    table.auto_set_font_size(False)
    table.set_fontsize(10)
    table.scale(1, 1.2)

    buf = io.BytesIO()
    plt.savefig(buf, format='png', bbox_inches='tight')
    plt.close(fig)
    buf.seek(0)
    img_base64 = base64.b64encode(buf.read()).decode('utf-8')
    return img_base64

async def display_assets_and_vulnerabilities(records):
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    df = get_latest_assets(df)

    # Define required columns
    required_columns = ['MAC Address', 'Plugin Name', 'Severity']
    for col in required_columns:
        if col not in df.columns:
            return {"message": f"Missing column: {col}"}

    # Prepare the asset-vulnerability table
    table_df = df[required_columns].dropna().head(10)
    table_df = table_df.rename(columns={
        'MAC Address': 'MAC',
        'Plugin Name': 'Vulnerability',
        'Severity': 'Severity Level'
    })

    # Convert to list of dicts for JSON response
    data = table_df.to_dict(orient='records')

    # Generate matplotlib table image
    table_image = generate_table_image(table_df)

    return {
        "type": "image",
        "graph": table_image  # base64 image that frontend can render as <img src=...>
    }













# import pandas as pd
# import plotly.graph_objects as go
# from plotly.io import to_json

# def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
#     df = df.copy()
#     df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
#     df = df.dropna(subset=['Plugin Modification Date'])
#     df = df.sort_values(by='Plugin Modification Date', ascending=False)
#     latest_df = df.drop_duplicates(subset=['IP Address', 'Port'], keep='first')
#     return latest_df

# async def display_assets_and_vulnerabilities(records):
#     if not records:
#         return {"message": "No records found"}

#     df = pd.DataFrame(records)
#     if df.empty:
#         return {"message": "Data is empty"}

#     df = get_latest_assets(df)

#     # Define required columns
#     required_columns = ['IP Address', 'Port', 'Plugin Name', 'Severity']
#     for col in required_columns:
#         if col not in df.columns:
#             return {"message": f"Missing column: {col}"}

#     # Prepare the asset-vulnerability table
#     table_df = df[required_columns].dropna()
#     table_df = table_df.rename(columns={
#         'IP Address': 'IP',
#         'Plugin Name': 'Vulnerability',
#         'Severity': 'Severity Level'
#     })

#     # Convert to list of dicts for JSON response
#     data = table_df.to_dict(orient='records')

#     # Plotly table for visualization
#     fig = go.Figure(data=[go.Table(
#         header=dict(values=['IP', 'Port', 'Vulnerability', 'Severity Level'],
#                     fill_color='paleturquoise',
#                     align='left'),
#         cells=dict(values=[
#             table_df['IP'],
#             table_df['Port'],
#             table_df['Vulnerability'],
#             table_df['Severity Level']
#         ],
#         fill_color='lavender',
#         align='left'))
#     ])

#     table_graph_json = to_json(fig)  # Serializes Plotly figure to JSON for frontend rendering

#     return {
#         "intent": "display_assets_and_vulnerabilities",
#         "type": "table",
#         "plot_type": "table",
#         "title": "Assets and Associated Vulnerabilities",
#         "columns": ['IP', 'Port', 'Vulnerability', 'Severity Level'],
#         "data": data,
#         "table_graph": table_graph_json  # <-- Added graph JSON here
#     }
