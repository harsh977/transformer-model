import pandas as pd
from datetime import datetime, timedelta
from typing import List, Dict

def get_latest_assets(df: pd.DataFrame) -> pd.DataFrame:
    """Consistent with other intents - gets latest records for each unique asset"""
    df = df.copy()
    df['Plugin Modification Date'] = pd.to_datetime(df['Plugin Modification Date'], errors='coerce')
    df = df.dropna(subset=['Plugin Modification Date'])
    df['vuln_id'] = df['IP Address'] + "|" + df['Port'].astype(str) + "|" + df['Plugin'].astype(str)
    df = df.sort_values('Plugin Modification Date', ascending=False)
    return df.drop_duplicates(subset=['vuln_id'], keep='first')

def identify_patch_candidates(df: pd.DataFrame) -> pd.DataFrame:
    """
    Identifies vulnerabilities that likely require patching based on:
    - Severity (Critical/High)
    - Recent discovery (last 30 days)
    - Patch availability (from plugin data)
    """
    # Filter for high severity vulnerabilities
    patch_candidates = df[df['Severity'].isin(['Critical', 'High'])]
    
    # Filter for recent vulnerabilities (last 30 days)
    recent_threshold = datetime.now() - timedelta(days=30)
    patch_candidates = patch_candidates[
        pd.to_datetime(patch_candidates['Plugin Modification Date']) >= recent_threshold
    ]
    
    # Filter for vulnerabilities with patch information
    if 'Patch Available' in patch_candidates.columns:
        patch_candidates = patch_candidates[patch_candidates['Patch Available'].str.contains('Yes', case=False, na=False)]
    elif 'Solution' in patch_candidates.columns:
        patch_candidates = patch_candidates[patch_candidates['Solution'].str.contains('patch|update|upgrade', case=False, na=False)]
    
    return patch_candidates

async def send_patch_update_notifications(records: List[Dict], recipients: List[str] = None) -> Dict:
    """
    Identifies vulnerabilities requiring patching and generates notifications
    
    Args:
        records: List of vulnerability scan records
        recipients: List of email addresses to receive notifications
    """
    if not records:
        return {"message": "No records found"}

    df = pd.DataFrame(records)
    if df.empty:
        return {"message": "Data is empty"}

    # Get latest records for each vulnerability
    df = get_latest_assets(df)
    
    # Identify patch candidates
    patch_candidates = identify_patch_candidates(df)
    
    if patch_candidates.empty:
        return {
            "intent": "send_patch_update_notifications",
            "task_type": "action",
            "plot_type": "notification",
            "status": "completed",
            "message": "No patchable vulnerabilities found in recent scans",
            "data": {
                "total_vulnerabilities": len(df),
                "critical_high_vulnerabilities": len(df[df['Severity'].isin(['Critical', 'High'])]),
                "patch_candidates_found": 0
            }
        }
    
    # Prepare notification data
    notification_data = patch_candidates[[
        'IP Address',
        'DNS Name',
        'Plugin Name',
        'Severity',
        'Plugin Modification Date',
        'Solution'
    ]].rename(columns={
        'IP Address': 'ip',
        'DNS Name': 'hostname',
        'Plugin Name': 'vulnerability',
        'Plugin Modification Date': 'discovered_date'
    })
    
    # Group by vulnerability type for summary
    vulnerability_summary = patch_candidates.groupby(['Plugin Name', 'Severity']).size().reset_index()
    vulnerability_summary.columns = ['vulnerability', 'severity', 'count']
    
    # Prepare response
    response = {
        "intent": "send_patch_update_notifications",
        "task_type": "action",
        "plot_type": "notification",
        "status": "completed",
        "message": f"Found {len(patch_candidates)} vulnerabilities requiring patching",
        "data": {
            "total_vulnerabilities": len(df),
            "critical_high_vulnerabilities": len(df[df['Severity'].isin(['Critical', 'High'])]),
            "patch_candidates_found": len(patch_candidates),
            "affected_systems": len(patch_candidates[['IP Address', 'Port']].drop_duplicates()),
            "vulnerability_summary": vulnerability_summary.to_dict('records'),
            "notification_recipients": recipients or [],
            "notification_sample": {
                "subject": f"Patch Notification: {len(patch_candidates)} Critical/High Vulnerabilities Found",
                "body": f"""Security Patch Notification\n
Found {len(patch_candidates)} vulnerabilities requiring immediate attention:\n
- Critical: {len(patch_candidates[patch_candidates['Severity'] == 'Critical'])}
- High: {len(patch_candidates[patch_candidates['Severity'] == 'High'])}\n
Top vulnerabilities:\n""" +
                "\n".join([f"{row['vulnerability']} ({row['severity']}): {row['count']} systems" 
                          for _, row in vulnerability_summary.head(5).iterrows()]) +
                f"\n\nPlease review the attached details and schedule patching immediately."
            },
            "detailed_findings": notification_data.to_dict('records')
        }
    }
    
    return response