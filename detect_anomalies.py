"""
detect_anomalies.py
PrivGuard-Anomaly-Monitor: Privileged Account Anomaly Detection Engine

Analyzes synthetic Windows event logs to identify privileged account anomalies based on:
1. Off-hours administrative logon / activity
2. Failed logins / abnormal logon type behavior
3. Privileged grants & sensitive elevation (Event 4672)
4. Suspicious process executions, unauthorized hosts, and untrusted destination IPs

Calculates a normalized multi-factor Risk Score (0-100) and exports flagged anomalies
to flagged_anomalies.csv.
"""

import os
import sys
from datetime import datetime
import numpy as np
import pandas as pd


# Baseline profiles for privileged personas
PERSONA_PROFILES = {
    "admin_tanish": {
        "role": "SecOps Administrator",
        "active_hours": (8, 19),  # 08:00 to 19:00
        "authorized_hosts": {"SEC-WS-01", "DC-PROD-01", "SEC-MGMT-02", "SIEM-COLLECTOR-01"},
        "standard_processes": {"powershell.exe", "mmc.exe", "mstsc.exe", "explorer.exe", "svchost.exe"},
        "standard_logon_types": {2, 10, 3},
    },
    "admin_himanshu": {
        "role": "Infrastructure Administrator",
        "active_hours": (9, 21),  # 09:00 to 21:00
        "authorized_hosts": {"INFRA-WS-02", "DC-PROD-02", "APP-SRV-01", "DB-SRV-02"},
        "standard_processes": {"pwsh.exe", "cmd.exe", "ServerManager.exe", "vmware-vmx.exe", "explorer.exe"},
        "standard_logon_types": {2, 3, 10},
    },
    "admin_backup": {
        "role": "Backup Service Account",
        "active_hours": (0, 6),  # Midnight to 06:00 batch window
        "authorized_hosts": {"BKP-SRV-01", "STORAGE-NAS-01", "DC-PROD-01", "DB-SRV-01"},
        "standard_processes": {"wbengine.exe", "backupagent.exe", "powershell.exe", "robocopy.exe", "services.exe"},
        "standard_logon_types": {4, 5, 3},  # Batch (4), Service (5), Network (3)
    },
}

SUSPICIOUS_PROCESS_LIST = {
    "mimikatz.exe",
    "psexec.exe",
    "vssadmin.exe",
    "certutil.exe",
    "net1.exe",
    "cobaltstrike.exe",
    "nc.exe",
    "rundll32.exe",
}

KNOWN_EXTERNAL_THREAT_IPS = {
    "185.220.101.5",
    "45.33.32.156",
    "194.26.29.112",
    "103.208.220.122",
    "91.240.118.172",
}


def is_private_ip(ip_str: str) -> bool:
    """Determine if an IP address belongs to RFC1918 / Loopback private ranges."""
    if not isinstance(ip_str, str):
        return True
    ip = ip_str.strip()
    if ip in ("127.0.0.1", "localhost", "::1"):
        return True
    if ip.startswith("10."):
        return True
    if ip.startswith("192.168."):
        return True
    if ip.startswith("172."):
        parts = ip.split(".")
        if len(parts) >= 2 and parts[1].isdigit():
            second_octet = int(parts[1])
            if 16 <= second_octet <= 31:
                return True
    return False


def evaluate_record(row: pd.Series) -> dict:
    """
    Apply multi-factor anomaly detection rules and compute risk score for a single log record.
    """
    user = row.get("username", "")
    event_id = int(row.get("event_id", 0))
    hostname = str(row.get("hostname", ""))
    process_name = str(row.get("process_name", "")).lower()
    dest_ip = str(row.get("destination_ip", ""))
    logon_type = int(row.get("logon_type", 0)) if pd.notnull(row.get("logon_type")) else 0
    ts = row["dt"]

    profile = PERSONA_PROFILES.get(user, None)
    triggered_rules = []
    risk_score = 0

    # Rule 1: Off-Hours Activity Detection
    is_off_hours = False
    if profile:
        start_h, end_h = profile["active_hours"]
        hour = ts.hour
        if start_h <= end_h:
            # Daytime window
            if hour < start_h or hour > end_h:
                is_off_hours = True
        else:
            # Wrap-around nocturnal window
            if hour > end_h and hour < start_h:
                is_off_hours = True

        if is_off_hours:
            triggered_rules.append("OFF_HOURS_ACTIVITY")
            risk_score += 25
            # Deep night penalty for human admins (1 AM - 5 AM)
            if user in ("admin_tanish", "admin_himanshu") and (1 <= hour <= 5):
                triggered_rules.append("DEEP_NIGHT_HUMAN_LOGON")
                risk_score += 15

    # Rule 2: Failed Login & Abnormal Logon Type Detection
    # Event ID 4625 represents failed logins in Windows
    if event_id == 4625:
        triggered_rules.append("FAILED_LOGON_EVENT_4625")
        risk_score += 35
    
    # Abnormal logon type check (e.g., interactive login on automated backup service account)
    if profile and logon_type in (2, 10) and user == "admin_backup":
        triggered_rules.append("ABNORMAL_INTERACTIVE_SERVICE_LOGON")
        risk_score += 25
    elif profile and logon_type not in profile["standard_logon_types"]:
        triggered_rules.append("UNUSUAL_LOGON_TYPE")
        risk_score += 15

    # Rule 3: Privilege Grants / Sensitive Elevation (Event 4672)
    if event_id == 4672:
        triggered_rules.append("PRIVILEGE_GRANT_EVENT_4672")
        risk_score += 20
        # High risk if privilege granted during off-hours or from network logon
        if is_off_hours:
            triggered_rules.append("OFF_HOURS_PRIVILEGE_ELEVATION")
            risk_score += 20
        if logon_type == 3:  # Network logon receiving high privileges
            triggered_rules.append("NETWORK_PRIVILEGE_ASSIGNMENT")
            risk_score += 15

    # Rule 4: Suspicious Process Execution
    if process_name in SUSPICIOUS_PROCESS_LIST or any(bad in process_name for bad in ["mimikatz", "psexec", "vssadmin", "cobalt"]):
        triggered_rules.append(f"SUSPICIOUS_PROCESS_{process_name.upper()}")
        risk_score += 35

    # Rule 5: Untrusted / External Destination IP
    if dest_ip in KNOWN_EXTERNAL_THREAT_IPS or not is_private_ip(dest_ip):
        triggered_rules.append("UNTRUSTED_EXTERNAL_IP")
        risk_score += 30

    # Rule 6: Unauthorized / Rogue Host Access
    if any(prefix in hostname for prefix in ["UNKNOWN", "SHADOW", "ROGUE", "DMZ-EXT"]):
        triggered_rules.append("ROGUE_HOST_ACCESS")
        risk_score += 25
    elif profile and hostname not in profile["authorized_hosts"]:
        triggered_rules.append("UNAUTHORIZED_HOSTNAME")
        risk_score += 20

    # Normalize score to 0 - 100
    risk_score = min(100, risk_score)

    # Classify Severity
    if risk_score >= 70:
        severity = "CRITICAL"
    elif risk_score >= 45:
        severity = "HIGH"
    elif risk_score >= 25:
        severity = "MEDIUM"
    else:
        severity = "LOW"

    return {
        "risk_score": risk_score,
        "risk_severity": severity,
        "triggered_rules": ";".join(triggered_rules) if triggered_rules else "NONE",
        "is_flagged_anomaly": 1 if risk_score >= 45 else 0,
    }


def run_anomaly_detection(
    input_file: str = "synthetic_privileged_logs.csv",
    output_file: str = "flagged_anomalies.csv",
    risk_threshold: int = 45,
) -> tuple[pd.DataFrame, pd.DataFrame]:
    """
    Main detection pipeline:
    - Ingests raw logs
    - Applies multi-factor detection rules
    - Assigns risk scores and severity
    - Exports flagged anomalies to CSV
    """
    script_dir = os.path.dirname(os.path.abspath(__file__))
    input_path = os.path.join(script_dir, input_file)
    output_path = os.path.join(script_dir, output_file)

    if not os.path.exists(input_path):
        raise FileNotFoundError(f"Input log file not found: {input_path}")

    print(f"[*] Ingesting logs from: {input_path}")
    df = pd.read_csv(input_path)
    total_records = len(df)
    print(f"[*] Loaded {total_records:,} records.")

    # Parse timestamps
    df["dt"] = pd.to_datetime(df["timestamp"])

    # Apply detection rules
    print("[*] Applying detection rules (Off-Hours, Failed Logins, Privilege Grants, Threat Indicators)...")
    results = df.apply(evaluate_record, axis=1, result_type="expand")

    # Combine results
    df_evaluated = pd.concat([df.drop(columns=["dt"]), results], axis=1)

    # Filter flagged anomalies (risk_score >= risk_threshold)
    df_flagged = df_evaluated[df_evaluated["is_flagged_anomaly"] == 1].copy()
    df_flagged = df_flagged.sort_values(by="risk_score", ascending=False).reset_index(drop=True)

    # Export flagged anomalies
    df_flagged.to_csv(output_path, index=False)
    print(f"[+] Successfully exported {len(df_flagged):,} flagged anomalies to: {output_path}")

    # Output Detection Metrics
    print("\n" + "=" * 65)
    print(" PrivGuard-Anomaly-Monitor: Anomaly Detection Report")
    print("=" * 65)
    print(f"Total Logs Analyzed:       {total_records:,}")
    print(f"Flagged Anomalies:         {len(df_flagged):,} ({len(df_flagged)/total_records*100:.2f}%)")
    print(f"Risk Score Threshold:      >= {risk_threshold}")

    print("\n--- Severity Breakdown ---")
    print(df_evaluated["risk_severity"].value_counts().to_string())

    print("\n--- Flagged Anomalies by Persona ---")
    print(df_flagged["username"].value_counts().to_string())

    # Evaluation against ground truth if available
    if "is_forced_anomaly" in df_evaluated.columns:
        y_true = df_evaluated["is_forced_anomaly"]
        y_pred = df_evaluated["is_flagged_anomaly"]

        tp = int(((y_true == 1) & (y_pred == 1)).sum())
        fp = int(((y_true == 0) & (y_pred == 1)).sum())
        fn = int(((y_true == 1) & (y_pred == 0)).sum())
        tn = int(((y_true == 0) & (y_pred == 0)).sum())

        precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0

        print("\n--- Detection Performance vs Ground Truth ---")
        print(f"True Positives (TP):       {tp:,}")
        print(f"False Positives (FP):      {fp:,}")
        print(f"False Negatives (FN):      {fn:,}")
        print(f"True Negatives (TN):       {tn:,}")
        print(f"Detection Recall:          {recall*100:.2f}%")
        print(f"Detection Precision:       {precision*100:.2f}%")
        print(f"F1-Score:                  {f1:.4f}")

    print("=" * 65)
    return df_evaluated, df_flagged


if __name__ == "__main__":
    run_anomaly_detection()
