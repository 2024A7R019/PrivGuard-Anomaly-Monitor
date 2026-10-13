"""
generate_logs.py
PrivGuard-Anomaly-Monitor: Synthetic Windows Privileged Event Log Generator

Generates 12,000 synthetic Windows event logs for privileged accounts across October 2026.
Features:
- Personas: admin_tanish, admin_himanshu, admin_backup
- Event IDs: 4624 (Normal Logon) and 4672 (Privileged Logon / Special Privileges)
- Hostnames, process names, and destination IPs
- ~10% forced anomalies (is_forced_anomaly = 1)
- Outputs directly to synthetic_privileged_logs.csv
"""

import os
from datetime import datetime, timedelta
import numpy as np
import pandas as pd


def generate_synthetic_logs(
    num_records: int = 12000,
    anomaly_ratio: float = 0.10,
    output_filename: str = "synthetic_privileged_logs.csv",
    random_seed: int = 42,
) -> pd.DataFrame:
    """
    Generate synthetic Windows security event logs for privileged accounts.

    Parameters:
        num_records (int): Total number of log entries to generate (default: 12000).
        anomaly_ratio (float): Fraction of records with forced anomalies (default: 0.10).
        output_filename (str): Target CSV filename for export.
        random_seed (int): Seed for reproducible data generation.

    Returns:
        pd.DataFrame: Generated event log dataset.
    """
    np.random.seed(random_seed)

    # 1. Administrator Personas
    personas = ["admin_tanish", "admin_himanshu", "admin_backup"]

    # Persona Profiles (Normal behavior)
    normal_profiles = {
        "admin_tanish": {
            # Senior SecOps Admin
            "hosts": ["SEC-WS-01", "DC-PROD-01", "SEC-MGMT-02", "SIEM-COLLECTOR-01"],
            "host_weights": [0.45, 0.25, 0.20, 0.10],
            "processes": ["powershell.exe", "mmc.exe", "mstsc.exe", "explorer.exe", "svchost.exe"],
            "proc_weights": [0.35, 0.25, 0.20, 0.10, 0.10],
            "ips": ["10.10.10.15", "10.10.10.25", "10.10.20.100", "127.0.0.1"],
            "ip_weights": [0.40, 0.30, 0.20, 0.10],
            "active_hours": (8, 19),  # 8 AM to 7 PM
            "logon_types": [2, 10, 3],  # Interactive, RDP, Network
            "logon_weights": [0.50, 0.40, 0.10],
            "event_4672_prob": 0.25,
        },
        "admin_himanshu": {
            # Infrastructure & Systems Admin
            "hosts": ["INFRA-WS-02", "DC-PROD-02", "APP-SRV-01", "DB-SRV-02"],
            "host_weights": [0.40, 0.30, 0.15, 0.15],
            "processes": ["pwsh.exe", "cmd.exe", "ServerManager.exe", "vmware-vmx.exe", "explorer.exe"],
            "proc_weights": [0.30, 0.25, 0.25, 0.10, 0.10],
            "ips": ["10.10.10.45", "10.10.30.50", "192.168.1.105", "127.0.0.1"],
            "ip_weights": [0.35, 0.35, 0.20, 0.10],
            "active_hours": (9, 21),  # 9 AM to 9 PM
            "logon_types": [2, 3, 10],  # Interactive, Network, RDP
            "logon_weights": [0.45, 0.35, 0.20],
            "event_4672_prob": 0.22,
        },
        "admin_backup": {
            # Automated Backup Service Account
            "hosts": ["BKP-SRV-01", "STORAGE-NAS-01", "DC-PROD-01", "DB-SRV-01"],
            "host_weights": [0.50, 0.25, 0.15, 0.10],
            "processes": ["wbengine.exe", "backupagent.exe", "powershell.exe", "robocopy.exe", "services.exe"],
            "proc_weights": [0.35, 0.30, 0.15, 0.10, 0.10],
            "ips": ["10.10.50.10", "10.10.50.20", "10.10.10.1", "127.0.0.1"],
            "ip_weights": [0.45, 0.35, 0.10, 0.10],
            "active_hours": (0, 6),  # Midnight to 6 AM batch windows
            "logon_types": [4, 5, 3],  # Batch, Service, Network
            "logon_weights": [0.50, 0.40, 0.10],
            "event_4672_prob": 0.30,
        },
    }

    # Anomalous Indicators (used when is_forced_anomaly == 1)
    anomalous_hosts = ["UNKNOWN-WS-88", "DMZ-EXT-GATEWAY", "SHADOW-DEV-09", "ROGUE-LAPTOP-X"]
    anomalous_processes = [
        "mimikatz.exe",
        "psexec.exe",
        "vssadmin.exe",
        "certutil.exe",
        "net1.exe",
        "cobaltstrike.exe",
        "nc.exe",
        "rundll32.exe",
    ]
    anomalous_ips = [
        "185.220.101.5",     # Tor Exit Node
        "45.33.32.156",      # External VPS
        "194.26.29.112",     # Untrusted Public Subnet
        "103.208.220.122",   # Offshore Hosting
        "91.240.118.172",    # Foreign External IP
    ]

    # 2. Assign Persona distribution
    # roughly equal distribution across personas
    assigned_personas = np.random.choice(personas, size=num_records, p=[0.36, 0.36, 0.28])

    # 3. Determine Anomaly Flags (~10%)
    num_anomalies = int(num_records * anomaly_ratio)
    is_anomaly = np.zeros(num_records, dtype=int)
    anomaly_indices = np.random.choice(num_records, size=num_anomalies, replace=False)
    is_anomaly[anomaly_indices] = 1

    # 4. Generate Timestamps Spanning October 2026
    start_date = datetime(2026, 10, 1, 0, 0, 0)
    end_date = datetime(2026, 10, 31, 23, 59, 59)
    total_seconds = int((end_date - start_date).total_seconds())

    # Generate random timestamps across the month
    random_offsets = np.random.randint(0, total_seconds, size=num_records)
    base_timestamps = [start_date + timedelta(seconds=int(offset)) for offset in random_offsets]

    # Pre-allocate feature lists
    timestamps = []
    event_ids = []
    hostnames = []
    process_names = []
    destination_ips = []
    logon_types = []
    anomaly_reasons = []

    for i in range(num_records):
        user = assigned_personas[i]
        profile = normal_profiles[user]
        flag = is_anomaly[i]
        dt = base_timestamps[i]

        if flag == 0:
            # Normal log generation aligned with persona profile
            # Adjust hour to persona active hours
            start_h, end_h = profile["active_hours"]
            if end_h > start_h:
                hour = np.random.randint(start_h, end_h + 1)
            else:
                # Night shift / wrap-around
                hours_pool = list(range(start_h, 24)) + list(range(0, end_h + 1))
                hour = int(np.random.choice(hours_pool))
            
            minute = np.random.randint(0, 60)
            second = np.random.randint(0, 60)
            dt = dt.replace(hour=hour, minute=minute, second=second)

            # Normal event ID: 4624 (Normal logon) or 4672 (Privilege logon)
            if np.random.rand() < profile["event_4672_prob"]:
                eid = 4672
            else:
                eid = 4624

            host = np.random.choice(profile["hosts"], p=profile["host_weights"])
            proc = np.random.choice(profile["processes"], p=profile["proc_weights"])
            ip = np.random.choice(profile["ips"], p=profile["ip_weights"])
            ltype = int(np.random.choice(profile["logon_types"], p=profile["logon_weights"]))
            reason = "Normal Activity"

        else:
            # Forced anomaly generation (~10%)
            anomaly_flavor = np.random.choice([
                "suspicious_process",
                "external_ip",
                "unauthorized_host",
                "off_hours_privilege",
                "privilege_spike",
            ])

            # Anomalies have high probability of 4672 (privileged escalation/anomaly)
            eid = int(np.random.choice([4672, 4624], p=[0.75, 0.25]))

            if anomaly_flavor == "suspicious_process":
                proc = np.random.choice(anomalous_processes)
                host = np.random.choice(profile["hosts"])
                ip = np.random.choice(profile["ips"])
                ltype = int(np.random.choice([2, 10, 3]))
                reason = f"Suspicious Process Execution ({proc})"

            elif anomaly_flavor == "external_ip":
                ip = np.random.choice(anomalous_ips)
                proc = np.random.choice(profile["processes"])
                host = np.random.choice(profile["hosts"])
                ltype = 3  # Network logon from untrusted external IP
                reason = f"External Destination IP Connection ({ip})"

            elif anomaly_flavor == "unauthorized_host":
                host = np.random.choice(anomalous_hosts)
                proc = np.random.choice(profile["processes"])
                ip = np.random.choice(["10.10.99.100", "192.168.100.254", np.random.choice(anomalous_ips)])
                ltype = int(np.random.choice([2, 10]))
                reason = f"Logon to Unauthorized Host ({host})"

            elif anomaly_flavor == "off_hours_privilege":
                # Deep midnight for human admins, midday for backup account
                if user in ["admin_tanish", "admin_himanshu"]:
                    dt = dt.replace(hour=np.random.randint(1, 5))
                else:
                    dt = dt.replace(hour=np.random.randint(12, 16))
                proc = np.random.choice(profile["processes"])
                host = np.random.choice(profile["hosts"])
                ip = np.random.choice(profile["ips"])
                ltype = 10  # Untracked off-hours remote session
                eid = 4672
                reason = "Off-Hours Privileged Elevation"

            else:  # privilege_spike
                proc = np.random.choice(["powershell.exe", "cmd.exe", "psexec.exe"])
                host = np.random.choice(profile["hosts"])
                ip = np.random.choice(anomalous_ips)
                ltype = 3
                eid = 4672
                reason = "Anomalous Privilege Assignment (Event 4672)"

        timestamps.append(dt)
        event_ids.append(eid)
        hostnames.append(host)
        process_names.append(proc)
        destination_ips.append(ip)
        logon_types.append(ltype)
        anomaly_reasons.append(reason)

    # 5. Build DataFrame
    df = pd.DataFrame({
        "timestamp": timestamps,
        "username": assigned_personas,
        "event_id": event_ids,
        "hostname": hostnames,
        "process_name": process_names,
        "destination_ip": destination_ips,
        "logon_type": logon_types,
        "is_forced_anomaly": is_anomaly,
        "anomaly_reason": anomaly_reasons,
    })

    # 6. Sort chronologically across October 2026
    df = df.sort_values(by="timestamp").reset_index(drop=True)

    # Format timestamp to ISO 8601 standard string
    df["timestamp"] = df["timestamp"].dt.strftime("%Y-%m-%d %H:%M:%S")

    # 7. Save directly to CSV
    script_dir = os.path.dirname(os.path.abspath(__file__))
    output_path = os.path.join(script_dir, output_filename)
    df.to_csv(output_path, index=False)
    print(f"[+] Successfully generated {len(df):,} logs.")
    print(f"[+] Dataset saved to: {output_path}")

    return df


if __name__ == "__main__":
    print("=" * 60)
    print(" PrivGuard-Anomaly-Monitor: Synthetic Log Generator")
    print("=" * 60)
    df_logs = generate_synthetic_logs()

    # Summary Statistics
    print("\n--- Generation Summary ---")
    print(f"Total Records: {len(df_logs):,}")
    print(f"Date Range: {df_logs['timestamp'].min()} to {df_logs['timestamp'].max()}")
    print("\nPersona Distribution:")
    print(df_logs["username"].value_counts().to_string())
    print("\nEvent ID Distribution:")
    print(df_logs["event_id"].value_counts().to_string())
    print("\nAnomaly Breakdown:")
    print(df_logs["is_forced_anomaly"].value_counts(normalize=True).map(lambda p: f"{p*100:.2f}%").to_string())
    print(f"Total Anomalies: {df_logs['is_forced_anomaly'].sum():,} / {len(df_logs):,}")
    print("=" * 60)
