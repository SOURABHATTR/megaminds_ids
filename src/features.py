import pandas as pd

FEATURE_COLUMNS = [
    "duration_s", "packets", "bytes", "packets_per_sec", "bytes_per_sec",
    "dst_port", "failed_auth", "is_tcp", "is_udp", "port_scan_score",
    "ssh_attempt_rate"
]

def add_features(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy().sort_values("timestamp").reset_index(drop=True)
    duration = out["duration_s"].clip(lower=0.01)
    out["packets_per_sec"] = out["packets"] / duration
    out["bytes_per_sec"] = out["bytes"] / duration
    out["is_tcp"] = (out["protocol"] == "TCP").astype(int)
    out["is_udp"] = (out["protocol"] == "UDP").astype(int)

    # Time-window features: count unique destination ports / SSH connections
    # from each source in the preceding 5 seconds.
    port_scores = []
    ssh_rates = []
    for _, row in out.iterrows():
        src = row["src_ip"]
        t = row["timestamp"]
        window = out[(out["src_ip"] == src) & (out["timestamp"] >= t - 5) & (out["timestamp"] <= t)]
        port_scores.append(window["dst_port"].nunique())
        ssh_rates.append(int(((window["dst_port"] == 22) & (window["protocol"] == "TCP")).sum()))
    out["port_scan_score"] = port_scores
    out["ssh_attempt_rate"] = ssh_rates
    return out
