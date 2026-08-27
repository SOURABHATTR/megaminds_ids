import pandas as pd

def apply_rules(df: pd.DataFrame) -> pd.DataFrame:
    out = df.copy()
    out["rule_alert"] = False
    out["rule_type"] = ""
    out["severity"] = "LOW"
    out["reason"] = "No rule threshold exceeded"

    scan = out["port_scan_score"] >= 15
    dos = (out["packets_per_sec"] >= 500) | (out["bytes_per_sec"] >= 250_000)
    brute = (out["dst_port"] == 22) & (out["ssh_attempt_rate"] >= 8) & (out["duration_s"] <= 0.5)

    out.loc[scan, ["rule_alert", "rule_type", "severity", "reason"]] = [
        True, "PORT_SCAN", "HIGH", "15+ unique destination ports from one source within 5 seconds"
    ]
    out.loc[dos, ["rule_alert", "rule_type", "severity", "reason"]] = [
        True, "DOS", "CRITICAL", "Abnormally high packet/byte rate"
    ]
    out.loc[brute, ["rule_alert", "rule_type", "severity", "reason"]] = [
        True, "BRUTE_FORCE", "HIGH", "Repeated short SSH connection attempts from one source"
    ]
    return out
