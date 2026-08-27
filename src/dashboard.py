import pandas as pd
import streamlit as st

st.set_page_config(page_title="AI Network IDS", layout="wide")
st.title("AI-Driven Network Traffic Analysis & Intrusion Detection")
st.caption("MegaMinds assessment prototype — simulated, controlled traffic")

uploaded = st.file_uploader("Upload analysed alerts CSV", type=["csv"])
path = "results/alerts.csv"
try:
    df = pd.read_csv(uploaded) if uploaded else pd.read_csv(path)
except FileNotFoundError:
    st.info("Run the generation, training, and detection commands first.")
    st.stop()
if "detection_method" not in df.columns:
    df["detection_method"] = "BENIGN"

    df.loc[
        df["rule_alert"] & ~df["ml_anomaly"],
        "detection_method"
    ] = "RULE_ONLY"

    df.loc[
        ~df["rule_alert"] & df["ml_anomaly"],
        "detection_method"
    ] = "ML_ONLY"

    df.loc[
        df["rule_alert"] & df["ml_anomaly"],
        "detection_method"
    ] = "RULE_AND_ML"
# Detection masks
alerts = df["alert"].astype(bool)
rule_alerts = df["rule_alert"].astype(bool)
ml_anomalies = df["ml_anomaly"].astype(bool)

# Summary metrics
c1, c2, c3, c4, c5 = st.columns(5)

c1.metric("Flows", f"{len(df):,}")
c2.metric("Total Alerts", f"{int(alerts.sum()):,}")
c3.metric("Rule Alerts", f"{int(rule_alerts.sum()):,}")
c4.metric("ML Anomalies", f"{int(ml_anomalies.sum()):,}")
c5.metric(
    "High/Critical",
    f"{int(df['severity'].isin(['HIGH', 'CRITICAL']).sum()):,}"
)

# Hybrid detection breakdown
st.subheader("Hybrid Detection Breakdown")

rule_and_ml = rule_alerts & ml_anomalies
ml_only = ~rule_alerts & ml_anomalies
rule_only = rule_alerts & ~ml_anomalies

b1, b2, b3 = st.columns(3)

b1.metric("Rule + ML", f"{int(rule_and_ml.sum()):,}")
b2.metric("ML Only", f"{int(ml_only.sum()):,}")
b3.metric("Rule Only", f"{int(rule_only.sum()):,}")

# Detection by scenario
st.subheader("Detection by Scenario")

scenario_summary = (
    df.groupby("scenario")
    .agg(
        flows=("scenario", "size"),
        alerts=("alert", "sum"),
        alert_rate=("alert", "mean")
    )
    .reset_index()
)

scenario_summary["alert_rate"] = (
    scenario_summary["alert_rate"] * 100
).round(2)

st.dataframe(
    scenario_summary,
    use_container_width=True
)

# Detection method by scenario
st.subheader("Detection Method by Scenario")

method_summary = pd.crosstab(
    df["scenario"],
    df["detection_method"]
)

st.dataframe(
    method_summary,
    use_container_width=True
)

# Flagged events
st.subheader("Flagged Events")

cols = [
    "timestamp",
    "src_ip",
    "dst_ip",
    "dst_port",
    "detection",
    "detection_method",
    "severity",
    "confidence",
    "reason",
    "ml_score"
]

st.dataframe(
    df[df["alert"]][cols].head(300),
    use_container_width=True
)