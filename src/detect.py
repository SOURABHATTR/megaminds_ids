import argparse
from pathlib import Path
import joblib
import pandas as pd
from features import add_features, FEATURE_COLUMNS
from rules import apply_rules

ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "models/isolation_forest.joblib"


def detect(input_path: str, output_path: str):
    df = pd.read_csv(input_path)
    df = add_features(df)
    df = apply_rules(df)

    model = joblib.load(MODEL)
    X = df[FEATURE_COLUMNS].fillna(0)
    df["ml_prediction"] = model.predict(X)
    df["ml_anomaly"] = df["ml_prediction"] == -1
    df["ml_score"] = -model.decision_function(X)

    df["alert"] = df["rule_alert"] | df["ml_anomaly"]
    df["confidence"] = 0.50
    df.loc[df["rule_alert"], "confidence"] += 0.30
    df.loc[df["ml_anomaly"], "confidence"] += 0.15
    df["confidence"] = df["confidence"].clip(upper=0.99).round(2)

    df["detection"] = df["rule_type"]
    df.loc[(df["detection"] == "") & df["ml_anomaly"], "detection"] = "ML_ANOMALY"
    df.loc[df["detection"] == "", "detection"] = "BENIGN"

    output = Path(output_path)
    output.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(output, index=False)
    print(f"Wrote {len(df):,} analysed flows -> {output}")
    print("Alerts:", int(df["alert"].sum()))


if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--input", default=str(ROOT / "data/raw/traffic.csv"))
    p.add_argument("--output", default=str(ROOT / "results/alerts.csv"))
    args = p.parse_args()
    detect(args.input, args.output)
