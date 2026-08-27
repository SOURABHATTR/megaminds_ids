from pathlib import Path
import pandas as pd
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix
from features import add_features, FEATURE_COLUMNS
from rules import apply_rules
import joblib

ROOT = Path(__file__).resolve().parents[1]


def main():
    data = ROOT / "data/raw/traffic.csv"
    df = pd.read_csv(data)
    df = add_features(df)
    df = apply_rules(df)
    model = joblib.load(ROOT / "models/isolation_forest.joblib")
    X = df[FEATURE_COLUMNS].fillna(0)
    df["ml_anomaly"] = model.predict(X) == -1
    df["predicted_attack"] = df["rule_alert"] | df["ml_anomaly"]
    df["actual_attack"] = df["label"] != "BENIGN"

    y_true, y_pred = df["actual_attack"], df["predicted_attack"]
    cm = confusion_matrix(y_true, y_pred, labels=[False, True])
    print("Accuracy :", round(accuracy_score(y_true, y_pred), 4))
    print("Precision:", round(precision_score(y_true, y_pred, zero_division=0), 4))
    print("Recall   :", round(recall_score(y_true, y_pred, zero_division=0), 4))
    print("F1       :", round(f1_score(y_true, y_pred, zero_division=0), 4))
    print("Confusion matrix [[TN, FP], [FN, TP]]:")
    print(cm)
    print("\nScenario summary:")
    print(df.groupby("scenario")["predicted_attack"].mean().round(3))

    ambiguous = df[df["scenario"] == "ambiguous"]["predicted_attack"].mean()
    print(f"\nAmbiguous case flagged fraction: {ambiguous:.3f}")


if __name__ == "__main__":
    main()
