from pathlib import Path
import joblib
import pandas as pd
from sklearn.ensemble import IsolationForest
from features import add_features, FEATURE_COLUMNS

ROOT = Path(__file__).resolve().parents[1]
DATA = ROOT / "data/raw/traffic.csv"
MODEL = ROOT / "models/isolation_forest.joblib"


def main():
    df = pd.read_csv(DATA)
    normal = df[df["label"] == "BENIGN"].copy()
    normal = normal[normal["scenario"] == "normal"]
    normal = add_features(normal)
    X = normal[FEATURE_COLUMNS].fillna(0)

    model = IsolationForest(n_estimators=200, contamination=0.03, random_state=42)
    model.fit(X)
    MODEL.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, MODEL)
    print(f"Trained Isolation Forest on {len(X):,} normal flows -> {MODEL}")


if __name__ == "__main__":
    main()
