import pandas as pd


def test_alerts_file_exists():
    df = pd.read_csv("results/alerts.csv")

    assert len(df) > 0
    assert "alert" in df.columns
    assert "scenario" in df.columns
    assert "detection" in df.columns


def test_required_scenarios_present():
    df = pd.read_csv("results/alerts.csv")

    required = {
        "normal",
        "port_scan",
        "dos",
        "brute_force",
        "ambiguous",
    }

    assert required.issubset(set(df["scenario"].unique()))