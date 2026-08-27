from pathlib import Path
import argparse
import numpy as np
import pandas as pd

RNG = np.random.default_rng(42)
OUT = Path(__file__).resolve().parent / "raw" / "traffic.csv"


def normal_flows(n=1800):
    rows = []
    services = [80, 443, 53, 22, 25, 123]
    for i in range(n):
        duration = float(np.clip(RNG.lognormal(1.0, 0.65), 0.3, 30))
        packets = int(np.clip(RNG.poisson(18) + 3, 4, 100))
        bytes_ = int(max(400, packets * RNG.normal(650, 180)))
        rows.append({
            "timestamp": i * 0.5,
            "src_ip": f"10.0.0.{RNG.integers(10, 40)}",
            "dst_ip": f"10.0.1.{RNG.integers(10, 60)}",
            "src_port": int(RNG.integers(32768, 60000)),
            "dst_port": int(RNG.choice(services)),
            "protocol": RNG.choice(["TCP", "TCP", "UDP"]),
            "duration_s": duration,
            "packets": packets,
            "bytes": bytes_,
            "failed_auth": 0,
            "label": "BENIGN",
            "scenario": "normal"
        })
    return rows

def port_scan(start=0, n=100):
    rows = []
    ports = [(i % 100) + 1 for i in range(n)]
    for i, port in enumerate(ports):
        rows.append({
            "timestamp": start + i * 0.03,
            "src_ip": "10.0.0.50",
            "dst_ip": "10.0.1.20",
            "src_port": 45000 + i,
            "dst_port": port,
            "protocol": "TCP",
            "duration_s": 0.05,
            "packets": int(RNG.integers(2, 5)),
            "bytes": int(RNG.integers(100, 350)),
            "failed_auth": 0,
            "label": "PORT_SCAN",
            "scenario": "port_scan"
        })
    return rows


def dos(start=0, n=500):
    rows = []
    for i in range(n):
        packets = int(RNG.integers(80, 140))
        rows.append({
            "timestamp": start + i * 0.02,
            "src_ip": "10.0.0.60",
            "dst_ip": "10.0.1.30",
            "src_port": int(RNG.integers(30000, 65000)),
            "dst_port": 80,
            "protocol": "TCP",
            "duration_s": 0.08,
            "packets": packets,
            "bytes": packets * int(RNG.integers(500, 900)),
            "failed_auth": 0,
            "label": "DOS",
            "scenario": "dos"
        })
    return rows


def brute_force(start=0, n=120):
    rows = []
    for i in range(n):
        rows.append({
            "timestamp": start + i * 0.25,
            "src_ip": "10.0.0.70",
            "dst_ip": "10.0.1.40",
            "src_port": 52000 + i,
            "dst_port": 22,
            "protocol": "TCP",
            "duration_s": float(RNG.uniform(0.05, 0.25)),
            "packets": int(RNG.integers(5, 15)),
            "bytes": int(RNG.integers(400, 1800)),
            "failed_auth": 1,
            "label": "BRUTE_FORCE",
            "scenario": "brute_force"
        })
    return rows


def ambiguous(start=0, n=35):
    rows = []
    # Looks somewhat bursty, but is intended to represent a legitimate backup/update burst.
    for i in range(n):
        packets = int(RNG.integers(35, 55))
        rows.append({
            "timestamp": start + i * 0.08,
            "src_ip": "10.0.0.25",
            "dst_ip": "10.0.1.55",
            "src_port": 41000 + i,
            "dst_port": 443,
            "protocol": "TCP",
            "duration_s": float(RNG.uniform(0.1, 0.5)),
            "packets": packets,
            "bytes": packets * int(RNG.integers(700, 1200)),
            "failed_auth": 0,
            "label": "BENIGN",
            "scenario": "ambiguous"
        })
    return rows

def main():
    parser = argparse.ArgumentParser(
        description="Generate simulated network traffic for the IDS"
    )
    parser.add_argument(
        "--scale",
        type=int,
        default=1,
        help="Scale factor for the generated traffic dataset"
    )

    args = parser.parse_args()

    if args.scale < 1:
        raise ValueError("Scale must be >= 1")

    scale = args.scale

    rows = normal_flows(n=1800 * scale)

    base = max(r["timestamp"] for r in rows) + 10
    rows += port_scan(base, n=100 * scale)

    base = max(r["timestamp"] for r in rows) + 10
    rows += dos(base, n=500 * scale)

    base = max(r["timestamp"] for r in rows) + 10
    rows += brute_force(base, n=120 * scale)

    base = max(r["timestamp"] for r in rows) + 10
    rows += ambiguous(base, n=35 * scale)

    df = pd.DataFrame(rows)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(OUT, index=False)

    print(f"Generated {len(df):,} flows -> {OUT}")
    print(df["scenario"].value_counts())
if __name__ == "__main__":
    main()