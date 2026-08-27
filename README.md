# AI-Driven Network Traffic Analysis and Intrusion Detection System

MegaMinds IT Services — Cybersecurity & Network Security Research Intern Assessment

## Overview

This prototype ingests simulated network-flow traffic, extracts security-relevant features, applies explainable rule-based detection, and combines the rules with an Isolation Forest anomaly detector. The output is an analyst-oriented alert containing the suspected attack, severity, confidence, and supporting reasons.

The traffic generator creates controlled examples for:
- Normal/benign traffic
- Port scanning/reconnaissance
- DoS/flooding
- Brute-force activity
- An ambiguous/borderline case

> The traffic is simulated locally for a safe, reproducible assessment environment. No attacks are launched against real systems.

## Architecture

Traffic generator -> Feature engineering -> Rule engine + Isolation Forest -> Hybrid decision -> Analyst alerts + metrics

## Setup

```bash
python -m venv .venv
# Windows: .venv\\Scripts\\activate
# Linux/macOS: source .venv/bin/activate
pip install -r requirements.txt
```

## Run

Generate the traffic dataset:

```bash
python data/generate_traffic.py
```

Train the anomaly model:

```bash
python src/train_model.py
```

Run detection:

```bash
python src/detect.py --input data/raw/traffic.csv --output results/alerts.csv
```

Evaluate the labelled scenarios:

```bash
python src/evaluate.py
```

Run the analyst dashboard:

```bash
streamlit run src/dashboard.py
```

## Detection approach

### Rule layer

- Port scan: unusually high number of unique destination ports in a short time window.
- DoS/flood: unusually high packets/sec and bytes/sec from a source.
- Brute force: repeated short authentication connections with a high failed-attempt indicator.

### ML layer

Isolation Forest is trained on normal traffic and identifies flows that differ from the learned baseline. The hybrid layer uses rule evidence as the primary explainable signal and ML anomaly evidence as supporting context.

## Evaluation

The evaluation script reports accuracy, precision, recall, F1, confusion matrix values, and representative false-positive/false-negative or ambiguous examples where available.

## Limitations

This is a controlled flow-level prototype. It does not reproduce the full packet payload, encrypted application context, distributed attacks, or the throughput characteristics of an enterprise sensor. Thresholds are dataset-specific and should be calibrated on representative production traffic.
