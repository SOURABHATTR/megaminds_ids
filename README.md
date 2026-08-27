# AI-Driven Network Traffic Analysis and Intrusion Detection System

**MegaMinds IT Services — Cybersecurity & Network Security Research Intern Assessment**

## Overview

This project is a controlled, AI-driven network traffic analysis and intrusion detection prototype developed for the MegaMinds Cybersecurity & Network Security Research Intern assessment.

The system analyzes simulated network-flow data, extracts security-relevant features, applies explainable rule-based detection, and uses an Isolation Forest machine-learning model to identify anomalous traffic.

The final detection pipeline combines rule-based evidence and ML anomaly detection to produce analyst-oriented alerts containing:

- Detected activity
- Detection method
- Severity
- Confidence
- Supporting reason
- ML anomaly score

All traffic used in this project is generated locally in a controlled environment. No attacks are launched against real systems or external infrastructure.

---

## Key Features

- Simulated network traffic generation
- Normal/benign traffic modeling
- Port-scan detection
- DoS/flooding detection
- Brute-force detection
- Ambiguous/borderline traffic scenario
- Rule-based detection
- Isolation Forest anomaly detection
- Hybrid rule + ML detection
- Alert severity and confidence
- Explainable detection reasons
- Accuracy, precision, recall and F1 evaluation
- Confusion matrix
- Scenario-level evaluation
- False-positive analysis
- Detection-method analysis
- Streamlit analyst dashboard
- Batch performance and scalability testing

---

## Detection Scenarios

The traffic generator creates five controlled scenarios:

| Scenario | Description |
|---|---|
| Normal | Simulated benign network activity |
| Port Scan | Reconnaissance involving connections to multiple destination ports |
| DoS | High-volume traffic intended to represent flooding behavior |
| Brute Force | Repeated SSH authentication attempts with failed authentication indicators |
| Ambiguous | Bursty traffic representing a legitimate backup/update activity that may resemble anomalous behavior |

The ambiguous scenario is intentionally included to evaluate how the system behaves when unusual traffic is not necessarily malicious.

---

## Architecture

```text
                    +----------------------+
                    |  Traffic Generator   |
                    |  Simulated Scenarios |
                    +----------+-----------+
                               |
                               v
                    +----------------------+
                    | Feature Engineering  |
                    +----------+-----------+
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
        +----------------+          +------------------+
        |  Rule Engine   |          | Isolation Forest |
        | Explainable    |          | ML Anomaly Model |
        +-------+--------+          +---------+--------+
                |                             |
                +-------------+---------------+
                              |
                              v
                    +----------------------+
                    |   Hybrid Detection   |
                    +----------+-----------+
                               |
                 +-------------+-------------+
                 |                           |
                 v                           v
        +------------------+       +------------------+
        | Analyst Alerts   |       |    Evaluation    |
        | Severity/Reason  |       | Metrics/Results  |
        +--------+---------+       +------------------+
                 |
                 v
        +----------------------+
        | Streamlit Dashboard  |
        +----------------------+
