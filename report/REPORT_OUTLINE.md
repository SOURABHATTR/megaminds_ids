# Technical Report Outline

## 1. Problem Overview
Explain the need for behavioural network intrusion detection and the four attack classes used.

## 2. Objectives
State the four core objectives from the assessment: ingest traffic, extract features, detect anomalies/intrusions, and present analyst-useful results.

## 3. Traffic Data
Describe the controlled simulated flow dataset, generation method, class balance, and why simulation was selected.

## 4. System Architecture
Include the pipeline: traffic -> feature extraction -> rule engine + Isolation Forest -> hybrid decision -> analyst alert.

## 5. Feature Extraction
Explain duration, packets, bytes, packets/sec, bytes/sec, destination port, failed authentication, protocol indicators, and port diversity.

## 6. Detection Methodology
Explain each rule, thresholds, Isolation Forest training on benign baseline, and hybrid decision logic.

## 7. Testing and Evaluation
Report accuracy, precision, recall, F1, confusion matrix, scenario-level results, and the ambiguous case.

## 8. Security and Network Considerations
Discuss latency, capture completeness, evasion, false positives, and scalability.

## 9. Limitations
Discuss synthetic data, threshold sensitivity, lack of payload/application context, encrypted traffic, and distributed attacks.

## 10. Future Improvements
Discuss Zeek/PCAP ingestion, richer flow aggregation, calibration on CICIDS2017 or real controlled captures, explainable ML, and real-time streaming.
