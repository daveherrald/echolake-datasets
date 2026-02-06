# Ollama Abnormal Service Crash Availability Attack

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects critical service crashes, fatal errors, and abnormal process terminations in Ollama that may indicate exploitation attempts, resource exhaustion attacks, malicious input triggering unhandled exceptions, or deliberate denial of service attacks designed to disrupt AI model availability and degrade system stability.

## MITRE ATT&CK

- T1489

## Analytic Stories

- Suspicious Ollama Activities

## Data Sources

- Ollama Server

## Sample Data

- **Source:** app.log
  **Sourcetype:** ollama:server
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/ollama/app.log


---

*Source: [Splunk Security Content](detections/application/ollama_abnormal_service_crash_availability_attack.yml)*
