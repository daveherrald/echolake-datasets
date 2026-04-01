# Ollama Abnormal Network Connectivity

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects abnormal network activity and connectivity issues in Ollama including non-localhost API access attempts and warning-level network errors such as DNS lookup failures, TCP connection issues, or host resolution problems that may indicate network-based attacks, unauthorized access attempts, or infrastructure reconnaissance activity.

## MITRE ATT&CK

- T1571

## Analytic Stories

- Suspicious Ollama Activities

## Data Sources

- Ollama Server

## Sample Data

- **Source:** app.log
  **Sourcetype:** ollama:server
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/ollama/app.log


---

*Source: [Splunk Security Content](detections/application/ollama_abnormal_network_connectivity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
