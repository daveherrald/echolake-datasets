# Kubernetes Access Scanning

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting potential scanning activities within a Kubernetes environment. It identifies unauthorized access attempts, probing of public APIs, or attempts to exploit known vulnerabilities by monitoring Kubernetes audit logs for repeated failed access attempts or unusual API requests. This activity is significant for a SOC as it may indicate an attacker's preliminary reconnaissance to gather information about the system. If confirmed malicious, this activity could lead to unauthorized access to sensitive systems or data, posing a severe security risk.

## MITRE ATT&CK

- T1046

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Audit

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1046/kubernetes_scanning/kubernetes_scanning.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_access_scanning.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
