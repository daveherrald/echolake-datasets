# Kubernetes Abuse of Secret by Unusual Location

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting unauthorized access or misuse of Kubernetes Secrets from unusual locations. It leverages Kubernetes Audit logs to identify anomalies in access patterns by analyzing the source of requests by country. This activity is significant for a SOC as Kubernetes Secrets store sensitive information like passwords, OAuth tokens, and SSH keys, making them critical assets. If confirmed malicious, this behavior could indicate an attacker attempting to exfiltrate or misuse these secrets, potentially leading to unauthorized access to sensitive systems or data.

## MITRE ATT&CK

- T1552.007

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Audit

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.007/kube_audit_get_secret/kube_audit_get_secret.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_abuse_of_secret_by_unusual_location.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
