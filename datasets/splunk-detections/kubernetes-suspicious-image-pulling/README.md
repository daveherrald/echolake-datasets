# Kubernetes Suspicious Image Pulling

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting suspicious image pulling in Kubernetes environments. It identifies this activity by monitoring Kubernetes audit logs for image pull requests that do not match a predefined list of allowed images. This behavior is significant for a SOC as it may indicate an attacker attempting to deploy malicious software or infiltrate the system. If confirmed malicious, the impact could be severe, potentially leading to unauthorized access to sensitive systems or data, and enabling further malicious activities within the cluster.

## MITRE ATT&CK

- T1526

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Audit

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/kubernetes_audit_pull_image/kubernetes_audit_pull_image.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_suspicious_image_pulling.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
