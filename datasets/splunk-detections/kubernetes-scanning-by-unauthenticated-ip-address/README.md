# Kubernetes Scanning by Unauthenticated IP Address

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for identifying potential scanning activities within a Kubernetes environment by unauthenticated IP addresses. It leverages Kubernetes audit logs to detect multiple unauthorized access attempts (HTTP 403 responses) from the same source IP. This activity is significant as it may indicate an attacker probing for vulnerabilities or attempting to exploit known issues. If confirmed malicious, such scanning could lead to unauthorized access, data breaches, or further exploitation of the Kubernetes infrastructure, compromising the security and integrity of the environment.

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

*Source: [Splunk Security Content](detections/cloud/kubernetes_scanning_by_unauthenticated_ip_address.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
