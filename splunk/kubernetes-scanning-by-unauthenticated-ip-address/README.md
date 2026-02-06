# Kubernetes Scanning by Unauthenticated IP Address

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic identifies potential scanning activities within a Kubernetes environment by unauthenticated IP addresses. It leverages Kubernetes audit logs to detect multiple unauthorized access attempts (HTTP 403 responses) from the same source IP. This activity is significant as it may indicate an attacker probing for vulnerabilities or attempting to exploit known issues. If confirmed malicious, such scanning could lead to unauthorized access, data breaches, or further exploitation of the Kubernetes infrastructure, compromising the security and integrity of the environment.

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
