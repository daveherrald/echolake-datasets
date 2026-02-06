# Kubernetes Abuse of Secret by Unusual User Group

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects unauthorized access or misuse of Kubernetes Secrets by unusual user groups. It leverages Kubernetes Audit logs to identify anomalies in access patterns by analyzing the source of requests and user groups. This activity is significant for a SOC as Kubernetes Secrets store sensitive information like passwords, OAuth tokens, and SSH keys. If confirmed malicious, this behavior could indicate an attacker attempting to exfiltrate or misuse these secrets, potentially leading to unauthorized access to sensitive systems or data.

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

*Source: [Splunk Security Content](detections/cloud/kubernetes_abuse_of_secret_by_unusual_user_group.yml)*
