# Kubernetes Unauthorized Access

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects unauthorized access attempts to Kubernetes by analyzing Kubernetes audit logs. It identifies anomalies in access patterns by examining the source of requests and their response statuses. This activity is significant for a SOC as it may indicate an attacker attempting to infiltrate the Kubernetes environment. If confirmed malicious, such access could lead to unauthorized control over Kubernetes resources, potentially compromising sensitive systems or data within the cluster.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Audit

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/kubernetes_unauthorized_access/kubernetes_unauthorized_access.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_unauthorized_access.yml)*
