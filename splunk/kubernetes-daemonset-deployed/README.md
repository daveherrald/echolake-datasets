# Kubernetes DaemonSet Deployed

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the creation of a DaemonSet in a Kubernetes cluster. This behavior is identified by monitoring Kubernetes Audit logs for the creation event of a DaemonSet. DaemonSets ensure a specific pod runs on every node, making them a potential vector for persistent access. This activity is significant for a SOC as it could indicate an attempt to maintain persistent access to the Kubernetes infrastructure. If confirmed malicious, it could lead to persistent attacks, service disruptions, or unauthorized access to sensitive information.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Audit

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/kubernetes_audit_daemonset_created/kubernetes_audit_daemonset_created.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_daemonset_deployed.yml)*
