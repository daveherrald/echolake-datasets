# Kubernetes Pod Created in Default Namespace

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects the creation of Kubernetes pods in the default, kube-system, or kube-public namespaces. It leverages Kubernetes audit logs to identify pod creation events within these specific namespaces. This activity is significant for a SOC as it may indicate an attacker attempting to hide their presence or evade defenses. Unauthorized pod creation in these namespaces can suggest a successful cluster breach, potentially leading to privilege escalation, persistent access, or further malicious activities within the cluster.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Audit

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/kubernetes_privileged_pod/kubernetes_privileged_pod.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_pod_created_in_default_namespace.yml)*
