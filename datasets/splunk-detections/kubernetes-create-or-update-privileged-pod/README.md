# Kubernetes Create or Update Privileged Pod

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the creation or update of privileged pods in Kubernetes. It identifies this activity by monitoring Kubernetes Audit logs for pod configurations that include root privileges. This behavior is significant for a SOC as it could indicate an attempt to escalate privileges, exploit the kernel, and gain full access to the host's namespace and devices. If confirmed malicious, this activity could lead to unauthorized access to sensitive information, data breaches, and service disruptions, posing a severe threat to the environment.

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

*Source: [Splunk Security Content](detections/cloud/kubernetes_create_or_update_privileged_pod.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
