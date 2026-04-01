# Kubernetes Pod With Host Network Attachment

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the creation or update of a Kubernetes pod with host network attachment. It leverages Kubernetes Audit logs to identify pods configured with host network settings. This activity is significant for a SOC as it could allow an attacker to monitor all network traffic on the node, potentially capturing sensitive information and escalating privileges. If confirmed malicious, this could lead to unauthorized access, data breaches, and service disruptions, severely impacting the security and integrity of the Kubernetes environment.

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

*Source: [Splunk Security Content](detections/cloud/kubernetes_pod_with_host_network_attachment.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
