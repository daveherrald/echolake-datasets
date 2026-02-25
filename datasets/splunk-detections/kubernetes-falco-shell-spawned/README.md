# Kubernetes Falco Shell Spawned

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting instances where a shell is spawned within a Kubernetes container. Leveraging Falco, a cloud-native runtime security tool, this analytic monitors system calls within the Kubernetes environment and flags when a shell is spawned. This activity is significant for a SOC as it may indicate unauthorized access, allowing an attacker to execute arbitrary commands, manipulate container processes, or escalate privileges. If confirmed malicious, this could lead to data breaches, service disruptions, or unauthorized access to sensitive information, severely impacting the Kubernetes infrastructure's integrity and security.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Falco

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** kube:container:falco
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/kubernetes_falco_shell_spawned/kubernetes_falco_shell_spawned.log


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_falco_shell_spawned.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
