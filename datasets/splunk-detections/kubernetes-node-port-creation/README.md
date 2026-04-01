# Kubernetes Node Port Creation

**Type:** Anomaly

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the creation of a Kubernetes NodePort service, which exposes a service to the external network. It identifies this activity by monitoring Kubernetes Audit logs for the creation of NodePort services. This behavior is significant for a SOC as it could allow an attacker to access internal services, posing a threat to the Kubernetes infrastructure's integrity and security. If confirmed malicious, this activity could lead to data breaches, service disruptions, or unauthorized access to sensitive information.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Kubernetes Security

## Data Sources

- Kubernetes Audit

## Sample Data

- **Source:** kubernetes
  **Sourcetype:** _json
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1204/kube_audit_create_node_port_service/kube_audit_create_node_port_service.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_node_port_creation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
