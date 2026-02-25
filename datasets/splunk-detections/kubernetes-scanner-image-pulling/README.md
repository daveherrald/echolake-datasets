# Kubernetes Scanner Image Pulling

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting the pulling of known Kubernetes security scanner images such as kube-hunter, kube-bench, and kube-recon. It leverages Kubernetes logs ingested through Splunk Connect for Kubernetes, specifically monitoring for messages indicating the pulling of these images. This activity is significant because the use of security scanners can indicate an attempt to identify vulnerabilities within the Kubernetes environment. If confirmed malicious, this could lead to the discovery and exploitation of security weaknesses, potentially compromising the entire Kubernetes cluster.

## MITRE ATT&CK

- T1526

## Analytic Stories

- Dev Sec Ops

## Data Sources


## Sample Data

- **Source:** kubernetes
  **Sourcetype:** kube:objects:events
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1526/kubernetes_kube_hunter/kubernetes_kube_hunter.json


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_scanner_image_pulling.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
