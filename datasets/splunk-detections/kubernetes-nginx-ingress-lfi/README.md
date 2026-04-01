# Kubernetes Nginx Ingress LFI

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

This dataset contains sample data for detecting local file inclusion (LFI) attacks targeting Kubernetes Nginx ingress controllers. It leverages Kubernetes logs, parsing fields such as `request` and `status` to identify suspicious patterns indicative of LFI attempts. This activity is significant because LFI attacks can allow attackers to read sensitive files from the server, potentially exposing critical information. If confirmed malicious, this could lead to unauthorized access to sensitive data, further exploitation, and potential compromise of the Kubernetes environment.

## MITRE ATT&CK

- T1212

## Analytic Stories

- Dev Sec Ops

## Data Sources


## Sample Data

- **Source:** kubernetes
  **Sourcetype:** kube:container:controller
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1212/kubernetes_nginx_lfi_attack/kubernetes_nginx_lfi_attack.log


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_nginx_ingress_lfi.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
