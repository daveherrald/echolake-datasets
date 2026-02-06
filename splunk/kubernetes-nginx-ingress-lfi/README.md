# Kubernetes Nginx Ingress LFI

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects local file inclusion (LFI) attacks targeting Kubernetes Nginx ingress controllers. It leverages Kubernetes logs, parsing fields such as `request` and `status` to identify suspicious patterns indicative of LFI attempts. This activity is significant because LFI attacks can allow attackers to read sensitive files from the server, potentially exposing critical information. If confirmed malicious, this could lead to unauthorized access to sensitive data, further exploitation, and potential compromise of the Kubernetes environment.

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
