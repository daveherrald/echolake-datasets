# Kubernetes Nginx Ingress RFI

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects remote file inclusion (RFI) attacks targeting Kubernetes Nginx ingress controllers. It leverages Kubernetes logs from the Nginx ingress controller, parsing fields such as `remote_addr`, `request`, and `url` to identify suspicious activity. This activity is significant because RFI attacks can allow attackers to execute arbitrary code or access sensitive files on the server. If confirmed malicious, this could lead to unauthorized access, data exfiltration, or further compromise of the Kubernetes environment.

## MITRE ATT&CK

- T1212

## Analytic Stories

- Dev Sec Ops

## Data Sources


## Sample Data

- **Source:** kubernetes
  **Sourcetype:** kube:container:controller
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1212/kuberntest_nginx_rfi_attack/kubernetes_nginx_rfi_attack.log


---

*Source: [Splunk Security Content](detections/cloud/kubernetes_nginx_ingress_rfi.yml)*
