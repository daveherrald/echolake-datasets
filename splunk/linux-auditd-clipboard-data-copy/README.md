# Linux Auditd Clipboard Data Copy

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the use of the Linux 'xclip' command to copy data from the clipboard. It leverages Linux Auditd telemetry, focusing on process names and command-line arguments related to clipboard operations. This activity is significant because adversaries can exploit clipboard data to capture sensitive information such as passwords or IP addresses. If confirmed malicious, this technique could lead to unauthorized data exfiltration, compromising sensitive information and potentially aiding further attacks within the environment.

## MITRE ATT&CK

- T1115

## Analytic Stories

- Linux Living Off The Land
- Compromised Linux Host

## Data Sources

- Linux Auditd Execve

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1115/linux_auditd_xclip/linux_auditd_xclip2.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_clipboard_data_copy.yml)*
