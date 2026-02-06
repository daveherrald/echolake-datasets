# Linux Clipboard Data Copy

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of the Linux 'xclip' command to copy data from the clipboard. It leverages Endpoint Detection and Response (EDR) telemetry, focusing on process names and command-line arguments related to clipboard operations. This activity is significant because adversaries can exploit clipboard data to capture sensitive information such as passwords or IP addresses. If confirmed malicious, this technique could lead to unauthorized data exfiltration, compromising sensitive information and potentially aiding further attacks within the environment.

## MITRE ATT&CK

- T1115

## Analytic Stories

- Linux Living Off The Land

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1115/atomic_red_team/linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_clipboard_data_copy.yml)*
