# Linux Obfuscated Files or Information Base64 Decode

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of the base64 decode command on Linux systems, which is often used to deobfuscate files. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions that include "base64 -d" or "base64 --decode". This activity is significant as it may indicate an attempt to hide malicious payloads or scripts. If confirmed malicious, an attacker could use this technique to execute hidden code, potentially leading to unauthorized access, data exfiltration, or further system compromise.

## MITRE ATT&CK

- T1027

## Analytic Stories

- Linux Living Off The Land

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1027/atomic_red_team/linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_obfuscated_files_or_information_base64_decode.yml)*
