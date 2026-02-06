# Detect Regsvcs with Network Connection

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances of Regsvcs.exe establishing a network connection to a public IP address, excluding private IP ranges. This detection leverages Sysmon EventID 3 logs to monitor network connections initiated by Regsvcs.exe. This activity is significant as Regsvcs.exe, a legitimate Microsoft-signed binary, can be exploited to bypass application control mechanisms and establish remote Command and Control (C2) channels. If confirmed malicious, this behavior could allow an attacker to escalate privileges, persist in the environment, and exfiltrate sensitive data. Immediate investigation and remediation are recommended.

## MITRE ATT&CK

- T1218.009

## Analytic Stories

- Suspicious Regsvcs Regasm Activity
- Living Off The Land
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 3

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.009/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_regsvcs_with_network_connection.yml)*
