# Detect Credential Dumping through LSASS access

**Type:** TTP

**Author:** Patrick Bareiss, Splunk

## Description

The following analytic detects attempts to read LSASS memory, indicative of credential dumping. It leverages Sysmon EventCode 10, filtering for specific access permissions (0x1010 and 0x1410) on the lsass.exe process. This activity is significant because it suggests an attacker is trying to extract credentials from LSASS memory, potentially leading to unauthorized access, data breaches, and compromise of sensitive information. If confirmed malicious, this could enable attackers to escalate privileges, move laterally within the network, or exfiltrate data. Extensive triage is necessary to differentiate between malicious and benign activities.

## MITRE ATT&CK

- T1003.001

## Analytic Stories

- Detect Zerologon Attack
- CISA AA23-347A
- Credential Dumping
- BlackSuit Ransomware
- Lokibot
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_credential_dumping_through_lsass_access.yml)*
