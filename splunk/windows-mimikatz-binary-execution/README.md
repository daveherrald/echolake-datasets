# Windows Mimikatz Binary Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the execution of the native mimikatz.exe binary on Windows systems, including instances where the binary is renamed. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and original file names. This activity is significant because Mimikatz is a widely used tool for extracting authentication credentials, posing a severe security risk. If confirmed malicious, this activity could allow attackers to obtain sensitive credentials, escalate privileges, and move laterally within the network, leading to potential data breaches and system compromise.

## MITRE ATT&CK

- T1003

## Analytic Stories

- Sandworm Tools
- Volt Typhoon
- Flax Typhoon
- CISA AA22-320A
- CISA AA23-347A
- Compromised Windows Host
- Credential Dumping
- Scattered Spider

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003/credential_extraction/mimikatzwindows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_mimikatz_binary_execution.yml)*
