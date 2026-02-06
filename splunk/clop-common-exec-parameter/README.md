# Clop Common Exec Parameter

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the execution of CLOP ransomware variants using specific arguments ("runrun" or "temp.dat") to trigger their malicious activities. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line arguments. Monitoring this activity is crucial as it indicates potential ransomware behavior, which can lead to file encryption on network shares or local machines. If confirmed malicious, this activity could result in significant data loss and operational disruption due to encrypted files, highlighting the need for immediate investigation and response.

## MITRE ATT&CK

- T1204

## Analytic Stories

- Compromised Windows Host
- Clop Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_b/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/clop_common_exec_parameter.yml)*
