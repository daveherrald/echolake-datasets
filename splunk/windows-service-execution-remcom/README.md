# Windows Service Execution RemCom

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the execution of RemCom.exe, an open-source alternative to PsExec, used for lateral movement and remote command execution. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, original file names, and command-line arguments. This activity is significant as it indicates potential lateral movement within the network. If confirmed malicious, this could allow an attacker to execute commands remotely, potentially leading to further compromise and control over additional systems within the network.

## MITRE ATT&CK

- T1569.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1569.002/remcom/remcom_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_execution_remcom.yml)*
