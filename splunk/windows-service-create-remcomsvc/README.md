# Windows Service Create RemComSvc

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of the RemComSvc service on a Windows endpoint, typically indicating lateral movement using RemCom.exe. It leverages Windows EventCode 7045 from the System event log, specifically looking for the "RemCom Service" name. This activity is significant as it often signifies unauthorized lateral movement within the network, which is a common tactic used by attackers to spread malware or gain further access. If confirmed malicious, this could lead to unauthorized access to sensitive systems, data exfiltration, or further compromise of the network.

## MITRE ATT&CK

- T1543.003

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Windows Event Log System 7045

## Sample Data

- **Source:** XmlWinEventLog:System
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1543.003/atomic_red_team/remcom_windows-system.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_service_create_remcomsvc.yml)*
