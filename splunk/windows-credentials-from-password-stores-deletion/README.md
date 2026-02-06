# Windows Credentials from Password Stores Deletion

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the Windows OS tool cmdkey.exe with the /delete parameter. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs and command-line arguments. The activity is significant because cmdkey.exe can be used by attackers to delete stored credentials, potentially leading to privilege escalation and persistence. If confirmed malicious, this behavior could allow attackers to remove stored user credentials, hindering incident response efforts and enabling further unauthorized access to the compromised system.

## MITRE ATT&CK

- T1555

## Analytic Stories

- Compromised Windows Host
- DarkGate Malware
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1555/cmdkey_delete_credentials_store/cmdkey_del_sys.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_credentials_from_password_stores_deletion.yml)*
