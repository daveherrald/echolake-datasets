# Windows Account Discovery for Sam Account Name

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the PowerView PowerShell cmdlet Get-NetUser, specifically querying for "samaccountname" and "pwdlastset" attributes. It leverages Event ID 4104 from PowerShell Script Block Logging to identify this activity. This behavior is significant as it may indicate an attempt to gather user account information from Active Directory, which is a common reconnaissance step in lateral movement or privilege escalation attacks. If confirmed malicious, this activity could allow an attacker to map out user accounts, potentially leading to further exploitation and unauthorized access within the network.

## MITRE ATT&CK

- T1087

## Analytic Stories

- CISA AA23-347A

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087/powerview_get_netuser_preauthnotrequire/get-netuser-not-require-pwh.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_account_discovery_for_sam_account_name.yml)*
