# Windows Account Discovery for None Disable User Account

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the PowerView PowerShell cmdlet Get-NetUser with the UACFilter parameter set to NOT_ACCOUNTDISABLE, indicating an attempt to enumerate Active Directory user accounts that are not disabled. This detection leverages PowerShell Script Block Logging (EventCode 4104) to identify the specific script block text. Monitoring this activity is significant as it may indicate reconnaissance efforts by an attacker to identify active user accounts for further exploitation. If confirmed malicious, this activity could lead to unauthorized access, privilege escalation, or lateral movement within the network.

## MITRE ATT&CK

- T1087.001

## Analytic Stories

- CISA AA23-347A

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087/powerview_get_netuser_preauthnotrequire/get-netuser-not-require-pwh.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_account_discovery_for_none_disable_user_account.yml)*
