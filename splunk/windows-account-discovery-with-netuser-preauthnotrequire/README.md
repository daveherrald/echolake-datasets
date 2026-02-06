# Windows Account Discovery With NetUser PreauthNotRequire

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the PowerView PowerShell cmdlet Get-NetUser with the -PreauthNotRequire parameter, leveraging Event ID 4104. This method identifies attempts to query Active Directory user accounts that do not require Kerberos preauthentication. Monitoring this activity is crucial as it can indicate reconnaissance efforts by an attacker to identify potentially vulnerable accounts. If confirmed malicious, this behavior could lead to further exploitation, such as unauthorized access or privilege escalation within the network.

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

*Source: [Splunk Security Content](detections/endpoint/windows_account_discovery_with_netuser_preauthnotrequire.yml)*
