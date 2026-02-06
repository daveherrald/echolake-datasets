# GetWmiObject User Account with PowerShell Script Block

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of the `Get-WmiObject` commandlet with the `Win32_UserAccount` parameter via PowerShell Script Block Logging (EventCode=4104). This method leverages script block text to identify when a list of all local users is being enumerated. This activity is significant as it may indicate an adversary or Red Team operation attempting to gather user information for situational awareness and Active Directory discovery. If confirmed malicious, this could lead to further reconnaissance, privilege escalation, or lateral movement within the network.

## MITRE ATT&CK

- T1059.001
- T1087.001

## Analytic Stories

- Winter Vivern
- Active Directory Discovery
- Malicious PowerShell

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getwmiobject_user_account_with_powershell_script_block.yml)*
