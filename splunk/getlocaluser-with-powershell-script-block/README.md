# GetLocalUser with PowerShell Script Block

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects the execution of the `Get-LocalUser` PowerShell commandlet using PowerShell Script Block Logging (EventCode=4104). This commandlet lists all local users on a system. The detection leverages script block text from PowerShell logs to identify this activity. Monitoring this behavior is significant as adversaries and Red Teams may use it to enumerate local users for situational awareness and Active Directory discovery. If confirmed malicious, this activity could lead to further reconnaissance, enabling attackers to identify potential targets for privilege escalation or lateral movement.

## MITRE ATT&CK

- T1059.001
- T1087.001

## Analytic Stories

- Active Directory Discovery
- Malicious PowerShell

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.001/AD_discovery/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getlocaluser_with_powershell_script_block.yml)*
