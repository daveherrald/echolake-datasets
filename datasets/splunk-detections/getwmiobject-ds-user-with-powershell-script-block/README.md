# GetWmiObject DS User with PowerShell Script Block

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-WmiObject` cmdlet with the `DS_User` class parameter via PowerShell Script Block Logging (EventCode=4104). It leverages logs to identify attempts to query all domain users using WMI. This activity is significant as it may indicate an adversary or Red Team operation attempting to enumerate domain users for situational awareness and Active Directory discovery. If confirmed malicious, this behavior could lead to further reconnaissance, enabling attackers to map out the network and identify potential targets for privilege escalation or lateral movement.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getwmiobject_ds_user_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
