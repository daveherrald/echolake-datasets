# GetWmiObject Ds Group with PowerShell Script Block

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-WmiObject` commandlet with the `DS_Group` parameter via PowerShell Script Block Logging (EventCode=4104). This method leverages WMI to query all domain groups. Monitoring this activity is crucial as adversaries and Red Teams may use it for domain group enumeration, aiding in situational awareness and Active Directory discovery. If confirmed malicious, this activity could allow attackers to map out the domain structure, potentially leading to further exploitation and privilege escalation within the network.

## MITRE ATT&CK

- T1069.002

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/getwmiobject_ds_group_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
