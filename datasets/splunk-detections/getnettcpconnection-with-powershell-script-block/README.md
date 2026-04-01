# GetNetTcpconnection with PowerShell Script Block

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-NetTcpconnection` PowerShell cmdlet using PowerShell Script Block Logging (EventCode=4104). This cmdlet lists network connections on a system, which adversaries may use for situational awareness and Active Directory discovery. Monitoring this activity is crucial as it can indicate reconnaissance efforts by an attacker. If confirmed malicious, this behavior could allow an attacker to map the network, identify critical systems, and plan further attacks, potentially leading to data exfiltration or lateral movement within the network.

## MITRE ATT&CK

- T1049

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/nettcpconnection.log


---

*Source: [Splunk Security Content](detections/endpoint/getnettcpconnection_with_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
