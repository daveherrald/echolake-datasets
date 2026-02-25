# User Discovery With Env Vars PowerShell Script Block

**Type:** Hunting

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the use of PowerShell environment variables to identify the current logged user by leveraging PowerShell Script Block Logging (EventCode=4104). This method monitors script blocks containing `$env:UserName` or `[System.Environment]::UserName`. Identifying this activity is significant as adversaries and Red Teams may use it for situational awareness and Active Directory discovery on compromised endpoints. If confirmed malicious, this activity could allow attackers to gain insights into user context, aiding in further exploitation and lateral movement within the network.

## MITRE ATT&CK

- T1033

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1033/AD_discovery/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/user_discovery_with_env_vars_powershell_script_block.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
