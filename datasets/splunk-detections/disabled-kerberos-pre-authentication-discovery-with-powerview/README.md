# Disabled Kerberos Pre-Authentication Discovery With PowerView

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-DomainUser` commandlet with the `-PreauthNotRequired` parameter using PowerShell Script Block Logging (EventCode=4104). This command is part of PowerView, a tool used for enumerating Windows Active Directory networks. Identifying domain accounts with Kerberos Pre-Authentication disabled is significant because adversaries can leverage this information to attempt offline password cracking. If confirmed malicious, this activity could lead to unauthorized access to domain accounts, potentially compromising sensitive information and escalating privileges within the network.

## MITRE ATT&CK

- T1558.004

## Analytic Stories

- Active Directory Kerberos Attacks
- Interlock Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/getdomainuser.log


---

*Source: [Splunk Security Content](detections/endpoint/disabled_kerberos_pre_authentication_discovery_with_powerview.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
