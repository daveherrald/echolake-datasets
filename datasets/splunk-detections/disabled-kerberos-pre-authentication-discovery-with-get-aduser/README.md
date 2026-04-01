# Disabled Kerberos Pre-Authentication Discovery With Get-ADUser

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the execution of the `Get-ADUser` PowerShell cmdlet with parameters indicating a search for domain accounts with Kerberos Pre-Authentication disabled. It leverages PowerShell Script Block Logging (EventCode=4104) to identify this specific activity. This behavior is significant because discovering accounts with Kerberos Pre-Authentication disabled can allow adversaries to perform offline password cracking. If confirmed malicious, this activity could lead to unauthorized access to user accounts, potentially compromising sensitive information and escalating privileges within the network.

## MITRE ATT&CK

- T1558.004

## Analytic Stories

- CISA AA23-347A
- Active Directory Kerberos Attacks
- BlackSuit Ransomware
- Interlock Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/getaduser/get-aduser-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/disabled_kerberos_pre_authentication_discovery_with_get_aduser.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
