# Windows Domain Account Discovery Via Get-NetComputer

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of the PowerView PowerShell cmdlet Get-NetComputer, which is used to query Active Directory for user account details such as "samaccountname," "accountexpires," "lastlogon," and more. It leverages Event ID 4104 from PowerShell Script Block Logging to identify this activity. This behavior is significant as it may indicate an attempt to gather user account information, which is often a precursor to further malicious actions. If confirmed malicious, this activity could lead to unauthorized access, privilege escalation, or lateral movement within the network.

## MITRE ATT&CK

- T1087.002

## Analytic Stories

- CISA AA23-347A

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087/powerview_get_netuser_preauthnotrequire/get-netuser-not-require-pwh.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_domain_account_discovery_via_get_netcomputer.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
