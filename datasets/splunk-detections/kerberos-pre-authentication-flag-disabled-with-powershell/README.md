# Kerberos Pre-Authentication Flag Disabled with PowerShell

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the use of the `Set-ADAccountControl` PowerShell cmdlet with parameters that disable Kerberos Pre-Authentication. It leverages PowerShell Script Block Logging (EventCode=4104) to identify this specific command execution. Disabling Kerberos Pre-Authentication is significant because it allows adversaries to perform offline brute force attacks against user passwords using the AS-REP Roasting technique. If confirmed malicious, this activity could enable attackers to escalate privileges or maintain persistence within an Active Directory environment, posing a severe security risk.

## MITRE ATT&CK

- T1558.004

## Analytic Stories

- Active Directory Kerberos Attacks

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.004/powershell/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/kerberos_pre_authentication_flag_disabled_with_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
