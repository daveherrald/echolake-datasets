# Windows PowerView SPN Discovery

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Splunk

## Description

The following analytic detects the execution of the `Get-DomainUser` or `Get-NetUser` PowerShell cmdlets with the `-SPN` parameter, indicating the use of PowerView for SPN discovery. It leverages PowerShell Script Block Logging (EventCode=4104) to identify these specific commands. This activity is significant as it suggests an attempt to enumerate domain accounts associated with Service Principal Names (SPNs), a common precursor to Kerberoasting attacks. If confirmed malicious, this could allow an attacker to identify and target accounts for credential theft, potentially leading to unauthorized access and privilege escalation within the network.

## MITRE ATT&CK

- T1558.003

## Analytic Stories

- CISA AA23-347A
- Rhysida Ransomware
- Active Directory Kerberos Attacks
- Interlock Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1558.003/powerview-2/windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powerview_spn_discovery.yml)*
