# ServicePrincipalNames Discovery with PowerShell

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of `powershell.exe` to query the domain for Service Principal Names (SPNs) using Script Block Logging EventCode 4104. It identifies the use of the KerberosRequestorSecurityToken class within the script block, which is equivalent to using setspn.exe. This activity is significant as it often precedes kerberoasting or silver ticket attacks, which can lead to credential theft. If confirmed malicious, attackers could leverage this information to escalate privileges or persist within the environment.

## MITRE ATT&CK

- T1558.003

## Analytic Stories

- Hellcat Ransomware
- Active Directory Discovery
- Active Directory Kerberos Attacks
- Malicious PowerShell
- Active Directory Privilege Escalation

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/serviceprincipalnames_discovery_with_powershell.yml)*
