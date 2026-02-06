# Detect Certify With PowerShell Script Block Logging

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects the use of the Certify tool via an in-memory PowerShell function to enumerate Active Directory Certificate Services (AD CS) environments. It leverages PowerShell Script Block Logging (EventCode 4104) to identify specific command patterns associated with Certify's enumeration and exploitation functions. This activity is significant as it indicates potential reconnaissance or exploitation attempts against AD CS, which could lead to unauthorized certificate issuance. If confirmed malicious, attackers could leverage this to escalate privileges, persist in the environment, or access sensitive information by abusing AD CS.

## MITRE ATT&CK

- T1059.001
- T1649

## Analytic Stories

- Windows Certificate Services
- Malicious PowerShell

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/certify_abuse/certify_esc1_abuse_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_certify_with_powershell_script_block_logging.yml)*
