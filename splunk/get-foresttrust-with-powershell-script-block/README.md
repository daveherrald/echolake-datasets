# Get-ForestTrust with PowerShell Script Block

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of the Get-ForestTrust command from PowerSploit using PowerShell Script Block Logging (EventCode=4104). This method captures the full command sent to PowerShell, providing detailed visibility into potentially suspicious activities. Monitoring this behavior is crucial as it can indicate an attempt to gather domain trust information, which is often a precursor to lateral movement or privilege escalation. If confirmed malicious, this activity could allow an attacker to map trust relationships within the domain, facilitating further exploitation and access to sensitive resources.

## MITRE ATT&CK

- T1482
- T1059.001

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1482/discovery/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/get_foresttrust_with_powershell_script_block.yml)*
