# Get DomainPolicy with Powershell Script Block

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the `Get-DomainPolicy` cmdlet using PowerShell Script Block Logging (EventCode=4104). It leverages logs capturing script block text to identify attempts to obtain the password policy in a Windows domain. This activity is significant as it indicates potential reconnaissance efforts by adversaries or Red Teams to gather domain policy information, which is crucial for planning further attacks. If confirmed malicious, this behavior could lead to detailed knowledge of domain security settings, aiding in privilege escalation or lateral movement within the network.

## MITRE ATT&CK

- T1201

## Analytic Stories

- Active Directory Discovery

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/domainpolicy.log


---

*Source: [Splunk Security Content](detections/endpoint/get_domainpolicy_with_powershell_script_block.yml)*
