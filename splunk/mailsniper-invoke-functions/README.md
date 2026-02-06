# Mailsniper Invoke functions

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of known MailSniper PowerShell functions on a machine. It leverages PowerShell logs (EventCode 4104) to identify specific script block text associated with MailSniper activities. This behavior is significant as MailSniper is often used by attackers to harvest sensitive emails from compromised Exchange servers. If confirmed malicious, this activity could lead to unauthorized access to sensitive email data, credential theft, and further compromise of the email infrastructure.

## MITRE ATT&CK

- T1114.001

## Analytic Stories

- Data Exfiltration

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/mailsniper_invoke_functions.yml)*
