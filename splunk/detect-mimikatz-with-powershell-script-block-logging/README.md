# Detect Mimikatz With PowerShell Script Block Logging

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of Mimikatz commands via PowerShell by leveraging PowerShell Script Block Logging (EventCode=4104). This method captures and logs the full command sent to PowerShell, allowing for the identification of suspicious activities such as Pass the Ticket, Pass the Hash, and credential dumping. This activity is significant as Mimikatz is a well-known tool used for credential theft and lateral movement. If confirmed malicious, this could lead to unauthorized access, privilege escalation, and potential compromise of sensitive information within the environment.

## MITRE ATT&CK

- T1003
- T1059.001

## Analytic Stories

- Hellcat Ransomware
- Malicious PowerShell
- Hermetic Wiper
- Sandworm Tools
- CISA AA22-264A
- CISA AA22-320A
- CISA AA23-347A
- Data Destruction
- Scattered Spider

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/credaccess-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_mimikatz_with_powershell_script_block_logging.yml)*
