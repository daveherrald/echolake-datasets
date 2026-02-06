# Powershell Fileless Process Injection via GetProcAddress

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of `GetProcAddress` in PowerShell script blocks, leveraging PowerShell Script Block Logging (EventCode=4104). This method captures the full command sent to PowerShell, which is then logged in Windows event logs. The presence of `GetProcAddress` is unusual for typical PowerShell scripts and often indicates malicious activity, as many attack toolkits use it to achieve code execution. If confirmed malicious, this activity could allow an attacker to execute arbitrary code, potentially leading to system compromise. Analysts should review parallel processes and the entire logged script block for further investigation.

## MITRE ATT&CK

- T1055
- T1059.001

## Analytic Stories

- Hellcat Ransomware
- Malicious PowerShell
- Hermetic Wiper
- Data Destruction

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/sbl_xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_fileless_process_injection_via_getprocaddress.yml)*
