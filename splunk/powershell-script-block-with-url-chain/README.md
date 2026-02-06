# PowerShell Script Block With URL Chain

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies suspicious PowerShell script execution via EventCode 4104 that contains multiple URLs within a function or array. It leverages PowerShell operational logs to detect script blocks with embedded URLs, often indicative of obfuscated scripts or those attempting to download secondary payloads. This activity is significant as it may signal an attempt to execute malicious code or download additional malware. If confirmed malicious, this could lead to code execution, further system compromise, or data exfiltration. Review parallel processes and the full script block for additional context and related artifacts.

## MITRE ATT&CK

- T1059.001
- T1105

## Analytic Stories

- Malicious PowerShell
- Hellcat Ransomware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/gootloader/partial_ttps/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_script_block_with_url_chain.yml)*
