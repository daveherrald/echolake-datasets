# PowerShell WebRequest Using Memory Stream

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects the use of .NET classes in PowerShell to download a URL payload directly into memory, a common fileless malware staging technique. It leverages PowerShell Script Block Logging (EventCode=4104) to identify suspicious PowerShell commands involving `system.net.webclient`, `system.net.webrequest`, and `IO.MemoryStream`. This activity is significant as it indicates potential fileless malware execution, which is harder to detect and can bypass traditional file-based defenses. If confirmed malicious, this technique could allow attackers to execute code in memory, evade detection, and maintain persistence in the environment.

## MITRE ATT&CK

- T1059.001
- T1105
- T1027.011

## Analytic Stories

- MoonPeak
- Medusa Ransomware
- Malicious PowerShell
- PHP-CGI RCE Attack on Japanese Organizations

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/gootloader/partial_ttps/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_webrequest_using_memory_stream.yml)*
