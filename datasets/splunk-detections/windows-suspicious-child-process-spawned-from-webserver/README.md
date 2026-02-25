# Windows Suspicious Child Process Spawned From WebServer

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying the execution of suspicious processes typically associated with WebShell activity on web servers. It detects when processes like `cmd.exe`, `powershell.exe`, or `bash.exe` are spawned by web server processes such as `w3wp.exe` or `nginx.exe`. This behavior is significant as it may indicate an adversary exploiting a web application vulnerability to install a WebShell, providing persistent access and command execution capabilities. If confirmed malicious, this activity could allow attackers to maintain control over the compromised server, execute arbitrary commands, and potentially escalate privileges or exfiltrate sensitive data.

## MITRE ATT&CK

- T1505.003

## Analytic Stories

- Flax Typhoon
- BlackByte Ransomware
- CISA AA22-257A
- HAFNIUM Group
- CISA AA22-264A
- ProxyShell
- SysAid On-Prem Software CVE-2023-47246 Vulnerability
- ProxyNotShell
- Medusa Ransomware
- WS FTP Server Critical Vulnerabilities
- Compromised Windows Host
- Citrix ShareFile RCE CVE-2023-24489
- Microsoft SharePoint Vulnerabilities
- GhostRedirector IIS Module and Rungan Backdoor
- Microsoft WSUS CVE-2025-59287

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.003/generic_webshell_exploit/generic_webshell_exploit.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_suspicious_child_process_spawned_from_webserver.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
