# Windows SSH Proxy Command

**Type:** Anomaly

**Author:** Michael Haag, AJ King, Nasreddine Bencherchali, Splunk, Jesse Hunter, Splunk Community Contributor

## Description

This detection identifies potential abuse of SSH "ProxyCommand" or "LocalCommand" by monitoring for suspicious process execution patterns.
Specifically, it looks for instances where ssh.exe (as a parent process) containing "ProxyCommand" or "LocalCommand" in its arguments spawns potentially malicious child processes like mshta, powershell, wscript, or cscript, or processes containing "http" in their command line.
This technique can be used by attackers to execute arbitrary commands through SSH proxy configurations, potentially enabling command & control activities or remote code execution. The detection focuses on commonly abused Windows scripting engines and web requests that may indicate malicious activity when spawned through SSH proxy commands.


## MITRE ATT&CK

- T1572
- T1059.001
- T1105

## Analytic Stories

- ZDI-CAN-25373 Windows Shortcut Exploit Abused as Zero-Day
- Living Off The Land
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1572/ssh_proxy_command/sshproxycommand_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_ssh_proxy_command.yml)*
