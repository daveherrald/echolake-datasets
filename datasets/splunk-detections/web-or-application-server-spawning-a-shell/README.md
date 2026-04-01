# Web or Application Server Spawning a Shell

**Type:** TTP

**Author:** Michael Haag, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting instances where Java, or Tomcat
processes spawn a Linux shell, which may indicate exploitation attempts, such as
those related to CVE-2021-44228 (Log4Shell). This detection leverages Endpoint Detection
and Response (EDR) telemetry, focusing on process names and parent-child process
relationships. This activity is significant as it can signify a compromised Java
application, potentially leading to unauthorized shell access. If confirmed malicious,
attackers could execute arbitrary commands, escalate privileges, or maintain persistent
access, posing a severe threat to the environment.


## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- BlackByte Ransomware
- CISA AA22-257A
- CISA AA22-264A
- Cleo File Transfer Software
- Data Destruction
- Flax Typhoon
- GhostRedirector IIS Module and Rungan Backdoor
- HAFNIUM Group
- Hermetic Wiper
- Log4Shell CVE-2021-44228
- Microsoft SharePoint Vulnerabilities
- Microsoft WSUS CVE-2025-59287
- PHP-CGI RCE Attack on Japanese Organizations
- ProxyNotShell
- ProxyShell
- SAP NetWeaver Exploitation
- Spring4Shell CVE-2022-22965
- SysAid On-Prem Software CVE-2023-47246 Vulnerability
- WS FTP Server Critical Vulnerabilities

## Data Sources

- Sysmon for Linux EventID 1
- Sysmon EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/java/java_spawn_shell_nix.log


---

*Source: [Splunk Security Content](detections/endpoint/web_or_application_server_spawning_a_shell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
