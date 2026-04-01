# Windows Visual Basic Commandline Compiler DNSQuery

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting instances where vbc.exe, the Visual Basic Command Line Compiler, initiates DNS queries. Normally, vbc.exe operates locally to compile Visual Basic code and does not require internet access or to perform DNS lookups. Therefore, any observed DNS activity originating from vbc.exe is highly suspicious and indicative of potential malicious activity. This behavior often suggests that a malicious payload is masquerading as the legitimate vbc.exe process to establish command-and-control (C2) communication, resolve domains for data exfiltration, or download additional stages of malware. Security teams should investigate the process's parent, command-line arguments, and the resolved domains for further indicators of compromise.

## MITRE ATT&CK

- T1071.004

## Analytic Stories

- Lokibot

## Data Sources

- Sysmon EventID 22

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1071.004/vbc_dnsquery/vbc_dns_query.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_visual_basic_commandline_compiler_dnsquery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
