# Java Writing JSP File

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the Java process writing a .jsp file to disk, which may indicate a web shell being deployed. It leverages data from the Endpoint datamodel, specifically monitoring process and filesystem activities. This activity is significant because web shells can provide attackers with remote control over the compromised server, leading to further exploitation. If confirmed malicious, this could allow unauthorized access, data exfiltration, or further compromise of the affected system, posing a severe security risk.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- Spring4Shell CVE-2022-22965
- Atlassian Confluence Server and Data Center CVE-2022-26134
- SysAid On-Prem Software CVE-2023-47246 Vulnerability
- SAP NetWeaver Exploitation

## Data Sources

- Sysmon for Linux EventID 1 AND Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/java_write_jsp-linux-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/java_writing_jsp_file.yml)*
