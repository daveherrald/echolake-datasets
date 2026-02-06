# Spoolsv Suspicious Process Access

**Type:** TTP

**Author:** Mauricio Velazco, Michael Haag, Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious process access by spoolsv.exe, potentially indicating exploitation of the PrintNightmare vulnerability (CVE-2021-34527). It leverages Sysmon EventCode 10 to identify when spoolsv.exe accesses critical system files or processes like rundll32.exe with elevated privileges. This activity is significant as it may signal an attempt to gain unauthorized privilege escalation on a vulnerable machine. If confirmed malicious, an attacker could achieve elevated privileges, leading to further system compromise, persistent access, or unauthorized control over the affected environment.

## MITRE ATT&CK

- T1068

## Analytic Stories

- PrintNightmare CVE-2021-34527
- Black Basta Ransomware

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/spoolsv_suspicious_process_access.yml)*
