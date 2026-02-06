# Spoolsv Writing a DLL

**Type:** TTP

**Author:** Mauricio Velazco, Michael Haag, Splunk

## Description

The following analytic detects `spoolsv.exe` writing a `.dll` file, which is unusual behavior and may indicate exploitation of vulnerabilities like CVE-2021-34527 (PrintNightmare). This detection leverages the Endpoint datamodel, specifically monitoring process and filesystem events to identify `.dll` file creation within the `\spool\drivers\x64\` path. This activity is significant as it may signify an attacker attempting to execute malicious code via the Print Spooler service. If confirmed malicious, this could lead to unauthorized code execution and potential system compromise. Immediate endpoint isolation and further investigation are recommended.

## MITRE ATT&CK

- T1547.012

## Analytic Stories

- PrintNightmare CVE-2021-34527
- Compromised Windows Host
- Black Basta Ransomware

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11
- Windows Event Log Security 4688 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/spoolsv_writing_a_dll.yml)*
