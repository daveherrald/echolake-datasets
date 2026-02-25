# Spoolsv Writing a DLL - Sysmon

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting `spoolsv.exe` writing a `.dll` file, which is unusual behavior and may indicate exploitation of vulnerabilities like CVE-2021-34527 (PrintNightmare). This detection leverages Sysmon EventID 11 to monitor file creation events in the `\spool\drivers\x64\` directory. This activity is significant because `spoolsv.exe` typically does not write DLL files, and such behavior could signify an ongoing attack. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or maintain persistence on the compromised system.

## MITRE ATT&CK

- T1547.012

## Analytic Stories

- PrintNightmare CVE-2021-34527
- Black Basta Ransomware

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/spoolsv_writing_a_dll___sysmon.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
