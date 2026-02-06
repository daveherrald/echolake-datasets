# Spoolsv Suspicious Loaded Modules

**Type:** TTP

**Author:** Mauricio Velazco, Michael Haag, Teoderick Contreras, Splunk

## Description

The following analytic detects the suspicious loading of DLLs by spoolsv.exe, potentially indicating PrintNightmare exploitation. It leverages Sysmon EventCode 7 to identify instances where spoolsv.exe loads multiple DLLs from the Windows System32 spool drivers x64 directory. This activity is significant as it may signify an attacker exploiting the PrintNightmare vulnerability to execute arbitrary code. If confirmed malicious, this could lead to unauthorized code execution, privilege escalation, and persistent access within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1547.012

## Analytic Stories

- PrintNightmare CVE-2021-34527
- Black Basta Ransomware

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/spoolsv_suspicious_loaded_modules.yml)*
