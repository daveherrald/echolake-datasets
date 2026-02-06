# Windows Handle Duplication in Known UAC-Bypass Binaries

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious handle duplication activity targeting known Windows utilities such as ComputerDefaults.exe, Eventvwr.exe, and others. This technique is commonly used to escalate privileges or bypass UAC by inheriting or injecting elevated tokens or handles. The detection focuses on non-standard use of DuplicateHandle or token duplication where process, thread, or token handles are copied into the context of trusted, signed utilities. Such behavior may indicate attempts to execute with elevated rights without user consent. Alerts enable rapid triage using process trees, handle data, token attributes, command-lines, and binary hashes.

## MITRE ATT&CK

- T1134.001

## Analytic Stories

- Castle RAT

## Data Sources

- Sysmon EventID 10

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1134.001/uac_process_handle_dup/Computerdefaults_access.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_handle_duplication_in_known_uac_bypass_binaries.yml)*
