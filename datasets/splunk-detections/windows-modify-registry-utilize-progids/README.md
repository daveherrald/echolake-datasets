# Windows Modify Registry Utilize ProgIDs

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows Registry specifically targeting Programmatic Identifier associations to bypass User Account Control (UAC) Windows OS feature. ValleyRAT may create or alter registry entries to targetted progIDs like `.pwn` files with malicious processes, allowing it to execute harmful scripts or commands when these files are opened. By monitoring for unusual changes in registry keys linked to ProgIDs, this detection enables security analysts to identify potential threats like ValleyRAT execution attempts. Early detection of these modifications helps mitigate unauthorized execution and prevents further exploitation of the system.

## MITRE ATT&CK

- T1112

## Analytic Stories

- ValleyRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/pwn_reg/pwn_reg.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_utilize_progids.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
