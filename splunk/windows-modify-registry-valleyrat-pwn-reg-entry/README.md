# Windows Modify Registry ValleyRat PWN Reg Entry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows Registry specifically targeting `.pwn` file associations related to the ValleyRAT malware. ValleyRAT may create or alter registry entries to associate `.pwn` files with malicious processes, allowing it to execute harmful scripts or commands when these files are opened. By monitoring for unusual changes in registry keys linked to `.pwn` extensions, this detection enables security analysts to identify potential ValleyRAT infection attempts. Early detection of these modifications helps mitigate unauthorized execution and prevents further exploitation of the system.

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

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_valleyrat_pwn_reg_entry.yml)*
