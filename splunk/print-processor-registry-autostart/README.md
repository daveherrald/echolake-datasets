# Print Processor Registry Autostart

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious modifications or new entries in the Print Processor registry path. It leverages registry activity data from the Endpoint data model to identify changes in the specified registry path. This activity is significant because the Print Processor registry is known to be exploited by APT groups like Turla for persistence and privilege escalation. If confirmed malicious, this could allow an attacker to execute a malicious DLL payload by restarting the spoolsv.exe process, leading to potential control over the compromised machine.

## MITRE ATT&CK

- T1547.012

## Analytic Stories

- Data Destruction
- Windows Privilege Escalation
- Hermetic Wiper
- Windows Persistence Techniques

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/print_reg/sysmon_print.log


---

*Source: [Splunk Security Content](detections/endpoint/print_processor_registry_autostart.yml)*
