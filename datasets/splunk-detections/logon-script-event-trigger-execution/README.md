# Logon Script Event Trigger Execution

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the modification of the UserInitMprLogonScript registry entry, which is often used by attackers to establish persistence and gain privilege escalation upon system boot. It leverages data from the Endpoint.Registry data model, focusing on changes to the specified registry path. This activity is significant because it is a common technique used by APT groups and malware to ensure their payloads execute automatically when the system starts. If confirmed malicious, this could allow attackers to maintain persistent access and potentially escalate their privileges on the compromised host.

## MITRE ATT&CK

- T1037.001

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1037.001/logonscript_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/logon_script_event_trigger_execution.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
