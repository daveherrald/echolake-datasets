# Windows New Default File Association Value Set

**Type:** Hunting

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects registry changes to the default file association value. It leverages data from the Endpoint data model, specifically monitoring registry paths under "HKCR\\*\\shell\\open\\command\\*". This activity can be significant because, attackers might alter the default file associations in order to execute arbitrary scripts or payloads when a user opens a file, leading to potential code execution. If confirmed malicious, this technique can enable attackers to persist on the compromised host and execute further malicious commands, posing a severe threat to the environment.

## MITRE ATT&CK

- T1546.001

## Analytic Stories

- Hermetic Wiper
- Windows Registry Abuse
- Prestige Ransomware
- Windows Privilege Escalation
- Windows Persistence Techniques
- Data Destruction

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.001/txtfile_reg/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_new_default_file_association_value_set.yml)*
