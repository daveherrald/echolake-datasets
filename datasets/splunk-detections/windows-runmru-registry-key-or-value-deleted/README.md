# Windows RunMRU Registry Key or Value Deleted

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the deletion or modification of Most Recently Used (MRU) command entries stored within the Windows Registry. Adversaries often clear these registry keys, such as HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU, to remove forensic evidence of commands executed via the Windows Run dialog or other system utilities. This activity aims to obscure their actions, hinder incident response efforts, and evade detection. Detection focuses on monitoring for changes (deletion of values or modification of the MRUList value) to these specific registry paths, particularly when performed by unusual processes or outside of typical user behavior. Anomalous deletion events can indicate an attempt at defense evasion or post-exploitation cleanup by a malicious actor.

## MITRE ATT&CK

- T1112

## Analytic Stories

- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 12

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/delete_runmru_reg/runmru_deletion.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_runmru_registry_key_or_value_deleted.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
