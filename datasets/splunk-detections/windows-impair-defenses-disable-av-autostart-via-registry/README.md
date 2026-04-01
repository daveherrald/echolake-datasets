# Windows Impair Defenses Disable AV AutoStart via Registry

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the registry related to the disabling of autostart functionality for certain antivirus products, such as Kingsoft and Tencent. Malware like ValleyRAT may alter specific registry keys to prevent these security tools from launching automatically at startup, thereby weakening system defenses. By monitoring changes in the registry entries associated with antivirus autostart settings, this detection enables security analysts to identify attempts to disable protective software. Detecting these modifications early is critical for maintaining system integrity and preventing further compromise by malicious actors.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Scattered Lapsus$ Hunters
- ValleyRAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/kingsoft_reg/kingsoft_reg.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defenses_disable_av_autostart_via_registry.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
