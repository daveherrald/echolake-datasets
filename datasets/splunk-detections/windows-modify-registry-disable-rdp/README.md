# Windows Modify Registry Disable RDP

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This analytic is developed to detect suspicious registry modifications that disable Remote Desktop Protocol (RDP) by altering the "fDenyTSConnections" key. Changing this key's value to 1 prevents remote connections, which can disrupt remote management and access. Such modifications could indicate an attempt to hinder remote administration or isolate the system from remote intervention, potentially signifying malicious activity.

## MITRE ATT&CK

- T1112

## Analytic Stories

- ShrinkLocker
- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/disable_rdp//fdenytsconnection-reg.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_disable_rdp.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
