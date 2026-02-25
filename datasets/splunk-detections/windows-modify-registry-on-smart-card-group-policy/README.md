# Windows Modify Registry on Smart Card Group Policy

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This analytic is developed to detect suspicious registry modifications targeting the "scforceoption" key. Altering this key enforces smart card login for all users, potentially disrupting normal access methods. Unauthorized changes to this setting could indicate an attempt to restrict access or force a specific authentication method, possibly signifying malicious intent to manipulate system security protocols.

## MITRE ATT&CK

- T1112

## Analytic Stories

- ShrinkLocker

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/smart_card_group_policy/scforceoption-reg.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_on_smart_card_group_policy.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
