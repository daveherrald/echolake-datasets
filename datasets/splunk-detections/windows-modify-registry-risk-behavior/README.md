# Windows Modify Registry Risk Behavior

**Type:** Correlation

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying instances where three or more distinct registry modification events associated with MITRE ATT&CK Technique T1112 are detected. It leverages data from the Risk data model in Splunk, focusing on registry-related sources and MITRE technique annotations. This activity is significant because multiple registry modifications can indicate an attempt to persist, hide malicious configurations, or erase forensic evidence. If confirmed malicious, this behavior could allow attackers to maintain persistent access, execute malicious code, and evade detection, posing a severe threat to the integrity and security of the affected host.

## MITRE ATT&CK

- T1112

## Analytic Stories

- Windows Registry Abuse

## Data Sources


## Sample Data

- **Source:** mod_reg
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1112/windows_mod_reg_risk_behavior/modify_reg_risk.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_modify_registry_risk_behavior.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
