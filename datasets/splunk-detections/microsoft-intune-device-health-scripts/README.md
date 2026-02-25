# Microsoft Intune Device Health Scripts

**Type:** Hunting

**Author:** Dean Luxton

## Description

Microsoft Intune device remediation scripts are a tool administrators can use to remotely manage devices, this functionality can also be abused for SYSTEM level code execution and lateral movement to intune managed devices.  This detection identifies when a new device health script has been added, updated or deleted. 

## MITRE ATT&CK

- T1072
- T1021.007
- T1202
- T1105

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Monitor Activity

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1072/intune/intune.log


---

*Source: [Splunk Security Content](detections/cloud/microsoft_intune_device_health_scripts.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
