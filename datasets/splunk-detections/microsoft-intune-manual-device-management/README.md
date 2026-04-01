# Microsoft Intune Manual Device Management

**Type:** Hunting

**Author:** Dean Luxton

## Description

Microsoft Intune device management configuration policies, scripts & apps are a all tools administrators can use to remotely manage intune managed devices. Instead of waiting for the devices to poll for changes to polciies, the policies can be manually pushed to expidite delivery.  This may be useful in a pinch, it may also be a sign of an impatient attacker trying to speed up the delivery of their payload.  This detection identifies when a device management configuration policy sync events, on-demand remediation scripts are triggered or when devices are remotely restarted. 

## MITRE ATT&CK

- T1021.007
- T1072
- T1529

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Monitor Activity

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1072/intune/intune.log


---

*Source: [Splunk Security Content](detections/cloud/microsoft_intune_manual_device_management.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
