# Microsoft Intune DeviceManagementConfigurationPolicies

**Type:** Hunting

**Author:** Dean Luxton

## Description

Microsoft Intune device management configuration policies are a tool administrators can use to remotely manage policies and settings on intune managed devices. This functionality can also be abused to disable defences & evade detection.  This detection identifies when a new device management configuration policy has been created. 

## MITRE ATT&CK

- T1072
- T1484
- T1021.007
- T1562.001
- T1562.004

## Analytic Stories

- Azure Active Directory Account Takeover

## Data Sources

- Azure Monitor Activity

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1072/intune/intune.log


---

*Source: [Splunk Security Content](detections/cloud/microsoft_intune_devicemanagementconfigurationpolicies.yml)*
