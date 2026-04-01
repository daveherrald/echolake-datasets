# O365 Multiple OS Vendors Authenticating From User

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when multiple operating systems are used to authenticate to Azure/EntraID/Office 365 by the same user account over a short period of time. This activity could be indicative of attackers enumerating various logon capabilities of Azure/EntraID/Office 365 and attempting to discover weaknesses in the organizational MFA or conditional access configurations. Usage of the tools like "MFASweep" will trigger this detection.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Office 365 Account Takeover

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110/azure_mfasweep_events/azure_mfasweep_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_multiple_os_vendors_authenticating_from_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
