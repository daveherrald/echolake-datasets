# Azure AD User ImmutableId Attribute Updated

**Type:** TTP

**Author:** Mauricio Velazco, Gowthamaraj Rajendran, Splunk

## Description

This dataset contains sample data for identifying the modification of the SourceAnchor (ImmutableId) attribute for an Azure Active Directory user. This detection leverages Azure AD audit logs, specifically monitoring the "Update user" operation and changes to the SourceAnchor attribute. This activity is significant as it is a step in setting up an Azure AD identity federation backdoor, allowing an adversary to establish persistence. If confirmed malicious, the attacker could impersonate any user, bypassing password and MFA requirements, leading to unauthorized access and potential data breaches.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Azure Active Directory Persistence
- Hellcat Ransomware

## Data Sources

- Azure Active Directory Update user

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/azure_ad_set_immutableid/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_user_immutableid_attribute_updated.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
