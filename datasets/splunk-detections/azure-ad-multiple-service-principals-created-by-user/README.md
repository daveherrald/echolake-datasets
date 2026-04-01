# Azure AD Multiple Service Principals Created by User

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where a single user creates more than three unique OAuth applications within a 10-minute timeframe in Azure AD. It detects this activity by monitoring the 'Add service principal' operation and aggregating data in 10-minute intervals. This behavior is significant as it may indicate an adversary rapidly creating multiple service principals to stage an attack or expand their foothold within the network. If confirmed malicious, this activity could allow attackers to establish persistence, escalate privileges, or access sensitive information within the Azure environment.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Azure Active Directory Persistence
- NOBELIUM Group

## Data Sources

- Azure Active Directory Add service principal

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/azure_ad_multiple_service_principals_created/azure_ad_multiple_service_principals_created.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_multiple_service_principals_created_by_user.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
