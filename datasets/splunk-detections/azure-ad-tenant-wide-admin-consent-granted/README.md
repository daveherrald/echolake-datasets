# Azure AD Tenant Wide Admin Consent Granted

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where admin consent is granted to an application within an Azure AD tenant. It leverages Azure AD audit logs, specifically events related to the admin consent action within the ApplicationManagement category. This activity is significant because admin consent allows applications to access data across the entire tenant, potentially exposing vast amounts of organizational data. If confirmed malicious, an attacker could gain extensive and persistent access to sensitive data, leading to data exfiltration, espionage, further malicious activities, and potential compliance violations.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Persistence
- NOBELIUM Group

## Data Sources

- Azure Active Directory Consent to application

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/azure_ad_admin_consent/azure_ad_admin_consent.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_tenant_wide_admin_consent_granted.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
