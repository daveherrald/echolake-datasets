# O365 Tenant Wide Admin Consent Granted

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where admin consent is granted to an application within an Azure AD and Office 365 tenant. It leverages O365 audit logs, specifically events related to the admin consent action within the AzureActiveDirectory workload. This activity is significant because admin consent allows applications to access data across the entire tenant, potentially exposing vast amounts of organizational data. If confirmed malicious, an attacker could gain extensive and persistent access to organizational data, leading to data exfiltration, espionage, further malicious activities, and potential compliance violations.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Office 365 Persistence Mechanisms
- NOBELIUM Group

## Data Sources

- O365 Consent to application.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/o365_admin_consent/o365_admin_consent.log


---

*Source: [Splunk Security Content](detections/cloud/o365_tenant_wide_admin_consent_granted.yml)*
