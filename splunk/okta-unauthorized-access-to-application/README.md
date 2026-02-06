# Okta Unauthorized Access to Application

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies attempts by users to access Okta applications that have not been assigned to them. It leverages Okta Identity Management logs, specifically focusing on failed access attempts to unassigned applications. This activity is significant for a SOC as it may indicate potential unauthorized access attempts, which could lead to exposure of sensitive information or disruption of services. If confirmed malicious, such activity could result in data breaches, non-compliance with data protection laws, and overall compromise of the IT environment.

## MITRE ATT&CK

- T1087.004

## Analytic Stories

- Okta Account Takeover

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1087.004/okta_unauth_access/okta_unauth_access.log


---

*Source: [Splunk Security Content](detections/application/okta_unauthorized_access_to_application.yml)*
