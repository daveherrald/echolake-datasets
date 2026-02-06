# Azure AD Multiple Service Principals Created by SP

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic detects when a single service principal in Azure AD creates more than three unique OAuth applications within a 10-minute span. It leverages Azure AD audit logs, specifically monitoring the 'Add service principal' operation initiated by service principals. This behavior is significant as it may indicate an attacker using a compromised or malicious service principal to rapidly establish multiple service principals, potentially staging an attack. If confirmed malicious, this activity could facilitate network infiltration or expansion, allowing the attacker to gain unauthorized access and persist within the environment.

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

*Source: [Splunk Security Content](detections/cloud/azure_ad_multiple_service_principals_created_by_sp.yml)*
