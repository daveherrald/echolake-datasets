# O365 Application Registration Owner Added

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where a new owner is assigned to an application registration within an Azure AD and Office 365 tenant. It leverages O365 audit logs, specifically events related to changes in owner assignments within the AzureActiveDirectory workload. This activity is significant because assigning a new owner to an application registration can grant significant control over the application's configuration, permissions, and behavior. If confirmed malicious, an attacker could modify the application's settings, permissions, and behavior, leading to unauthorized data access, privilege escalation, or the introduction of malicious behavior within the application's operations.

## MITRE ATT&CK

- T1098

## Analytic Stories

- Office 365 Persistence Mechanisms
- NOBELIUM Group

## Data Sources

- O365 Add owner to application.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/o365_add_app_registration_owner/o365_add_app_registration_owner.log


---

*Source: [Splunk Security Content](detections/cloud/o365_application_registration_owner_added.yml)*
