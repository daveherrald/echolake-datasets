# O365 Add App Role Assignment Grant User

**Type:** TTP

**Author:** Rod Soto, Splunk

## Description

The following analytic detects the addition of an application role assignment grant to a user in Office 365. It leverages data from the `o365_management_activity` dataset, specifically monitoring the "Add app role assignment grant to user" operation. This activity is significant as it can indicate unauthorized privilege escalation or the assignment of sensitive roles to users. If confirmed malicious, this could allow an attacker to gain elevated permissions, potentially leading to unauthorized access to critical resources and data within the Office 365 environment.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Office 365 Persistence Mechanisms
- Cloud Federated Credential Abuse

## Data Sources

- O365 Add app role assignment grant to user.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_new_federation/o365_new_federation.json


---

*Source: [Splunk Security Content](detections/cloud/o365_add_app_role_assignment_grant_user.yml)*
