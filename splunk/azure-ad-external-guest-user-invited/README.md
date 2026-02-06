# Azure AD External Guest User Invited

**Type:** TTP

**Author:** Gowthamaraj Rajendran, Mauricio Velazco, Splunk

## Description

The following analytic detects the invitation of an external guest user within Azure AD. It leverages Azure AD AuditLogs to identify events where an external user is invited, using fields such as operationName and initiatedBy. Monitoring these invitations is crucial as they can lead to unauthorized access if abused. If confirmed malicious, this activity could allow attackers to gain access to internal resources, potentially leading to data breaches or further exploitation of the environment.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Azure Active Directory Invite external user

## Sample Data

- **Source:** Azure AD
  **Sourcetype:** azure:monitor:aad
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/azure_ad_external_guest_user_invited/azure-audit.log


---

*Source: [Splunk Security Content](detections/cloud/azure_ad_external_guest_user_invited.yml)*
