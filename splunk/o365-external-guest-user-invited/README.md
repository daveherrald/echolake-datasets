# O365 External Guest User Invited

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies the invitation of an external guest user within Azure AD. With Azure AD B2B collaboration, users and administrators can invite external users to collaborate with internal users. External guest account invitations should be monitored by security teams as they could potentially lead to unauthorized access. An example of this attack vector was described at BlackHat 2022 by security researcher Dirk-Jan during his tall `Backdooring and Hijacking Azure AD Accounts by Abusing External Identities`. This detection leverages the Universal Audit Log (UAL)/o365:management:activity sourcetype as a detection data source.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/o365_azure_workload_events/o365_azure_workload_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_external_guest_user_invited.yml)*
