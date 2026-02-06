# O365 Privileged Role Assigned

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies the assignment of sensitive and privileged Azure Active Directory roles to an Azure AD user. Adversaries and red teams alike may assign these roles to a compromised account to establish Persistence in an Azure AD environment. This detection leverages the O365 Universal Audit Log data source.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Persistence
- Scattered Lapsus$ Hunters

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/o365_azure_workload_events/o365_azure_workload_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_privileged_role_assigned.yml)*
