# O365 Privileged Role Assigned To Service Principal

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic detects potential privilege escalation threats in Azure Active Directory (AD). This detection is important because it identifies instances where privileged roles that hold elevated permissions are assigned to service principals. This prevents unauthorized access or malicious activities, which occur when these non-human entities access Azure resources to exploit them. False positives might occur since administrators can legitimately assign privileged roles to service principals. This detection leverages the O365 Universal Audit Log data source.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Privilege Escalation
- Scattered Lapsus$ Hunters

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/o365_azure_workload_events/o365_azure_workload_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_privileged_role_assigned_to_service_principal.yml)*
