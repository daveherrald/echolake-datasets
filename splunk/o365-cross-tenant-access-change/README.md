# O365 Cross-Tenant Access Change

**Type:** TTP

**Author:** Steven Dick

## Description

The following analytic identifies when cross-tenant access/synchronization policies are changed in an Azure tenant. Adversaries have been observed altering victim cross-tenant policies as a method of lateral movement or maintaining persistent access to compromised environments. These policies should be considered sensitive and monitored for changes and/or loose configuration.

## MITRE ATT&CK

- T1484.002

## Analytic Stories

- Azure Active Directory Persistence

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/o365_azure_workload_events/o365_azure_workload_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_cross_tenant_access_change.yml)*
