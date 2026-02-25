# O365 Application Available To Other Tenants

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying the configuration of Azure Active Directory Applications in a manner that allows authentication from external tenants or personal accounts. This configuration can lead to inappropriate or malicious access of any data or capabilities the application is allowed to access. This detection leverages the O365 Universal Audit Log data source.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Persistence
- Azure Active Directory Account Takeover
- Data Exfiltration

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098/o365_azure_workload_events/o365_azure_workload_events.log


---

*Source: [Splunk Security Content](detections/cloud/o365_application_available_to_other_tenants.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
