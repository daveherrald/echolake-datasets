# O365 External Identity Policy Changed

**Type:** TTP

**Author:** Steven Dick

## Description

This dataset contains sample data for identifying when changes are made to the external guest policies within Azure AD. With Azure AD B2B collaboration, users and administrators can invite external users to collaborate with internal users. This detection also attempts to highlight what may have changed. External guest account invitations should be monitored by security teams as they could potentially lead to unauthorized access. An example of this attack vector was described at BlackHat 2022 by security researcher Dirk-Jan during his tall `Backdooring and Hijacking Azure AD Accounts by Abusing External Identities`.

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

*Source: [Splunk Security Content](detections/cloud/o365_external_identity_policy_changed.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
