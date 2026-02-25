# O365 Service Principal Privilege Escalation

**Type:** TTP

**Author:** Dean Luxton

## Description

This detection identifies when an Azure Service Principal elevates privileges by adding themself to a new app role assignment.

## MITRE ATT&CK

- T1098.003

## Analytic Stories

- Azure Active Directory Privilege Escalation
- Office 365 Account Takeover

## Data Sources

- O365 Add app role assignment grant to user.

## Sample Data

- **Source:** Office 365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.003/o365_spn_privesc/o365_spn_privesc.log


---

*Source: [Splunk Security Content](detections/cloud/o365_service_principal_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
