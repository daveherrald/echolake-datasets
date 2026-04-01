# O365 Added Service Principal

**Type:** TTP

**Author:** Rod Soto, Splunk

## Description

This dataset contains sample data for detecting the addition of new service principal accounts in O365 tenants. It leverages data from the `o365_management_activity` dataset, specifically monitoring for operations related to adding or creating service principals. This activity is significant because attackers can exploit service principals to gain unauthorized access and perform malicious actions within an organization's environment. If confirmed malicious, this could allow attackers to interact with APIs, access resources, and execute operations on behalf of the organization, potentially leading to data breaches or further compromise.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Office 365 Persistence Mechanisms
- Cloud Federated Credential Abuse
- NOBELIUM Group

## Data Sources

- O365

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_added_service_principal/o365_add_service_principal.log


---

*Source: [Splunk Security Content](detections/cloud/o365_added_service_principal.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
