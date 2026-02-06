# O365 Added Service Principal

**Type:** TTP

**Author:** Rod Soto, Splunk

## Description

The following analytic detects the addition of new service principal accounts in O365 tenants. It leverages data from the `o365_management_activity` dataset, specifically monitoring for operations related to adding or creating service principals. This activity is significant because attackers can exploit service principals to gain unauthorized access and perform malicious actions within an organization's environment. If confirmed malicious, this could allow attackers to interact with APIs, access resources, and execute operations on behalf of the organization, potentially leading to data breaches or further compromise.

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
