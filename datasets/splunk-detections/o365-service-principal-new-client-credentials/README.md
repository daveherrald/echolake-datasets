# O365 Service Principal New Client Credentials

**Type:** TTP

**Author:** Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the addition of new credentials for Service Principals within an Office 365 tenant. It uses O365 audit logs, focusing on events related to credential modifications or additions in the AzureActiveDirectory workload. This activity is significant because Service Principals represent application identities, and their credentials allow applications to authenticate and access resources. If an attacker successfully adds or modifies these credentials, they can impersonate the application, leading to unauthorized data access, data exfiltration, or malicious operations under the application's identity.

## MITRE ATT&CK

- T1098.001

## Analytic Stories

- Office 365 Persistence Mechanisms
- NOBELIUM Group

## Data Sources

- O365

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.001/o365_service_principal_credentials/o365_service_principal_credentials.log


---

*Source: [Splunk Security Content](detections/cloud/o365_service_principal_new_client_credentials.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
