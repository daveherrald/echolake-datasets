# O365 Multiple Service Principals Created by SP

**Type:** Anomaly

**Author:** Mauricio Velazco, Splunk

## Description

The following analytic identifies instances where a single service principal creates more than three unique OAuth applications within a 10-minute timeframe. It leverages O365 logs from the Unified Audit Log, focusing on the 'Add service principal' operation in the Office 365 Azure Active Directory environment. This activity is significant as it may indicate a compromised or malicious service principal attempting to expand control or access within the network. If confirmed malicious, this could lead to unauthorized access and potential lateral movement within the environment, posing a significant security risk.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Office 365 Persistence Mechanisms
- NOBELIUM Group

## Data Sources

- O365 Add service principal.

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_multiple_service_principals_created/o365_multiple_service_principals_created.log


---

*Source: [Splunk Security Content](detections/cloud/o365_multiple_service_principals_created_by_sp.yml)*
