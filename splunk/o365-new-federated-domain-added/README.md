# O365 New Federated Domain Added

**Type:** TTP

**Author:** Rod Soto, Mauricio Velazco Splunk

## Description

The following analytic identifies the addition of a new federated domain in an Office 365 environment. This behavior is detected by analyzing Office 365 management activity logs, specifically filtering for Workload=Exchange and Operation="Add-FederatedDomain". The addition of a new federated domain is significant as it may indicate unauthorized changes or potential compromises. If confirmed malicious, attackers could establish a backdoor, bypass security measures, or exfiltrate data, leading to data breaches and unauthorized access to sensitive information. Immediate investigation is required to review the details of the added domain and any concurrent suspicious activities.

## MITRE ATT&CK

- T1136.003

## Analytic Stories

- Office 365 Persistence Mechanisms
- Cloud Federated Credential Abuse

## Data Sources

- O365

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1136.003/o365_new_federated_domain_added/o365_add_federated_domain.log


---

*Source: [Splunk Security Content](detections/cloud/o365_new_federated_domain_added.yml)*
