# O365 Excessive Authentication Failures Alert

**Type:** Anomaly

**Author:** Rod Soto, Splunk

## Description

The following analytic identifies an excessive number of authentication failures, including failed attempts against MFA prompt codes. It uses data from the `o365_management_activity` dataset, focusing on events where the authentication status is marked as failure. This behavior is significant as it may indicate a brute force attack or an attempt to compromise user accounts. If confirmed malicious, this activity could lead to unauthorized access, data breaches, or further exploitation within the environment.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Office 365 Account Takeover

## Data Sources


## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110/o365_brute_force_login/o365_brute_force_login.json


---

*Source: [Splunk Security Content](detections/cloud/o365_excessive_authentication_failures_alert.yml)*
