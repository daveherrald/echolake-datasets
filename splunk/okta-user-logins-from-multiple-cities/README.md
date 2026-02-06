# Okta User Logins from Multiple Cities

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies instances where the same Okta user logs in from different cities within a 24-hour period. This detection leverages Okta Identity Management logs, analyzing login events and their geographic locations. Such behavior is significant as it may indicate a compromised account, with an attacker attempting unauthorized access from multiple locations. If confirmed malicious, this activity could lead to account takeovers and data breaches, allowing attackers to access sensitive information and potentially escalate their privileges within the environment.

## MITRE ATT&CK

- T1586.003

## Analytic Stories

- Okta Account Takeover

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1586.003/okta_multiple_city/okta_multiple_city_im2.log


---

*Source: [Splunk Security Content](detections/application/okta_user_logins_from_multiple_cities.yml)*
