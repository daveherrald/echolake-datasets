# Okta Successful Single Factor Authentication

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying successful single-factor authentication events against the Okta Dashboard for accounts without Multi-Factor Authentication (MFA) enabled. It detects this activity by analyzing Okta logs for successful authentication events where "Okta Verify" is not used. This behavior is significant as it may indicate a misconfiguration, policy violation, or potential account takeover. If confirmed malicious, an attacker could gain unauthorized access to the account, potentially leading to data breaches or further exploitation within the environment.

## MITRE ATT&CK

- T1078.004
- T1586.003
- T1621

## Analytic Stories

- Okta Account Takeover

## Data Sources

- Okta

## Sample Data

- **Source:** okta_log
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078.004/okta_single_factor_auth/okta_single_factor_auth.log


---

*Source: [Splunk Security Content](detections/application/okta_successful_single_factor_authentication.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
