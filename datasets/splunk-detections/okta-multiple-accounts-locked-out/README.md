# Okta Multiple Accounts Locked Out

**Type:** Anomaly

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting multiple Okta accounts being locked out within a short period. It uses the user.account.lock event from Okta logs, aggregated over a 5-minute window, to identify this behavior. This activity is significant as it may indicate a brute force or password spraying attack, where an adversary attempts to guess passwords, leading to account lockouts. If confirmed malicious, this could result in potential account takeovers or unauthorized access to sensitive Okta accounts, posing a significant security risk.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Okta Account Takeover

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110/okta_multiple_accounts_lockout/okta_multiple_accounts_lockout.log


---

*Source: [Splunk Security Content](detections/application/okta_multiple_accounts_locked_out.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
