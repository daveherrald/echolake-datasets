# Okta Multiple Accounts Locked Out

**Type:** Anomaly

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

The following analytic detects multiple Okta accounts being locked out within a short period. It uses the user.account.lock event from Okta logs, aggregated over a 5-minute window, to identify this behavior. This activity is significant as it may indicate a brute force or password spraying attack, where an adversary attempts to guess passwords, leading to account lockouts. If confirmed malicious, this could result in potential account takeovers or unauthorized access to sensitive Okta accounts, posing a significant security risk.

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
