# Okta Suspicious Activity Reported

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies when an associate reports a login attempt as suspicious via an email from Okta. It leverages Okta Identity Management logs, specifically the `user.account.report_suspicious_activity_by_enduser` event type. This activity is significant as it indicates potential unauthorized access attempts, warranting immediate investigation to prevent possible security breaches. If confirmed malicious, the attacker could gain unauthorized access to sensitive systems and data, leading to data theft, privilege escalation, or further compromise of the environment.

## MITRE ATT&CK

- T1078.001

## Analytic Stories

- Okta Account Takeover

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1078/okta_suspicious_activity_reported_by_user/okta_suspicious_activity_reported_by_user.log


---

*Source: [Splunk Security Content](detections/application/okta_suspicious_activity_reported.yml)*
