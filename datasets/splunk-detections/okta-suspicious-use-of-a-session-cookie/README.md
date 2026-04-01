# Okta Suspicious Use of a Session Cookie

**Type:** Anomaly

**Author:** Scott Dermott, Felicity Robson, Okta, Michael Haag, Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying suspicious use of a session cookie by detecting multiple client values (IP, User Agent, etc.) changing for the same Device Token associated with a specific user. It leverages policy evaluation events from successful authentication logs in Okta. This activity is significant as it may indicate an adversary attempting to reuse a stolen web session cookie, potentially bypassing authentication mechanisms. If confirmed malicious, this could allow unauthorized access to user accounts, leading to data breaches or further exploitation within the environment.

## MITRE ATT&CK

- T1539

## Analytic Stories

- Suspicious Okta Activity
- Okta Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1539/okta_web_session_multiple_ip/okta_web_session_multiple_ip.log


---

*Source: [Splunk Security Content](detections/application/okta_suspicious_use_of_a_session_cookie.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
