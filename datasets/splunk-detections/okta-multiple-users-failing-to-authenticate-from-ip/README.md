# Okta Multiple Users Failing To Authenticate From Ip

**Type:** Anomaly

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for identifying instances where more than 10 unique user accounts have failed to authenticate from a single IP address within a 5-minute window in an Okta tenant. This detection uses OktaIm2 logs ingested via the Splunk Add-on for Okta Identity Cloud. Such activity is significant as it may indicate brute-force attacks or password spraying attempts. If confirmed malicious, this behavior suggests an external entity is attempting to compromise multiple user accounts, potentially leading to unauthorized access to organizational resources and data breaches.

## MITRE ATT&CK

- T1110.003

## Analytic Stories

- Okta Account Takeover

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/okta_multiple_users_from_ip/okta_multiple_users_from_ip.log


---

*Source: [Splunk Security Content](detections/application/okta_multiple_users_failing_to_authenticate_from_ip.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
