# Okta IDP Lifecycle Modifications

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

This dataset contains sample data for identifying modifications to Okta Identity Provider (IDP) lifecycle events, including creation, activation, deactivation, and deletion of IDP configurations. It uses OktaIm2 logs ingested via the Splunk Add-on for Okta Identity Cloud. Monitoring these events is crucial for maintaining the integrity and security of authentication mechanisms. Unauthorized or anomalous changes could indicate potential security breaches or misconfigurations. If confirmed malicious, attackers could manipulate authentication processes, potentially gaining unauthorized access or disrupting identity management systems.

## MITRE ATT&CK

- T1087.004

## Analytic Stories

- Suspicious Okta Activity

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1556/okta_idp/okta.log


---

*Source: [Splunk Security Content](detections/application/okta_idp_lifecycle_modifications.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
