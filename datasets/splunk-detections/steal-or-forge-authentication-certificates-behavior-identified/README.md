# Steal or Forge Authentication Certificates Behavior Identified

**Type:** Correlation

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying potential threats related to the theft or forgery of authentication certificates. It detects when five or more analytics from the Windows Certificate Services story trigger within a specified timeframe. This detection leverages aggregated risk scores and event counts from the Risk data model. This activity is significant as it may indicate an ongoing attack aimed at compromising authentication mechanisms. If confirmed malicious, attackers could gain unauthorized access to sensitive systems and data, potentially leading to severe security breaches.

## MITRE ATT&CK

- T1649

## Analytic Stories

- Windows Certificate Services

## Data Sources


## Sample Data

- **Source:** certs
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1649/atomic_red_team/risk_certificate_services.log


---

*Source: [Splunk Security Content](detections/endpoint/steal_or_forge_authentication_certificates_behavior_identified.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
