# Crowdstrike High Identity Risk Severity

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting CrowdStrike alerts for High Identity Risk Severity with a risk score of 70 or higher. These alerts indicate significant vulnerabilities in user identities, such as suspicious behavior or compromised credentials. Promptly investigating and addressing these alerts is crucial to prevent potential security breaches and ensure the integrity and protection of sensitive information and systems.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** crowdstrike:identities
  **Sourcetype:** crowdstrike:identities
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/high_risk_score/crowdstrike_high_riskscore_cleaned.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_high_identity_risk_severity.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
