# Crowdstrike Medium Identity Risk Severity

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects CrowdStrike alerts for Medium Identity Risk Severity with a risk score of 55 or higher. These alerts indicate significant vulnerabilities in user identities, such as suspicious behavior or compromised credentials. Promptly investigating and addressing these alerts is crucial to prevent potential security breaches and ensure the integrity and protection of sensitive information and systems.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** crowdstrike:identities
  **Sourcetype:** crowdstrike:identities
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/riskscore/crowdstrike_riskscore_cleaned.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_medium_identity_risk_severity.yml)*
