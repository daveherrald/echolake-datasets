# Crowdstrike User Weak Password Policy

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects CrowdStrike alerts for weak password policy violations, identifying instances where passwords do not meet the required security standards. These alerts highlight potential vulnerabilities that could be exploited by attackers, emphasizing the need for stronger password practices. Addressing these alerts promptly helps to enhance overall security and protect sensitive information from unauthorized access.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** crowdstrike:identities
  **Sourcetype:** crowdstrike:identities
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/non_adminweak_password_policy/crowdstrike_user_weak_password_cleaned.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_user_weak_password_policy.yml)*
