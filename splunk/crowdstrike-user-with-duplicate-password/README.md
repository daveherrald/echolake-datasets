# Crowdstrike User with Duplicate Password

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects CrowdStrike alerts for non-admin accounts with duplicate password risk, identifying instances where multiple non-admin users share the same password. This practice weakens security and increases the potential for unauthorized access. Addressing these alerts is essential to ensure each user account has a unique, strong password, thereby enhancing overall security and protecting sensitive information.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** crowdstrike:identities
  **Sourcetype:** crowdstrike:identities
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/user_duplicate_password/crowdstrike_user_dup_pwd_cleaned.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_user_with_duplicate_password.yml)*
