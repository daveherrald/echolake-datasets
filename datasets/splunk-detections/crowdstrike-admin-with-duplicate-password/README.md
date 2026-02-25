# Crowdstrike Admin With Duplicate Password

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting CrowdStrike alerts for admin accounts with duplicate password risk, identifying instances where administrative users share the same password. This practice significantly increases the risk of unauthorized access and potential breaches. Addressing these alerts promptly is crucial for maintaining strong security protocols, ensuring each admin account uses a unique, secure password to protect critical systems and data.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** crowdstrike:identities
  **Sourcetype:** crowdstrike:identities
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/admin_duplicate_password/crowdstrike_admin_dup_pwd_cleaned.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_admin_with_duplicate_password.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
