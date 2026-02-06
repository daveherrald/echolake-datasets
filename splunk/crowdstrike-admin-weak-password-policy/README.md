# Crowdstrike Admin Weak Password Policy

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects CrowdStrike alerts for admin weak password policy violations, identifying instances where administrative passwords do not meet security standards. These alerts highlight significant vulnerabilities that could be exploited by attackers to gain unauthorized access. Promptly addressing these alerts is crucial for maintaining robust security and protecting critical systems and data from potential threats.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** crowdstrike:identities
  **Sourcetype:** crowdstrike:identities
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/admin_weak_password_policy/crowdstrike_weak_password_admin_cleaned.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_admin_weak_password_policy.yml)*
