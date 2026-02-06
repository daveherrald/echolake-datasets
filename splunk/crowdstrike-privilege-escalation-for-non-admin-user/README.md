# Crowdstrike Privilege Escalation For Non-Admin User

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects CrowdStrike alerts for privilege escalation attempts by non-admin users. These alerts indicate unauthorized efforts by regular users to gain elevated permissions, posing a significant security risk. Detecting and addressing these attempts promptly helps prevent potential breaches and ensures that user privileges remain properly managed, maintaining the integrity of the organization's security protocols.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** CrowdStrike:Event:Streams
  **Sourcetype:** CrowdStrike:Event:Streams:JSON
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/privilege_escalation/crowdstrike_priv_esc_cleaned.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_privilege_escalation_for_non_admin_user.yml)*
