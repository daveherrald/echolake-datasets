# Crowdstrike Medium Severity Alert

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a CrowdStrike alert with MEDIUM severity indicates a potential threat that requires prompt attention. This alert level suggests suspicious activity that may compromise security but is not immediately critical. It typically involves detectable but non-imminent risks, such as unusual behavior or attempted policy violations, which should be investigated further and mitigated quickly to prevent escalation of attacks.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** CrowdStrike:Event:Streams
  **Sourcetype:** CrowdStrike:Event:Streams:JSON
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/medium_alert/crowdstrike_medium_clean.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_medium_severity_alert.yml)*
