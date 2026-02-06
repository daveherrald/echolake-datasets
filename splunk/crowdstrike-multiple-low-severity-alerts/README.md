# Crowdstrike Multiple LOW Severity Alerts

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects multiple CrowdStrike LOW severity alerts, indicating a series of minor suspicious activities or policy violations. These alerts are not immediately critical but should be reviewed to prevent potential threats. They often highlight unusual behavior or low-level risks that, if left unchecked, could escalate into more significant security issues. Regular monitoring and analysis of these alerts are essential for maintaining robust security.

## MITRE ATT&CK

- T1110

## Analytic Stories

- Compromised Windows Host

## Data Sources


## Sample Data

- **Source:** CrowdStrike:Event:Streams
  **Sourcetype:** CrowdStrike:Event:Streams:JSON
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/multiple_low_alert/crowdstrike_multiple_low_cleaned.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_multiple_low_severity_alerts.yml)*
