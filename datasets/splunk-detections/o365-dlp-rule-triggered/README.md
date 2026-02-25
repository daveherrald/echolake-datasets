# O365 DLP Rule Triggered

**Type:** Anomaly

**Author:** Steven Dick

## Description

This dataset contains sample data for detecting when Microsoft Office 365 Data Loss Prevention (DLP) rules have been triggered. DLP rules can be configured for any number of security, regulatory, or business compliance reasons, as such this analytic will only be as accurate as the upstream DLP configuration. Detections from this analytic should be evaluated thoroughly to de termine what, if any, security relevance the underlying DLP events contain.

## MITRE ATT&CK

- T1048
- T1567

## Analytic Stories

- Data Exfiltration

## Data Sources

- Office 365 Universal Audit Log

## Sample Data

- **Source:** o365
  **Sourcetype:** o365:management:activity
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566/o365_various_alerts/o365_various_alerts.log


---

*Source: [Splunk Security Content](detections/cloud/o365_dlp_rule_triggered.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
