# O365 DLP Rule Triggered

**Type:** Anomaly

**Author:** Steven Dick

## Description

The following analytic detects when Microsoft Office 365 Data Loss Prevention (DLP) rules have been triggered. DLP rules can be configured for any number of security, regulatory, or business compliance reasons, as such this analytic will only be as accurate as the upstream DLP configuration. Detections from this analytic should be evaluated thoroughly to de termine what, if any, security relevance the underlying DLP events contain.

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
