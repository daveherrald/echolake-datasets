# M365 Copilot Application Usage Pattern Anomalies

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects M365 Copilot users exhibiting suspicious application usage patterns including multi-location access, abnormally high activity volumes, or access to multiple Copilot applications that may indicate account compromise or automated abuse. The detection aggregates M365 Copilot Graph API events per user, calculating metrics like distinct cities/countries accessed, unique IP addresses, number of different Copilot apps used, and average events per day over the observation period. Users are flagged when they access Copilot from multiple cities (cities_count > 1), generate excessive daily activity (events_per_day > 100), or use more than two different Copilot applications (app_count > 2), which are anomalous patterns suggesting credential compromise or bot-driven abuse.

## MITRE ATT&CK

- T1078

## Analytic Stories

- Suspicious Microsoft 365 Copilot Activities

## Data Sources

- M365 Copilot Graph API

## Sample Data

- **Source:** AuditLogs.SignIns
  **Sourcetype:** o365:graph:api
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/m365_copilot/m365_copilot_access.log


---

*Source: [Splunk Security Content](detections/application/m365_copilot_application_usage_pattern_anomalies.yml)*
