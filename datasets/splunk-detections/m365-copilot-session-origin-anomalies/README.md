# M365 Copilot Session Origin Anomalies

**Type:** Anomaly

**Author:** Rod Soto

## Description

Detects M365 Copilot users accessing from multiple geographic locations to identify potential account compromise, credential sharing, or impossible travel patterns. The detection aggregates M365 Copilot Graph API events per user, calculating distinct cities and countries accessed, unique IP addresses, and the observation timeframe to compute a locations-per-day metric that measures geographic mobility. Users accessing Copilot from more than one city (cities_count > 1) are flagged and sorted by country and city diversity, surfacing accounts exhibiting anomalous geographic patterns that suggest compromised credentials being used from distributed locations or simultaneous access from impossible travel distances.

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

*Source: [Splunk Security Content](detections/application/m365_copilot_session_origin_anomalies.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
