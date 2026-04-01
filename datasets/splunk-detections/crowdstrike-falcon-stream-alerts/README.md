# CrowdStrike Falcon Stream Alerts

**Type:** Anomaly

**Author:** Bryan Pluta, Teoderick Contreras, Splunk

## Description

This dataset contains sample data for leveraging alerts from CrowdStrike Falcon Event Stream. This query aggregates and summarizes DetectionSummaryEvent and IdpDetectionSummaryEvent alerts from CrowdStrike Falcon Event Stream, providing details such as destination, user, severity, MITRE information, and Crowdstrike id and links. The evals in the search do multiple things to include align the severity, ensure the user, dest, title, description, MITRE fields are set properly, and the drilldowns are defined based on the type of alert. The search is highly dynamic to account for different alert types in which some fields may or may not be populated. Having all these fields properly set ensure the appropriate risk and analyst queue fields are correctly populated.

## Analytic Stories

- Critical Alerts

## Data Sources

- CrowdStrike Falcon Stream Alert

## Sample Data

- **Source:** CrowdStrike:Event:Streams
  **Sourcetype:** CrowdStrike:Event:Streams:JSON
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/crowdstrike_stream/event_stream_events/stream_events.log


---

*Source: [Splunk Security Content](detections/endpoint/crowdstrike_falcon_stream_alerts.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
