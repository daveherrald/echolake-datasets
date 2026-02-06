# Microsoft Defender Incident Alerts

**Type:** TTP

**Author:** Bryan Pluta, Bhavin Patel, Splunk, lyonheart14, Github Community

## Description

The following analytic is to leverage alerts from Microsoft Defender O365 Incidents. This query aggregates and summarizes all alerts from Microsoft Defender O365 Incidents, providing details such as the destination, file name, severity, process command line, ip address, registry key, signature, description, unique id, and timestamps. This detection is not intended to detect new activity from raw data, but leverages Microsoft provided alerts to be correlated with other data as part of risk based alerting. The data contained in the alert is mapped not only to the risk obejct, but also the threat object. This detection filters out evidence that has a verdict of clean from Microsoft. It dynamically maps the MITRE technique at search time to auto populate the annotation field with the value provided in the alert. It also uses a static mapping to set the risk score based on the severity of the alert.

## Analytic Stories

- Critical Alerts

## Data Sources

- MS365 Defender Incident Alerts

## Sample Data

- **Source:** m365_defender_incident_alerts
  **Sourcetype:** ms365:defender:incident:alerts
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/suspicious_behaviour/alerts/defender_incident_alerts_single_event.log


---

*Source: [Splunk Security Content](detections/endpoint/microsoft_defender_incident_alerts.yml)*
