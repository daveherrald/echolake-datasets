# Shai-Hulud 2 Exfiltration Artifact Files

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

Detects creation of exfiltration artifact files associated with Shai-Hulud 2.0 npm supply
chain malware. The malware creates cloud.json, contents.json, environment.json, truffleSecrets.json,
and actionsSecrets.json files containing harvested credentials from AWS, Azure, GCP, GitHub secrets,
and environment variables. These files are staged before being pushed to attacker-controlled repositories.


## MITRE ATT&CK

- T1074.001
- T1552.001
- T1195.002

## Analytic Stories

- NPM Supply Chain Compromise

## Data Sources

- Sysmon for Linux EventID 11
- Sysmon EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/npm/shai_hulud_workflow_sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/npm/windows_workflow_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/shai_hulud_2_exfiltration_artifact_files.yml)*
