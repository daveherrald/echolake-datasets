# Windows Impair Defenses Disable Auto Logger Session

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the disabling of an AutoLogger session or one of its providers, by identifying changes to the Registry values "Start" and "Enabled" part of the "\WMI\Autologger\" key path. It leverages data from the Endpoint.Registry datamodel to monitor specific registry paths and values. This activity is significant as attackers and adversaries can leverage this in order to evade defense and blind EDRs and log ingest tooling. If confirmed malicious, this action could allow an attacker to conceal their activities, making it harder to detect further malicious actions and maintain persistence on the compromised endpoint.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable_defender_logging/sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defenses_disable_auto_logger_session.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
