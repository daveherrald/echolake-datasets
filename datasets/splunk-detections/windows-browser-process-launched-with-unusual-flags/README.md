# Windows Browser Process Launched with Unusual Flags

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the use of unusual browser flags, specifically --mute-audio and --do-not-elevate, which deviate from standard browser launch behavior. These flags may indicate automated scripts, testing environments, or attempts to modify browser functionality for silent operation or restricted privilege execution. Detection focuses on non-standard launch parameters, unexpected process behavior, or deviations from baseline configurations. Monitoring such flag usage helps identify potentially suspicious activity, misconfigurations, or policy violations, enabling security teams to investigate anomalies, ensure system compliance, and differentiate legitimate administrative or testing uses from unusual or unauthorized operations.

## MITRE ATT&CK

- T1185

## Analytic Stories

- Castle RAT

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/browser_unusual_flag/castle_chrome_shell32.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_browser_process_launched_with_unusual_flags.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
