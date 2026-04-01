# Windows SQL Server Configuration Option Hunt

**Type:** Hunting

**Author:** Michael Haag, Splunk, sidoyle from Splunk Community

## Description

This detection helps hunt for changes to SQL Server configuration options that could indicate malicious activity. It monitors for modifications to any SQL Server configuration settings, allowing analysts to identify potentially suspicious changes that may be part of an attack, such as enabling dangerous features or modifying security-relevant settings.

## MITRE ATT&CK

- T1505.001

## Analytic Stories

- SQL Server Abuse

## Data Sources

- Windows Event Log Application 15457

## Sample Data

- **Source:** XmlWinEventLog:Application
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.001/simulation/windows-application.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sql_server_configuration_option_hunt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
