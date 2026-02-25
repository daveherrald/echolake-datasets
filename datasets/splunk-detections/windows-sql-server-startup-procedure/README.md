# Windows SQL Server Startup Procedure

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This detection identifies when a startup procedure is registered or executed in SQL Server. Startup procedures automatically execute when SQL Server starts, making them an attractive persistence mechanism for attackers. The detection monitors for suspicious stored procedure names and patterns that may indicate malicious activity, such as attempts to execute operating system commands or gain elevated privileges.

## MITRE ATT&CK

- T1505.001

## Analytic Stories

- SQL Server Abuse
- Hellcat Ransomware

## Data Sources

- Windows Event Log Application 17135

## Sample Data

- **Source:** XmlWinEventLog:Application
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.001/simulation/sql_startupprocedure_widows-application.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sql_server_startup_procedure.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
