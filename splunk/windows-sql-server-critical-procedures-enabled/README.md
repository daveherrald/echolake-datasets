# Windows SQL Server Critical Procedures Enabled

**Type:** TTP

**Author:** Michael Haag, Splunk, sidoyle from Splunk Community

## Description

This detection identifies when critical SQL Server configuration options are modified, including "Ad Hoc Distributed Queries", "external scripts enabled", "Ole Automation Procedures", "clr enabled", and "clr strict security". These features can be abused by attackers for various malicious purposes - Ad Hoc Distributed Queries enables Active Directory reconnaissance through ADSI provider, external scripts and Ole Automation allow execution of arbitrary code, and CLR features can be used to run custom assemblies. Enabling these features could indicate attempts to gain code execution or perform reconnaissance through SQL Server.

## MITRE ATT&CK

- T1505.001

## Analytic Stories

- SQL Server Abuse

## Data Sources

- Windows Event Log Application 15457

## Sample Data

- **Source:** XmlWinEventLog:Application
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.001/simulation/adhocdq_windows_application.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_sql_server_critical_procedures_enabled.yml)*
