# Windows Office Product Dropped Cab or Inf File

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects Office products writing .cab or .inf files, indicative of CVE-2021-40444 exploitation. It leverages the Endpoint.Processes and Endpoint.Filesystem data models to identify Office applications creating these file types. This activity is significant as it may signal an attempt to load malicious ActiveX controls and download remote payloads, a known attack vector. If confirmed malicious, this could lead to remote code execution, allowing attackers to gain control over the affected system and potentially compromise sensitive data.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- Microsoft MSHTML Remote Code Execution CVE-2021-40444
- Compromised Windows Host
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 11
- Windows Event Log Security 4688 AND Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_cabinf.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_dropped_cab_or_inf_file.yml)*
