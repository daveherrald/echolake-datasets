# Windows Office Product Loaded MSHTML Module

**Type:** Anomaly

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting the loading of the mshtml.dll module into an Office product, which is indicative of CVE-2021-40444 exploitation. It leverages Sysmon EventID 7 to monitor image loads by specific Office processes. This activity is significant because it can indicate an attempt to exploit a vulnerability in the MSHTML component via a malicious document. If confirmed malicious, this could allow an attacker to execute arbitrary code, potentially leading to system compromise, data exfiltration, or further network penetration.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Spearphishing Attachments
- Microsoft MSHTML Remote Code Execution CVE-2021-40444
- CVE-2023-36884 Office and Windows HTML RCE Vulnerability

## Data Sources

- Sysmon EventID 7

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/windows-sysmon_mshtml.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_office_product_loaded_mshtml_module.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
