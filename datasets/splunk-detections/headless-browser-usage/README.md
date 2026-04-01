# Headless Browser Usage

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the usage of headless browsers within an organization. It identifies processes containing the "--headless" and "--disable-gpu" command line arguments, which are indicative of headless browsing. This detection leverages data from the Endpoint.Processes datamodel to identify such processes. Monitoring headless browser usage is significant as these tools can be exploited by adversaries for malicious activities like web scraping, automated testing, and undetected web interactions. If confirmed malicious, this activity could lead to unauthorized data extraction, automated attacks, or other covert operations on web applications.

## MITRE ATT&CK

- T1564.003

## Analytic Stories

- Forest Blizzard

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/headlessbrowser/headless_mockbin.log


---

*Source: [Splunk Security Content](detections/endpoint/headless_browser_usage.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
