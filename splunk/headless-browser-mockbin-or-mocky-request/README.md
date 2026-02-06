# Headless Browser Mockbin or Mocky Request

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects headless browser activity accessing mockbin.org or mocky.io. It identifies processes with the "--headless" and "--disable-gpu" command line arguments, along with references to mockbin.org or mocky.io. This behavior is significant as headless browsers are often used for automated tasks, including malicious activities like web scraping or automated attacks. If confirmed malicious, this activity could indicate an attempt to bypass traditional browser security measures, potentially leading to data exfiltration or further exploitation of web applications.

## MITRE ATT&CK

- T1564.003

## Analytic Stories

- Forest Blizzard
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/headlessbrowser/headless_mockbin.log


---

*Source: [Splunk Security Content](detections/endpoint/headless_browser_mockbin_or_mocky_request.yml)*
