# Windows PowerShell Invoke-RestMethod IP Information Collection

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of PowerShell's Invoke-RestMethod cmdlet to collect geolocation data from ipinfo.io or IP address information from api.ipify.org. This behavior leverages PowerShell Script Block Logging to identify scripts that gather external IP information and potential geolocation data. This activity is significant as it may indicate reconnaissance efforts, where threat actors are attempting to determine the geographical location or network details of a compromised system. While some legitimate software may use these services, this pattern is commonly observed in malware and post-exploitation toolkits like those used by Water Gamayun threat actors.

## MITRE ATT&CK

- T1082
- T1016
- T1059.001

## Analytic Stories

- Water Gamayun

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/irm_powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_invoke_restmethod_ip_information_collection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
