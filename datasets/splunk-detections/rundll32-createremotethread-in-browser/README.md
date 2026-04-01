# Rundll32 CreateRemoteThread In Browser

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the suspicious creation of a remote thread by rundll32.exe targeting browser processes such as firefox.exe, chrome.exe, iexplore.exe, and microsoftedgecp.exe. This detection leverages Sysmon EventCode 8, focusing on SourceImage and TargetImage fields to identify the behavior. This activity is significant as it is commonly associated with malware like IcedID, which hooks browsers to steal sensitive information such as banking details. If confirmed malicious, this could allow attackers to intercept and exfiltrate sensitive user data, leading to potential financial loss and privacy breaches.

## MITRE ATT&CK

- T1055

## Analytic Stories

- IcedID
- Living Off The Land

## Data Sources

- Sysmon EventID 8

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/rundll32_createremotethread_in_browser.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
