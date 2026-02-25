# Windows Process Injection Of Wermgr to Known Browser

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the suspicious remote thread execution of the wermgr.exe process into known browsers such as firefox.exe, chrome.exe, and others. It leverages Sysmon EventCode 8 logs to detect this behavior by monitoring SourceImage and TargetImage fields. This activity is significant because it is indicative of Qakbot malware, which injects malicious code into legitimate processes to steal information. If confirmed malicious, this activity could allow attackers to execute arbitrary code, escalate privileges, and exfiltrate sensitive data from the compromised host.

## MITRE ATT&CK

- T1055.001

## Analytic Stories

- Qakbot

## Data Sources

- Sysmon EventID 8

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/qakbot/remote_thread/sysmon_wermgr_remote.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_process_injection_of_wermgr_to_known_browser.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
