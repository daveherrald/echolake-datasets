# Suspicious IcedID Rundll32 Cmdline

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting a suspicious `rundll32.exe` command line used to execute a DLL file, a technique associated with IcedID malware. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions containing the pattern `*/i:*`. This activity is significant as it indicates potential malware attempting to load an encrypted DLL payload, often named `license.dat`. If confirmed malicious, this could allow attackers to execute arbitrary code, leading to further system compromise and potential data exfiltration.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- IcedID
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_icedid_rundll32_cmdline.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
