# Windows System Binary Proxy Execution Compiled HTML File Decompile

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of the decompile parameter with the HTML Help application (HH.exe). This behavior is identified through Endpoint Detection and Response (EDR) telemetry, focusing on command-line executions involving the decompile parameter. This activity is significant because it is an uncommon command and has been associated with APT41 campaigns, where it was used to unpack HTML help files for further malicious actions. If confirmed malicious, this technique could allow attackers to execute arbitrary commands, potentially leading to further compromise and persistence within the environment.

## MITRE ATT&CK

- T1218.001

## Analytic Stories

- Suspicious Compiled HTML Activity
- Living Off The Land
- Compromised Windows Host
- APT37 Rustonotto and FadeStealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.001/atomic_red_team/hh_decom_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_system_binary_proxy_execution_compiled_html_file_decompile.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
