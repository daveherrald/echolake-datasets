# Windows InstallUtil Remote Network Connection

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the Windows InstallUtil.exe binary making a remote network connection. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process and network telemetry. This activity is significant because InstallUtil.exe can be exploited to download and execute malicious code, bypassing application control mechanisms. If confirmed malicious, an attacker could achieve code execution, potentially leading to further system compromise, data exfiltration, or lateral movement within the network. Analysts should review the parent process, network connections, and any associated file modifications to determine the legitimacy of this activity.

## MITRE ATT&CK

- T1218.004

## Analytic Stories

- Living Off The Land
- Compromised Windows Host
- Signed Binary Proxy Execution InstallUtil
- Cisco Network Visibility Module Analytics

## Data Sources

- Sysmon EventID 1 AND Sysmon EventID 3
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_installutil_remote_network_connection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
