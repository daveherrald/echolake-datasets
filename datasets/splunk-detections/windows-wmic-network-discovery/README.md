# Windows Wmic Network Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting the execution of Windows Management Instrumentation Command-line (WMIC) commands used for network interface discovery on a Windows system. Specifically, it identifies commands such as “wmic nic” that retrieve detailed information about the network adapters installed on the device. While these commands are commonly used by IT administrators for legitimate network inventory and diagnostics, they can also be leveraged by malicious actors for reconnaissance, enabling them to map network configurations and identify potential targets. Monitoring WMIC network interface queries allows security teams to detect suspicious or unauthorized enumeration activities, supporting early threat identification and response.ß

## MITRE ATT&CK

- T1082

## Analytic Stories

- LAMEHUG

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/lamehug/T1082/wmic_cmd/wmic_cmd.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_wmic_network_discovery.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
