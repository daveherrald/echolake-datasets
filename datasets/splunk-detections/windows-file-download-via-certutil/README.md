# Windows File Download Via CertUtil

**Type:** TTP

**Author:** Nasreddine Bencherchali, Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of `certutil.exe` to download files using the `-URL`, `-urlcache` or '-verifyctl' arguments. This behavior is identified by monitoring command-line executions for these specific arguments via Endpoint Detection and Response (EDR) telemetry. This activity is significant because `certutil.exe` is a legitimate tool often abused by attackers to download and execute malicious payloads. If confirmed malicious, this could allow an attacker to download and execute arbitrary files, potentially leading to code execution, data exfiltration, or further compromise of the system.

## MITRE ATT&CK

- T1105

## Analytic Stories

- Living Off The Land
- Ingress Tool Transfer
- ProxyNotShell
- DarkSide Ransomware
- Forest Blizzard
- Flax Typhoon
- Compromised Windows Host
- CISA AA22-277A
- Cisco Network Visibility Module Analytics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_file_download_via_certutil.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
