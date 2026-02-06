# Windows Curl Upload to Remote Destination

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of Windows Curl.exe to upload a file to a remote destination. It identifies command-line arguments such as `-T`, `--upload-file`, `-d`, `--data`, and `-F` in process execution logs. This activity is significant because adversaries may use Curl to exfiltrate data or upload malicious payloads. If confirmed malicious, this could lead to data breaches or further compromise of the system. Analysts should review parallel processes and network logs to determine if the upload was successful and isolate the endpoint if necessary.

## MITRE ATT&CK

- T1105

## Analytic Stories

- Cisco Network Visibility Module Analytics
- Compromised Windows Host
- Ingress Tool Transfer
- Microsoft WSUS CVE-2025-59287
- NPM Supply Chain Compromise
- PromptLock

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon_curl_upload.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_curl_upload_to_remote_destination.yml)*
