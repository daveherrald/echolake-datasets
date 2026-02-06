# Windows Curl Download to Suspicious Path

**Type:** TTP

**Author:** Michael Haag, Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the use of Windows Curl.exe to download
a file to a suspicious location, such as AppData, ProgramData, or Public directories.
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on
command-line executions that include the -O or --output options. This activity is
significant because downloading files to these locations can indicate an attempt
to bypass security controls or establish persistence. If confirmed malicious, this
behavior could lead to unauthorized code execution, data exfiltration, or further
compromise of the system.


## MITRE ATT&CK

- T1105

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- Black Basta Ransomware
- China-Nexus Threat Activity
- Cisco Network Visibility Module Analytics
- Compromised Windows Host
- Forest Blizzard
- GhostRedirector IIS Module and Rungan Backdoor
- IcedID
- Ingress Tool Transfer
- NPM Supply Chain Compromise
- Salt Typhoon

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1105/atomic_red_team/windows-sysmon_curl.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_curl_download_to_suspicious_path.yml)*
