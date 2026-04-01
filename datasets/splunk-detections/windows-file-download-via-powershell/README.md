# Windows File Download Via PowerShell

**Type:** Anomaly

**Author:** Michael Haag, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for detecting the use of PowerShell's download methods such as
"DownloadString" and "DownloadData" from the WebClient class or Invoke-WebRequest
and it's aliases "IWR" or "Curl".
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on
process execution logs that include command-line details.
This activity can be significant such methods and functions are commonly used in malicious
PowerShell scripts to fetch and execute remote code.
If confirmed malicious, this behavior could allow an attacker to download and run
arbitrary code, potentially leading to unauthorized access, data exfiltration,
or further compromise of the affected system.


## MITRE ATT&CK

- T1059.001
- T1105

## Analytic Stories

- APT37 Rustonotto and FadeStealer
- Cisco Network Visibility Module Analytics
- Data Destruction
- GhostRedirector IIS Module and Rungan Backdoor
- HAFNIUM Group
- Hermetic Wiper
- IcedID
- Ingress Tool Transfer
- Malicious PowerShell
- Microsoft WSUS CVE-2025-59287
- NetSupport RMM Tool Abuse
- NPM Supply Chain Compromise
- Phemedrone Stealer
- PHP-CGI RCE Attack on Japanese Organizations
- SysAid On-Prem Software CVE-2023-47246 Vulnerability
- Winter Vivern
- XWorm
- Tuoni
- StealC Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_file_download_via_powershell.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
