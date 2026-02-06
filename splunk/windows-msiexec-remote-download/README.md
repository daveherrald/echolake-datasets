# Windows MSIExec Remote Download

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of msiexec.exe with an HTTP or
HTTPS URL in the command line, indicating a remote file download attempt. This detection
leverages data from Endpoint Detection and Response (EDR) agents, focusing on process
execution logs that include command-line details. This activity is significant as
it may indicate an attempt to download and execute potentially malicious software
from a remote server. If confirmed malicious, this could lead to unauthorized code
execution, system compromise, or further malware deployment within the network.


## MITRE ATT&CK

- T1218.007

## Analytic Stories

- Windows System Binary Proxy Execution MSIExec
- Water Gamayun
- Cisco Network Visibility Module Analytics
- StealC Stealer

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msiexec_remote_download.yml)*
