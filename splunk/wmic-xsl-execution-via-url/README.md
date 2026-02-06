# WMIC XSL Execution via URL

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects `wmic.exe` loading a remote XSL script
via a URL. This detection leverages Endpoint Detection and Response (EDR) data,
focusing on command-line executions that include HTTP/HTTPS URLs and the /FORMAT
switch. This activity is significant as it indicates a potential application control
bypass, allowing adversaries to execute JScript or VBScript within an XSL file.
If confirmed malicious, this technique can enable attackers to execute arbitrary
code, escalate privileges, or maintain persistence using a trusted Windows tool,
posing a severe threat to the environment.


## MITRE ATT&CK

- T1220

## Analytic Stories

- Compromised Windows Host
- Suspicious WMI Use
- Cisco Network Visibility Module Analytics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1220/atomic_red_team/windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/wmic_xsl_execution_via_url.yml)*
