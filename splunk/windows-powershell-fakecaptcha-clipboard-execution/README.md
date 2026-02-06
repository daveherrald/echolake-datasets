# Windows PowerShell FakeCAPTCHA Clipboard Execution

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This detection identifies potential FakeCAPTCHA/ClickFix clipboard hijacking campaigns by looking for PowerShell execution with hidden window parameters and distinctive strings related to fake CAPTCHA verification. These campaigns use social engineering to trick users into pasting malicious PowerShell commands from their clipboard, typically delivering information stealers or remote access trojans.


## MITRE ATT&CK

- T1059.001
- T1204.001
- T1059.003

## Analytic Stories

- Scattered Lapsus$ Hunters
- Fake CAPTCHA Campaigns
- Cisco Network Visibility Module Analytics
- Interlock Ransomware
- NetSupport RMM Tool Abuse

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2
- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/atomic_red_team/captcha_windows-sysmon.log

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_powershell_fakecaptcha_clipboard_execution.yml)*
