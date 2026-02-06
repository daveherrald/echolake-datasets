# Bcdedit Command Back To Normal Mode Boot

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of a suspicious `bcdedit` command that reconfigures a host from safe mode back to normal boot. This detection leverages Endpoint Detection and Response (EDR) data, focusing on command-line executions involving `bcdedit.exe` with specific parameters. This activity is significant as it may indicate the presence of ransomware, such as BlackMatter, which manipulates boot configurations to facilitate encryption processes. If confirmed malicious, this behavior could allow attackers to maintain control over the boot process, potentially leading to further system compromise and data encryption.

## MITRE ATT&CK

- T1490

## Analytic Stories

- Black Basta Ransomware
- BlackMatter Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1552.002/autoadminlogon/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/bcdedit_command_back_to_normal_mode_boot.yml)*
