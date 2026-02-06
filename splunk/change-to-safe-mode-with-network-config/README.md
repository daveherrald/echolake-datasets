# Change To Safe Mode With Network Config

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of a suspicious `bcdedit` command that configures a host to boot in safe mode with network support. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving `bcdedit.exe` with specific parameters. This activity is significant because it is a known technique used by BlackMatter ransomware to force a compromised host into safe mode for continued encryption. If confirmed malicious, this could allow attackers to bypass certain security controls, persist in the environment, and continue their malicious activities.

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

*Source: [Splunk Security Content](detections/endpoint/change_to_safe_mode_with_network_config.yml)*
