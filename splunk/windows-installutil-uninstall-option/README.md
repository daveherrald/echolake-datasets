# Windows InstallUtil Uninstall Option

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of the Windows InstallUtil.exe binary with the `/u` (uninstall) switch, which can execute code while bypassing application control. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names, parent processes, and command-line executions. This activity is significant because it can indicate an attempt to execute malicious code without administrative privileges. If confirmed malicious, an attacker could achieve code execution, potentially leading to further system compromise or persistence within the environment.

## MITRE ATT&CK

- T1218.004

## Analytic Stories

- Living Off The Land
- Compromised Windows Host
- Signed Binary Proxy Execution InstallUtil

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_installutil_uninstall_option.yml)*
