# Windows DotNet Binary in Non Standard Path

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of native .NET binaries from non-standard directories within the Windows operating system.
It leverages Endpoint Detection and Response (EDR) telemetry, comparing process names and original file names against a predefined lookup "is_net_windows_file".
This activity is significant because adversaries may move .NET binaries to unconventional paths to evade detection and execute malicious code.
If confirmed malicious, this behavior could allow attackers to execute arbitrary code, escalate privileges, or maintain persistence within the environment, posing a significant security risk.
Also this analytic leverages a sub-search to enhance performance. sub-searches have limitations on the amount of data they can return. Keep this in mind if you have an extensive list of ransomware note file names.


## MITRE ATT&CK

- T1036.003
- T1218.004

## Analytic Stories

- Masquerading - Rename System Utilities
- Ransomware
- Unusual Processes
- Signed Binary Proxy Execution InstallUtil
- Data Destruction
- WhisperGate

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.004/atomic_red_team/windows-sysmon_installutil_path.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_dotnet_binary_in_non_standard_path.yml)*
