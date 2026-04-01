# Windows InstallUtil in Non Standard Path

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the execution of InstallUtil.exe from non-standard paths. It leverages Endpoint Detection and Response (EDR) data, focusing on process names and original file names outside typical directories. This activity is significant because InstallUtil.exe is often used by attackers to execute malicious code or scripts. If confirmed malicious, this behavior could allow an attacker to bypass security controls, execute arbitrary code, and potentially gain unauthorized access or persist within the environment.

## MITRE ATT&CK

- T1036.003
- T1218.004

## Analytic Stories

- Masquerading - Rename System Utilities
- Ransomware
- Unusual Processes
- Signed Binary Proxy Execution InstallUtil
- Living Off The Land
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

*Source: [Splunk Security Content](detections/endpoint/windows_installutil_in_non_standard_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
