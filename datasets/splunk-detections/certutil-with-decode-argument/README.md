# CertUtil With Decode Argument

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting the use of CertUtil.exe with the 'decode' argument, which may indicate an attempt to decode a previously encoded file, potentially containing malicious payloads. This detection leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving CertUtil.exe. This activity is significant because attackers often use CertUtil to decode malicious files downloaded from the internet, which are then executed to compromise the system. If confirmed malicious, this activity could lead to unauthorized code execution, further system compromise, and potential data exfiltration.

## MITRE ATT&CK

- T1140

## Analytic Stories

- Deobfuscate-Decode Files or Information
- Living Off The Land
- Forest Blizzard
- APT29 Diplomatic Deceptions with WINELOADER
- Storm-2460 CLFS Zero Day Exploitation
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1140/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/certutil_with_decode_argument.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
