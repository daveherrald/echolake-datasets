# Powershell Disable Security Monitoring

**Type:** TTP

**Author:** Michael Haag, Nasreddine Bencherchali, Splunk

## Description

This dataset contains sample data for identifying attempts to disable Windows Defender
real-time behavior monitoring via PowerShell commands. It detects the use of specific
`Set-MpPreference` parameters that disable various security features. This activity
is significant as it is commonly used by malware such as RATs, bots, or Trojans
to evade detection by disabling antivirus protections. If confirmed malicious, this
action could allow an attacker to operate undetected, leading to potential data
exfiltration, further system compromise, or persistent access within the environment.


## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Ransomware
- Revil Ransomware
- CISA AA24-241A

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/pwh_defender_disabling/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_disable_security_monitoring.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
