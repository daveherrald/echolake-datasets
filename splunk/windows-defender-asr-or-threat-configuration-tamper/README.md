# Windows Defender ASR or Threat Configuration Tamper

**Type:** TTP

**Author:** Nasreddine Bencherchali, Splunk

## Description

The following analytic detects the use of commands to disable Attack Surface Reduction (ASR) rules or change threat default actions in Windows Defender.
It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions involving "Add-MpPreference" or "Set-MpPreference".
This activity is significant because adversaries often use it to bypass Windows Defender, allowing malicious code to execute undetected.
If confirmed malicious, this behavior could enable attackers to evade antivirus detection, maintain persistence, and execute further malicious activities without interference from Windows Defender.


## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable_defender_asr_or_threats/disable_defender_asr_or_threats.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_defender_asr_or_threat_configuration_tamper.yml)*
