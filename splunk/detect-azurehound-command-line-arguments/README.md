# Detect AzureHound Command-Line Arguments

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of the `Invoke-AzureHound` command-line argument, commonly used by the AzureHound tool. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process names and command-line executions. This activity is significant because AzureHound is often used for reconnaissance in Azure environments, potentially exposing sensitive information. If confirmed malicious, this activity could allow an attacker to map out Azure Active Directory structures, aiding in further attacks and privilege escalation.

## MITRE ATT&CK

- T1069.001
- T1069.002
- T1087.001
- T1087.002
- T1482

## Analytic Stories

- Windows Discovery Techniques
- Compromised Windows Host

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/sharphound/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/detect_azurehound_command_line_arguments.yml)*
