# PowerShell Invoke WmiExec Usage

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the execution of the Invoke-WMIExec utility within PowerShell Script Block Logging (EventCode 4104). This detection leverages PowerShell script block logs to identify instances where the Invoke-WMIExec command is used. Monitoring this activity is crucial as it indicates potential lateral movement using WMI commands with NTLMv2 pass-the-hash authentication. If confirmed malicious, this activity could allow an attacker to execute commands remotely on target systems, potentially leading to further compromise and lateral spread within the network.

## MITRE ATT&CK

- T1047

## Analytic Stories

- Scattered Lapsus$ Hunters
- Suspicious WMI Use

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1047/atomic_red_team/invokewmiexec_windows-powershell.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_invoke_wmiexec_usage.yml)*
