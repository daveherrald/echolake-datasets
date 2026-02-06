# Windows Execute Arbitrary Commands with MSDT

**Type:** TTP

**Author:** Michael Haag, Teoderick Contreras, Splunk

## Description

The following analytic detects arbitrary command execution using Windows msdt.exe, a Diagnostics Troubleshooting Wizard. It leverages Endpoint Detection and Response (EDR) data to identify instances where msdt.exe is invoked via the ms-msdt:/ protocol handler to retrieve a remote payload. This activity is significant as it can indicate an exploitation attempt leveraging msdt.exe to execute arbitrary commands, potentially leading to unauthorized code execution. If confirmed malicious, this could allow an attacker to execute arbitrary code, escalate privileges, or persist within the environment, posing a severe security risk.

## MITRE ATT&CK

- T1218

## Analytic Stories

- Compromised Windows Host
- Microsoft Support Diagnostic Tool Vulnerability CVE-2022-30190

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/macro/msdt.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_execute_arbitrary_commands_with_msdt.yml)*
