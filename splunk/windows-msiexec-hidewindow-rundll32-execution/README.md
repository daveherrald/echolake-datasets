# Windows MsiExec HideWindow Rundll32 Execution

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of the msiexec.exe process with the /HideWindow and rundll32 command-line parameters. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process creation events and command-line arguments. This activity is significant because it is a known tactic used by malware like QakBot to mask malicious operations under legitimate system processes. If confirmed malicious, this behavior could allow an attacker to download additional payloads, execute malicious code, or establish communication with remote servers, thereby evading detection and maintaining persistence.

## MITRE ATT&CK

- T1218.007

## Analytic Stories

- Qakbot
- Water Gamayun

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1218.007/msiexec-hidewindow-rundll32/hidewndw-rundll32.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_msiexec_hidewindow_rundll32_execution.yml)*
