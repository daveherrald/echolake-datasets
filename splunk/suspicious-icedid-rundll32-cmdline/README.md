# Suspicious IcedID Rundll32 Cmdline

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects a suspicious `rundll32.exe` command line used to execute a DLL file, a technique associated with IcedID malware. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on command-line executions containing the pattern `*/i:*`. This activity is significant as it indicates potential malware attempting to load an encrypted DLL payload, often named `license.dat`. If confirmed malicious, this could allow attackers to execute arbitrary code, leading to further system compromise and potential data exfiltration.

## MITRE ATT&CK

- T1218.011

## Analytic Stories

- IcedID
- Living Off The Land

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/icedid/inf_icedid/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/suspicious_icedid_rundll32_cmdline.yml)*
