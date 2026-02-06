# Uninstall App Using MsiExec

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the uninstallation of applications using msiexec with specific command-line arguments. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on process execution logs that include command-line details. This activity is significant because it is an uncommon practice in enterprise environments and has been associated with malicious behavior, such as disabling antivirus software. If confirmed malicious, this could allow an attacker to remove security software, potentially leading to further compromise and persistence within the network.

## MITRE ATT&CK

- T1218.007

## Analytic Stories

- Ransomware

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/conti/conti_leak/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/uninstall_app_using_msiexec.yml)*
