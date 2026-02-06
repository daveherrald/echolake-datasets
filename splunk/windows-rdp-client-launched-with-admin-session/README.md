# Windows RDP Client Launched with Admin Session

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies the execution of the Windows Remote Desktop Client (mstsc.exe) with the "/v" and /admin command-line arguments. The "/v" flag specifies the remote host to connect to, while the /admin flag initiates a connection to the target system’s console session, often used for administrative purposes. This combination may indicate that a user or attacker is performing privileged remote access, potentially to manage a system without disrupting existing user sessions. While such usage may be legitimate for IT administrators, it is less common in typical user behavior. Threat actors may abuse this capability during lateral movement to maintain stealthy access to high-value systems. Monitoring for this pattern can help detect interactive hands-on-keyboard activity, privilege abuse, or attempts to access critical infrastructure without leaving typical login traces associated with non-admin RDP sessions.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 1

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.001/mstsc_admini/mstsc_admin.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_client_launched_with_admin_session.yml)*
