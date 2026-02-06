# Windows RDP Login Session Was Established

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects instances where a successful Remote Desktop Protocol (RDP) login session was established, as indicated by Windows Security Event ID 4624 with Logon Type 10. This event confirms that a user has not only provided valid credentials but has also initiated a full interactive RDP session. It is a key indicator of successful remote access to a Windows system. When correlated with Event ID 1149, which logs RDP authentication success, this analytic helps distinguish between mere credential acceptance and actual session establishment—critical for effective monitoring and threat detection.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Windows RDP Artifacts and Defense Evasion
- Scattered Lapsus$ Hunters

## Data Sources

- Windows Event Log Security 4624

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.001/rdp_session_established/4624_10_logon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_login_session_was_established.yml)*
