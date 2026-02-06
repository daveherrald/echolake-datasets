# Windows Scheduled Tasks for CompMgmtLauncher or Eventvwr

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation or modification of Windows Scheduled Tasks related to CompMgmtLauncher or Eventvwr. These legitimate system utilities, used for launching the Computer Management Console and Event Viewer, can be abused by attackers to execute malicious payloads under the guise of normal system processes. By leveraging these tasks, adversaries can establish persistence or elevate privileges without raising suspicion. This detection helps security analysts identify unusual or unauthorized scheduled tasks involving these executables, allowing for timely investigation and remediation of potential threats.

## MITRE ATT&CK

- T1053

## Analytic Stories

- ValleyRAT
- Water Gamayun

## Data Sources

- Windows Event Log Security 4698

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1053/valleyrat_schedtask/valleyrat_schedtask.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_scheduled_tasks_for_compmgmtlauncher_or_eventvwr.yml)*
