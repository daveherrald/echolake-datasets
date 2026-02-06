# Windows Event Triggered Image File Execution Options Injection

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies the creation or modification of Image File Execution Options (IFEO) registry keys, detected via EventCode 3000 in the Application channel. This detection leverages Windows Event Logs to monitor for process names added to IFEO under specific registry paths. This activity is significant as it can indicate attempts to set traps for process monitoring or debugging, often used by attackers for persistence or evasion. If confirmed malicious, this could allow an attacker to execute arbitrary code or manipulate process behavior, leading to potential system compromise.

## MITRE ATT&CK

- T1546.012

## Analytic Stories

- Windows Persistence Techniques

## Data Sources

- Windows Event Log Application 3000

## Sample Data

- **Source:** XmlWinEventLog:Application
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1546.012/atomic_red_team/windows-application.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_event_triggered_image_file_execution_options_injection.yml)*
