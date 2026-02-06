# Trickbot Named Pipe

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the creation or connection to a named pipe associated with Trickbot malware. It leverages Sysmon EventCodes 17 and 18 to identify named pipes with the pattern "\\pipe\\*lacesomepipe". This activity is significant as Trickbot uses named pipes for communication with its command and control (C2) servers, facilitating data exfiltration and command execution. If confirmed malicious, this behavior could allow attackers to maintain persistence, execute arbitrary commands, and exfiltrate sensitive information from the compromised system.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Trickbot
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 17
- Sysmon EventID 18

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/namedpipe/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/trickbot_named_pipe.yml)*
