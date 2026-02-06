# High Process Termination Frequency

**Type:** Anomaly

**Author:** Teoderick Contreras

## Description

The following analytic identifies a high frequency of process termination events on a computer within a short period. It leverages Sysmon EventCode 5 logs to detect instances where 15 or more processes are terminated within a 3-second window. This behavior is significant as it is commonly associated with ransomware attempting to avoid exceptions during file encryption. If confirmed malicious, this activity could indicate an active ransomware attack, potentially leading to widespread file encryption and significant data loss.

## MITRE ATT&CK

- T1486

## Analytic Stories

- BlackByte Ransomware
- Rhysida Ransomware
- LockBit Ransomware
- Medusa Ransomware
- Crypto Stealer
- Snake Keylogger
- Clop Ransomware
- Termite Ransomware
- Interlock Ransomware
- NailaoLocker Ransomware
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 5

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/clop/clop_a/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/high_process_termination_frequency.yml)*
