# Cobalt Strike Named Pipes

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the use of default or publicly known named pipes associated with Cobalt Strike. It leverages Sysmon EventID 17 and 18 to identify specific named pipes commonly used by Cobalt Strike's Artifact Kit and Malleable C2 Profiles. This activity is significant because Cobalt Strike is a popular tool for adversaries to conduct post-exploitation tasks, and identifying its named pipes can reveal potential malicious activity. If confirmed malicious, this could indicate an active Cobalt Strike beacon, leading to unauthorized access, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1055

## Analytic Stories

- Trickbot
- DarkSide Ransomware
- Cobalt Strike
- BlackByte Ransomware
- Graceful Wipe Out Attack
- LockBit Ransomware
- Gozi Malware
- APT37 Rustonotto and FadeStealer
- Hellcat Ransomware

## Data Sources

- Sysmon EventID 17
- Sysmon EventID 18

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1055/cobalt_strike/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/deprecated/cobalt_strike_named_pipes.yml)*
