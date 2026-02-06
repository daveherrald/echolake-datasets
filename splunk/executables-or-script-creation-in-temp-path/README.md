# Executables Or Script Creation In Temp Path

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies the creation of executables or scripts in suspicious file paths on Windows systems. It leverages the Endpoint.Filesystem data model to detect files with specific extensions (e.g., .exe, .dll, .ps1) created in uncommon directories (e.g., \windows\fonts\, \users\public\). This activity is significant as adversaries often use these paths to evade detection and maintain persistence. If confirmed malicious, this behavior could allow attackers to execute unauthorized code, escalate privileges, or persist within the environment, posing a significant security threat.

## MITRE ATT&CK

- T1036

## Analytic Stories

- Snake Keylogger
- China-Nexus Threat Activity
- Remcos
- LockBit Ransomware
- AsyncRAT
- DarkCrystal RAT
- Derusbi
- WinDealer RAT
- DarkGate Malware
- AcidPour
- ValleyRAT
- Crypto Stealer
- PlugX
- Data Destruction
- Qakbot
- CISA AA23-347A
- Hermetic Wiper
- Volt Typhoon
- Double Zero Destructor
- NjRAT
- Trickbot
- Meduza Stealer
- AgentTesla
- SnappyBee
- Azorult
- WhisperGate
- Warzone RAT
- Swift Slicer
- Rhysida Ransomware
- Brute Ratel C4
- BlackByte Ransomware
- Graceful Wipe Out Attack
- Chaos Ransomware
- Handala Wiper
- RedLine Stealer
- Salt Typhoon
- XMRig
- MoonPeak
- Industroyer2
- Amadey
- IcedID
- Interlock Rat
- APT37 Rustonotto and FadeStealer
- PromptLock
- Lokibot
- SesameOp
- PromptFlux

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/xmrig_miner/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/executables_or_script_creation_in_temp_path.yml)*
