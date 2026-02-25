# Executables Or Script Creation In Suspicious Path

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying the creation of executables or scripts in suspicious file paths on Windows systems. It leverages the Endpoint.Filesystem data model to detect files with specific extensions (e.g., .exe, .dll, .ps1) created in uncommon directories (e.g., \windows\fonts\, \users\public\). This activity is significant as adversaries often use these paths to evade detection and maintain persistence. If confirmed malicious, this behavior could allow attackers to execute unauthorized code, escalate privileges, or persist within the environment, posing a significant security threat.

## MITRE ATT&CK

- T1036

## Analytic Stories

- PlugX
- Warzone RAT
- Swift Slicer
- Data Destruction
- AgentTesla
- LockBit Ransomware
- Volt Typhoon
- Brute Ratel C4
- Industroyer2
- WhisperGate
- DarkGate Malware
- Chaos Ransomware
- ValleyRAT
- XMRig
- Hermetic Wiper
- Remcos
- Quasar RAT
- Rhysida Ransomware
- DarkCrystal RAT
- Qakbot
- Snake Keylogger
- China-Nexus Threat Activity
- IcedID
- CISA AA23-347A
- Azorult
- Handala Wiper
- Crypto Stealer
- Salt Typhoon
- Earth Alux
- Double Zero Destructor
- Trickbot
- Cactus Ransomware
- BlackByte Ransomware
- SystemBC
- AcidPour
- NjRAT
- Graceful Wipe Out Attack
- Amadey
- Derusbi
- AsyncRAT
- RedLine Stealer
- SnappyBee
- Meduza Stealer
- WinDealer RAT
- MoonPeak
- Interlock Ransomware
- Interlock Rat
- NailaoLocker Ransomware
- PromptLock
- GhostRedirector IIS Module and Rungan Backdoor
- Lokibot
- Castle RAT
- SesameOp

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/executables_suspicious_file_path/exec_susp_path2.log


---

*Source: [Splunk Security Content](detections/endpoint/executables_or_script_creation_in_suspicious_path.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
