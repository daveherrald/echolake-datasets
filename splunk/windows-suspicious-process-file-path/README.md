# Windows Suspicious Process File Path

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies processes running from file paths not typically associated with legitimate software. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific process paths within the Endpoint data model. This activity is significant because adversaries often use unconventional file paths to execute malicious code without requiring administrative privileges. If confirmed malicious, this behavior could indicate an attempt to bypass security controls, leading to unauthorized software execution, potential system compromise, and further malicious activities within the environment.

## MITRE ATT&CK

- T1543
- T1036.005

## Analytic Stories

- StealC Stealer
- PlugX
- Water Gamayun
- Warzone RAT
- Swift Slicer
- Data Destruction
- AgentTesla
- LockBit Ransomware
- Volt Typhoon
- Brute Ratel C4
- WhisperGate
- Industroyer2
- DarkGate Malware
- ValleyRAT
- XMRig
- Chaos Ransomware
- Hermetic Wiper
- Remcos
- Quasar RAT
- Rhysida Ransomware
- DarkCrystal RAT
- Qakbot
- China-Nexus Threat Activity
- XWorm
- IcedID
- CISA AA23-347A
- Azorult
- Handala Wiper
- Salt Typhoon
- Earth Alux
- Double Zero Destructor
- Trickbot
- Malicious Inno Setup Loader
- BlackByte Ransomware
- SystemBC
- Phemedrone Stealer
- Graceful Wipe Out Attack
- Prestige Ransomware
- Amadey
- AsyncRAT
- RedLine Stealer
- SnappyBee
- Meduza Stealer
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

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1036/suspicious_process_path/susp_path_sysmon1.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_suspicious_process_file_path.yml)*
