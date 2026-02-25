# Registry Keys Used For Persistence

**Type:** TTP

**Author:** Jose Hernandez, David Dorsey, Teoderick Contreras, Rod Soto, Splunk

## Description

This dataset contains sample data for identifying modifications to registry keys commonly used for persistence mechanisms. It leverages data from endpoint detection sources like Sysmon or Carbon Black, focusing on specific registry paths known to initiate applications or services during system startup. This activity is significant as unauthorized changes to these keys can indicate attempts to maintain persistence or execute malicious actions upon system boot. If confirmed malicious, this could allow attackers to achieve persistent access, execute arbitrary code, or maintain control over compromised systems, posing a severe threat to system integrity and security.

## MITRE ATT&CK

- T1547.001

## Analytic Stories

- Warzone RAT
- Possible Backdoor Activity Associated With MUDCARP Espionage Campaigns
- Sneaky Active Directory Persistence Tricks
- Windows Registry Abuse
- Chaos Ransomware
- DarkGate Malware
- Remcos
- Quasar RAT
- Braodo Stealer
- Qakbot
- Snake Keylogger
- China-Nexus Threat Activity
- IcedID
- CISA AA23-347A
- Ransomware
- XWorm
- Azorult
- Salt Typhoon
- Cactus Ransomware
- BlackSuit Ransomware
- BlackByte Ransomware
- SystemBC
- NjRAT
- DHS Report TA18-074A
- Derusbi
- Amadey
- Suspicious MSHTA Activity
- Suspicious Windows Registry Activities
- Emotet Malware DHS Report TA18-201A
- WinDealer RAT
- AsyncRAT
- RedLine Stealer
- SnappyBee
- Windows Persistence Techniques
- MoonPeak
- Interlock Ransomware
- 0bj3ctivity Stealer
- APT37 Rustonotto and FadeStealer
- NetSupport RMM Tool Abuse
- DarkCrystal RAT
- Lokibot
- ValleyRAT
- Castle RAT

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/registry_keys_used_for_persistence.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
