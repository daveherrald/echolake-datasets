# Executable File Written in Administrative SMB Share

**Type:** TTP

**Author:** Teoderick Contreras, Mauricio Velazco, Splunk

## Description

This dataset contains sample data for detecting executable files (.exe or .dll) being written to Windows administrative SMB shares (Admin$, IPC$, C$). It leverages Windows Security Event Logs with EventCode 5145 to identify this activity. This behavior is significant as it is commonly used by tools like PsExec/PaExec for staging binaries before creating and starting services on remote endpoints, a technique often employed for lateral movement and remote code execution. If confirmed malicious, this activity could allow an attacker to execute arbitrary code remotely, potentially compromising additional systems within the network.

## MITRE ATT&CK

- T1021.002

## Analytic Stories

- Active Directory Lateral Movement
- BlackSuit Ransomware
- IcedID
- Prestige Ransomware
- Industroyer2
- Data Destruction
- Graceful Wipe Out Attack
- Compromised Windows Host
- Hermetic Wiper
- Trickbot
- VanHelsing Ransomware

## Data Sources

- Windows Event Log Security 5145

## Sample Data

- **Source:** XmlWinEventLog:Security
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/trickbot/exe_smbshare/windows-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/executable_file_written_in_administrative_smb_share.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
