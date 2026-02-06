# Recon Using WMI Class

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious PowerShell activity via EventCode 4104, where WMI performs event queries to gather information on running processes or services. This detection leverages PowerShell Script Block Logging to identify specific WMI queries targeting system information classes like Win32_Bios and Win32_OperatingSystem. This activity is significant as it often indicates reconnaissance efforts by an adversary to profile the compromised machine. If confirmed malicious, the attacker could gain detailed system information, aiding in further exploitation or lateral movement within the network.

## MITRE ATT&CK

- T1592
- T1059.001

## Analytic Stories

- Hermetic Wiper
- Quasar RAT
- Malicious PowerShell
- Data Destruction
- AsyncRAT
- MoonPeak
- LockBit Ransomware
- Malicious Inno Setup Loader
- Qakbot
- Industroyer2
- Scattered Spider

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/reconusingwmi.log


---

*Source: [Splunk Security Content](detections/endpoint/recon_using_wmi_class.yml)*
