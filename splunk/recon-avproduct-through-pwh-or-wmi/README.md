# Recon AVProduct Through Pwh or WMI

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious PowerShell script execution via EventCode 4104, specifically targeting checks for installed anti-virus products using WMI or PowerShell commands. This detection leverages PowerShell Script Block Logging to identify scripts containing keywords like "SELECT," "WMIC," "AntiVirusProduct," or "AntiSpywareProduct." This activity is significant as it is commonly used by malware and APT actors to map running security applications or services, potentially aiding in evasion techniques. If confirmed malicious, this could allow attackers to disable or bypass security measures, leading to further compromise of the endpoint.

## MITRE ATT&CK

- T1592

## Analytic Stories

- XWorm
- Ransomware
- Hermetic Wiper
- Prestige Ransomware
- Quasar RAT
- Malicious PowerShell
- Data Destruction
- MoonPeak
- Qakbot
- Windows Post-Exploitation

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/t1592/pwh_av_recon/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/recon_avproduct_through_pwh_or_wmi.yml)*
