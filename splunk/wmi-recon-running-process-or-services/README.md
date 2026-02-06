# WMI Recon Running Process Or Services

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies suspicious PowerShell script execution via EventCode 4104, where WMI performs an event query to list running processes or services. This detection leverages PowerShell Script Block Logging to capture and analyze script block text for specific WMI queries. This activity is significant as it is commonly used by malware and APT actors to map security applications or services on a compromised machine. If confirmed malicious, this could allow attackers to identify and potentially disable security defenses, facilitating further compromise and persistence within the environment.

## MITRE ATT&CK

- T1592

## Analytic Stories

- Malicious PowerShell
- Hermetic Wiper
- Data Destruction

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/win32process.log


---

*Source: [Splunk Security Content](detections/endpoint/wmi_recon_running_process_or_services.yml)*
