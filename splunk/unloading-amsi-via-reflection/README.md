# Unloading AMSI via Reflection

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the tampering of AMSI (Antimalware Scan Interface) via PowerShell reflection. It leverages PowerShell Script Block Logging (EventCode=4104) to capture and analyze suspicious PowerShell commands, specifically those involving `system.management.automation.amsi`. This activity is significant as it indicates an attempt to bypass AMSI, a critical security feature that helps detect and block malicious scripts. If confirmed malicious, this could allow an attacker to execute harmful code undetected, leading to potential system compromise and data exfiltration.

## MITRE ATT&CK

- T1059.001
- T1562

## Analytic Stories

- Malicious PowerShell
- Hermetic Wiper
- Data Destruction

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059.001/powershell_script_block_logging/windows-powershell-xml.log


---

*Source: [Splunk Security Content](detections/endpoint/unloading_amsi_via_reflection.yml)*
