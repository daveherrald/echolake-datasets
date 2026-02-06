# Powershell Remote Services Add TrustedHost

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects the execution of a PowerShell script that modifies the 'TrustedHosts' configuration via EventCode 4104. It leverages PowerShell Script Block Logging to identify commands targeting WSMan settings, specifically those altering or concatenating trusted hosts. This activity is significant as it can indicate attempts to manipulate remote connection settings, potentially allowing unauthorized remote access. If confirmed malicious, this could enable attackers to establish persistent remote connections, bypass security protocols, and gain unauthorized access to sensitive systems and data.

## MITRE ATT&CK

- T1021.006

## Analytic Stories

- DarkGate Malware

## Data Sources

- Powershell Script Block Logging 4104

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-PowerShell/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.006/wsman_trustedhost/wsman_pwh.log


---

*Source: [Splunk Security Content](detections/endpoint/powershell_remote_services_add_trustedhost.yml)*
