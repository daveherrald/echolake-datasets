# Windows Impair Defense Configure App Install Control

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications to the Windows registry that disable the Windows Defender SmartScreen App Install Control feature. It leverages data from the Endpoint.Registry data model to identify changes to specific registry values. This activity is significant because disabling App Install Control can allow users to install potentially malicious web-based applications without restrictions, increasing the risk of security vulnerabilities. If confirmed malicious, this action could lead to the installation of harmful applications, potentially compromising the system and exposing sensitive information.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable-windows-security-defender-features/windefender-bypas-2-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_configure_app_install_control.yml)*
