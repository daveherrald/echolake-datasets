# Windows Impair Defense Disable Defender Firewall And Network

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects modifications in the Windows registry to disable firewall and network protection settings within Windows Defender Security Center. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the UILockdown registry value. This activity is significant as it may indicate an attempt to impair system defenses, potentially restricting users from modifying firewall or network protection settings. If confirmed malicious, this could allow an attacker to weaken the system's security posture, making it more vulnerable to further attacks and unauthorized access.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- Windows Defense Evasion Tactics
- Windows Registry Abuse
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/disable-windows-security-defender-features/windefender-bypas-2-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_defender_firewall_and_network.yml)*
