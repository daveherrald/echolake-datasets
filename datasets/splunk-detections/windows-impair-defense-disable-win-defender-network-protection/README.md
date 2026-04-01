# Windows Impair Defense Disable Win Defender Network Protection

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting modifications to the Windows registry that disable Windows Defender Network Protection. It leverages data from the Endpoint.Registry data model, specifically monitoring changes to the EnableNetworkProtection registry entry. This activity is significant because disabling Network Protection can leave the system vulnerable to network-based threats by preventing Windows Defender from analyzing and blocking malicious network activity. If confirmed malicious, this action could allow attackers to bypass security measures, potentially leading to unauthorized access, data exfiltration, or further compromise of the network.

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

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defense_disable_win_defender_network_protection.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
