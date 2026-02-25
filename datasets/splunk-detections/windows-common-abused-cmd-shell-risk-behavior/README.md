# Windows Common Abused Cmd Shell Risk Behavior

**Type:** Correlation

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for identifying instances where four or more distinct detection analytics are associated with malicious command line behavior on a specific host. This detection leverages the Command Line Interface (CLI) data from various sources to identify suspicious activities. This behavior is significant as it often indicates attempts to execute malicious commands, access sensitive data, install backdoors, or perform other nefarious actions. If confirmed malicious, attackers could gain unauthorized control, exfiltrate information, escalate privileges, or launch further attacks within the network, leading to severe compromise.

## MITRE ATT&CK

- T1222
- T1049
- T1033
- T1529
- T1016
- T1059

## Analytic Stories

- Azorult
- Volt Typhoon
- Sandworm Tools
- Windows Post-Exploitation
- FIN7
- Qakbot
- Netsh Abuse
- DarkCrystal RAT
- Windows Defense Evasion Tactics
- CISA AA23-347A
- Disabling Security Tools
- Microsoft WSUS CVE-2025-59287

## Data Sources


## Sample Data

- **Source:** risk
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1059/risk_behavior/abused_commandline/risk_recon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_common_abused_cmd_shell_risk_behavior.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
