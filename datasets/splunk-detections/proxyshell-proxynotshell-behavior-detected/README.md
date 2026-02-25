# ProxyShell ProxyNotShell Behavior Detected

**Type:** Correlation

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying potential exploitation of Windows Exchange servers via ProxyShell or ProxyNotShell vulnerabilities, followed by post-exploitation activities such as running nltest, Cobalt Strike, Mimikatz, and adding new users. It leverages data from multiple analytic stories, requiring at least five distinct sources to trigger, thus reducing noise. This activity is significant as it indicates a high likelihood of an active compromise, potentially leading to unauthorized access, privilege escalation, and persistent threats within the environment. If confirmed malicious, attackers could gain control over the Exchange server, exfiltrate data, and maintain long-term access.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- ProxyShell
- ProxyNotShell
- Seashell Blizzard

## Data Sources


## Sample Data

- **Source:** proxyshell
  **Sourcetype:** stash
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/proxyshell/proxyshell-risk.log


---

*Source: [Splunk Security Content](detections/web/proxyshell_proxynotshell_behavior_detected.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
