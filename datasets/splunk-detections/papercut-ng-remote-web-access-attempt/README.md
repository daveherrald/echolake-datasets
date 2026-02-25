# PaperCut NG Remote Web Access Attempt

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting potential exploitation attempts on publicly accessible PaperCut NG servers. It identifies connections from public IP addresses to the server, specifically monitoring URI paths commonly used in proof-of-concept scripts for exploiting PaperCut NG vulnerabilities. This detection leverages web traffic data from the `Web` datamodel, focusing on specific URI paths and excluding internal IP ranges. This activity is significant as it may indicate an attempt to exploit known vulnerabilities in PaperCut NG, potentially leading to unauthorized access or control of the server. If confirmed malicious, attackers could gain administrative access, leading to data breaches or further network compromise.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- PaperCut MF NG Vulnerability

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/papercut/papercutng-suricata.log


---

*Source: [Splunk Security Content](detections/web/papercut_ng_remote_web_access_attempt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
