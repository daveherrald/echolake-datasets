# PaperCut NG Suspicious Behavior Debug Log

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies potential exploitation attempts on a PaperCut NG server by analyzing its debug log data. It detects unauthorized or suspicious access attempts from public IP addresses and searches for specific URIs associated with known exploits. The detection leverages regex to parse unstructured log data, focusing on admin login activities. This activity is significant as it can indicate an active exploitation attempt on the server. If confirmed malicious, attackers could gain unauthorized access, potentially leading to data breaches or further compromise of the server.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- PaperCut MF NG Vulnerability

## Data Sources


## Sample Data

- **Source:** papercutng
  **Sourcetype:** papercutng
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/papercut/server.log


---

*Source: [Splunk Security Content](detections/endpoint/papercut_ng_suspicious_behavior_debug_log.yml)*
