# HTTP Suspicious Tool User Agent

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This Splunk query analyzes web access logs to identify and categorize non-browser user agents, detecting various types of security tools, scripting languages, automation frameworks, and suspicious patterns. This activity can signify malicious actors attempting to interact with web endpoints in non-standard ways.

## MITRE ATT&CK

- T1071.001

## Analytic Stories

- HTTP Request Smuggling

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx:plus:kv
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/request_smuggling/nginx_scripting_tools.log


---

*Source: [Splunk Security Content](detections/deprecated/http_suspicious_tool_user_agent.yml)*
