# HTTP Scripting Tool User Agent

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This Splunk query analyzes web access logs to identify and categorize non-browser user agents, detecting various types of security tools, scripting languages, automation frameworks, and suspicious patterns. This activity can signify malicious actors attempting to interact with web endpoints in non-standard ways.

## MITRE ATT&CK

- T1071.001

## Analytic Stories

- HTTP Request Smuggling
- Suspicious User Agents

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx:plus:kv
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/request_smuggling/nginx_scripting_tools.log


---

*Source: [Splunk Security Content](detections/web/http_scripting_tool_user_agent.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
