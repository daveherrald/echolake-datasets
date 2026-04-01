# Confluence Data Center and Server Privilege Escalation

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying potential exploitation attempts on a known vulnerability in Atlassian Confluence, specifically targeting the /setup/*.action* URL pattern. It leverages web logs within the Splunk 'Web' Data Model, filtering for successful accesses (HTTP status 200) to these endpoints. This activity is significant as it suggests attackers might be exploiting a privilege escalation flaw in Confluence. If confirmed malicious, it could result in unauthorized access or account creation with escalated privileges, leading to potential data breaches or further exploitation within the environment.

## MITRE ATT&CK

- T1190

## Analytic Stories

- CVE-2023-22515 Privilege Escalation Vulnerability Confluence Data Center and Server
- Confluence Data Center and Confluence Server Vulnerabilities

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx:plus:kv
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/confluence/nginx_plus_kv_confluence.log


---

*Source: [Splunk Security Content](detections/web/confluence_data_center_and_server_privilege_escalation.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
