# Spring4Shell Payload URL Request

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting attempts to exploit the Spring4Shell vulnerability (CVE-2022-22963) by identifying specific URL patterns associated with web shell payloads. It leverages web traffic data, focusing on HTTP GET requests with URLs containing indicators like "tomcatwar.jsp," "poc.jsp," and "shell.jsp." This activity is significant as it suggests an attacker is trying to deploy a web shell, which can lead to remote code execution. If confirmed malicious, this could allow the attacker to gain persistent access, execute arbitrary commands, and potentially escalate privileges within the compromised environment.

## MITRE ATT&CK

- T1133
- T1190
- T1505.003

## Analytic Stories

- Spring4Shell CVE-2022-22965

## Data Sources

- Nginx Access

## Sample Data

- **Source:** /var/log/nginx/access.log
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/spring4shell_nginx.log


---

*Source: [Splunk Security Content](detections/web/spring4shell_payload_url_request.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
