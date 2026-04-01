# HTTP Rapid POST with Mixed Status Codes

**Type:** Anomaly

**Author:** Raven Tait, Splunk

## Description

This detection identifies rapid-fire POST request attacks where an attacker sends more than 20 POST requests within a 5-second window, potentially attempting to exploit race conditions or overwhelm request handling. The pattern is particularly suspicious when responses vary in size or status codes, indicating successful exploitation attempts or probing for vulnerable endpoints.

## MITRE ATT&CK

- T1071.001
- T1190
- T1595

## Analytic Stories

- HTTP Request Smuggling

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx:plus:kv
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/request_smuggling/nginx_request_smuggling.log


---

*Source: [Splunk Security Content](detections/web/http_rapid_post_with_mixed_status_codes.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
