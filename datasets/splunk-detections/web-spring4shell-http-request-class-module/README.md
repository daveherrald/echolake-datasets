# Web Spring4Shell HTTP Request Class Module

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for detecting HTTP requests containing payloads related to the Spring4Shell vulnerability (CVE-2022-22965). It leverages Splunk Stream HTTP data to inspect the HTTP request body and form data for specific fields such as "class.module.classLoader.resources.context.parent.pipeline.first". This activity is significant as it indicates an attempt to exploit a critical vulnerability in Spring Framework, potentially leading to remote code execution. If confirmed malicious, this could allow attackers to gain unauthorized access, execute arbitrary code, and compromise the affected system.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- Spring4Shell CVE-2022-22965

## Data Sources

- Splunk Stream HTTP

## Sample Data

- **Source:** stream:http
  **Sourcetype:** stream:http
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/http_request_body_streams.log


---

*Source: [Splunk Security Content](detections/web/web_spring4shell_http_request_class_module.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
