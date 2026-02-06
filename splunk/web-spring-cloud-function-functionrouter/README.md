# Web Spring Cloud Function FunctionRouter

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies HTTP POST requests to the Spring Cloud Function endpoint containing "functionRouter" in the URL. It leverages the Web data model to detect these requests based on specific fields such as http_method, url, and http_user_agent. This activity is significant because it targets CVE-2022-22963, a known vulnerability in Spring Cloud Function, which has multiple proof-of-concept exploits available. If confirmed malicious, this activity could allow attackers to execute arbitrary code, potentially leading to unauthorized access, data exfiltration, or further compromise of the affected system.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/all_functionrouter_http_streams.log


---

*Source: [Splunk Security Content](detections/web/web_spring_cloud_function_functionrouter.yml)*
