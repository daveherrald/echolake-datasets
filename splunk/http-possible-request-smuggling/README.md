# HTTP Possible Request Smuggling

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

HTTP request smuggling is a technique for interfering with the way a web site processes sequences of HTTP requests that are received from one or more users. Request smuggling vulnerabilities are often critical in nature, allowing an attacker to bypass security controls, gain unauthorized access to sensitive data, and directly compromise other application users. This detection identifies a common request smuggling technique of using both Content-Length and Transfer-Encoding headers to cause a parsing confusion between the frontend and backend.

## MITRE ATT&CK

- T1071.001

## Analytic Stories

- HTTP Request Smuggling

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/request_smuggling/suricata_request_smuggling.log


---

*Source: [Splunk Security Content](detections/web/http_possible_request_smuggling.yml)*
