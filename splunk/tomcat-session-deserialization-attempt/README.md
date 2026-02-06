# Tomcat Session Deserialization Attempt

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This detection identifies potential exploitation of CVE-2025-24813 in Apache Tomcat through the second stage of the attack. This phase occurs when an attacker attempts to trigger deserialization of a previously uploaded malicious session file by sending a GET request with a specially crafted JSESSIONID cookie. These requests typically have specific characteristics, including a JSESSIONID cookie with a leading dot that matches a previously uploaded filename, and typically result in a HTTP 500 error when the exploitation succeeds.

## MITRE ATT&CK

- T1190
- T1505.003

## Analytic Stories

- Apache Tomcat Session Deserialization Attacks

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/tomcat/tomcat_nginx_access.log


---

*Source: [Splunk Security Content](detections/web/tomcat_session_deserialization_attempt.yml)*
