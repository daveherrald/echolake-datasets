# Log4Shell JNDI Payload Injection Attempt

**Type:** Anomaly

**Author:** Jose Hernandez

## Description

The following analytic identifies attempts to inject Log4Shell JNDI payloads via web calls. It leverages the Web datamodel and uses regex to detect patterns like `${jndi:ldap://` in raw web event data, including HTTP headers. This activity is significant because it targets vulnerabilities in Java web applications using Log4j, such as Apache Struts and Solr. If confirmed malicious, this could allow attackers to execute arbitrary code, potentially leading to full system compromise. Immediate investigation is required to determine if the attempt was successful and to mitigate any potential exploitation.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- Log4Shell CVE-2021-44228
- CISA AA22-257A
- CISA AA22-320A

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/log4j_proxy_logs/log4j_proxy_logs.log


---

*Source: [Splunk Security Content](detections/web/log4shell_jndi_payload_injection_attempt.yml)*
