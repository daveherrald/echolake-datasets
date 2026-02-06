# Log4Shell JNDI Payload Injection with Outbound Connection

**Type:** Anomaly

**Author:** Jose Hernandez

## Description

The following analytic detects Log4Shell JNDI payload injections via outbound connections. It identifies suspicious LDAP lookup functions in web logs, such as `${jndi:ldap://PAYLOAD_INJECTED}`, and correlates them with network traffic to known malicious IP addresses. This detection leverages the Web and Network_Traffic data models in Splunk. Monitoring this activity is crucial as it targets vulnerabilities in Java web applications using log4j, potentially leading to remote code execution. If confirmed malicious, attackers could gain unauthorized access, execute arbitrary code, and compromise sensitive data within the affected environment.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- Log4Shell CVE-2021-44228
- CISA AA22-320A

## Data Sources


## Sample Data

- **Source:** nginx
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/log4j_proxy_logs/log4j_proxy_logs.log

- **Source:** stream:Splunk_IP
  **Sourcetype:** stream:ip
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/log4j_network_logs/log4j_network_logs.log


---

*Source: [Splunk Security Content](detections/web/log4shell_jndi_payload_injection_with_outbound_connection.yml)*
