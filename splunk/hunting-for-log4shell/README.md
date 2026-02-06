# Hunting for Log4Shell

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

The following analytic detects potential exploitation attempts of the Log4Shell vulnerability (CVE-2021-44228) by analyzing HTTP headers for specific patterns. It leverages the Web Datamodel and evaluates various indicators such as the presence of `{jndi:`, environment variables, and common URI paths. This detection is significant as Log4Shell allows remote code execution, posing a severe threat to systems. If confirmed malicious, attackers could gain unauthorized access, execute arbitrary code, and potentially compromise sensitive data, leading to extensive damage and data breaches.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- Log4Shell CVE-2021-44228
- CISA AA22-320A

## Data Sources

- Nginx Access

## Sample Data

- **Source:** /var/log/nginx/access.log
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/java/log4shell-nginx.log


---

*Source: [Splunk Security Content](detections/web/hunting_for_log4shell.yml)*
