# Web JSP Request via URL

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies URL requests associated with CVE-2022-22965 (Spring4Shell) exploitation attempts, specifically targeting webshell access on a remote webserver. It detects HTTP GET requests with URLs containing ".jsp?cmd=" or "j&cmd=" patterns. This activity is significant as it indicates potential webshell deployment, which can lead to unauthorized remote command execution. If confirmed malicious, attackers could gain control over the webserver, execute arbitrary commands, and potentially escalate privileges, leading to severe data breaches and system compromise.

## MITRE ATT&CK

- T1133
- T1190
- T1505.003

## Analytic Stories

- Spring4Shell CVE-2022-22965
- Earth Alux

## Data Sources

- Nginx Access

## Sample Data

- **Source:** /var/log/nginx/access.log
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/spring4shell/spring4shell_nginx.log


---

*Source: [Splunk Security Content](detections/web/web_jsp_request_via_url.yml)*
