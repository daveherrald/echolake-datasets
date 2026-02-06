# Web Remote ShellServlet Access

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies attempts to access the Remote ShellServlet on a web server, specifically targeting Confluence servers vulnerable to CVE-2023-22518 and CVE-2023-22515. It leverages web data to detect URLs containing "*plugins/servlet/com.jsos.shell/*" with a status code of 200. This activity is significant as it is commonly associated with web shells and other malicious behaviors, potentially leading to unauthorized command execution. If confirmed malicious, attackers could gain remote code execution capabilities, compromising the server and potentially the entire network.

## MITRE ATT&CK

- T1190

## Analytic Stories

- CVE-2023-22515 Privilege Escalation Vulnerability Confluence Data Center and Server
- GhostRedirector IIS Module and Rungan Backdoor

## Data Sources

- Nginx Access

## Sample Data

- **Source:** /var/log/nginx/access.log
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/confluence/nginx_shellservlet.log


---

*Source: [Splunk Security Content](detections/web/web_remote_shellservlet_access.yml)*
