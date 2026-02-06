# VMware Workspace ONE Freemarker Server-side Template Injection

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic detects server-side template injection attempts related to CVE-2022-22954 in VMware Workspace ONE. It leverages web or proxy logs to identify HTTP GET requests to the endpoint catalog-portal/ui/oauth/verify with the freemarker.template.utility.Execute command. This activity is significant as it indicates potential exploitation attempts that could lead to remote code execution. If confirmed malicious, an attacker could execute arbitrary commands on the server, leading to full system compromise, data exfiltration, or further lateral movement within the network.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- VMware Server Side Injection and Privilege Escalation

## Data Sources

- Palo Alto Network Threat

## Sample Data

- **Source:** pan:threat
  **Sourcetype:** pan:threat
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/vmware/vmware_scanning_pan_threat.log


---

*Source: [Splunk Security Content](detections/web/vmware_workspace_one_freemarker_server_side_template_injection.yml)*
