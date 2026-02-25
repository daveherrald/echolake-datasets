# VMware Server Side Template Injection Hunt

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying potential server-side template injection attempts related to CVE-2022-22954. It detects suspicious URL patterns containing "deviceudid" and keywords like "java.lang.ProcessBuilder" or "freemarker.template.utility.ObjectConstructor" using web or proxy logs within the Web Datamodel. This activity is significant as it may indicate an attempt to exploit a known vulnerability in VMware, potentially leading to remote code execution. If confirmed malicious, attackers could gain unauthorized access, execute arbitrary code, and compromise the affected system, posing a severe security risk.

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

*Source: [Splunk Security Content](detections/web/vmware_server_side_template_injection_hunt.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
