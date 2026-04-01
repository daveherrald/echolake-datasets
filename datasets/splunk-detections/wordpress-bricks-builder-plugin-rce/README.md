# WordPress Bricks Builder plugin RCE

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying potential exploitation of the WordPress Bricks Builder plugin RCE vulnerability. It detects HTTP POST requests to the URL path "/wp-json/bricks/v1/render_element" with a status code of 200, leveraging the Web datamodel. This activity is significant as it indicates an attempt to exploit CVE-2024-25600, a known vulnerability that allows remote code execution. If confirmed malicious, an attacker could execute arbitrary commands on the target server, leading to potential full system compromise and unauthorized access to sensitive data.

## MITRE ATT&CK

- T1190

## Analytic Stories

- WordPress Vulnerabilities
- Hellcat Ransomware

## Data Sources

- Nginx Access

## Sample Data

- **Source:** nginx:plus:kv
  **Sourcetype:** nginx:plus:kv
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/wordpress/bricks_cve_2024_25600.log


---

*Source: [Splunk Security Content](detections/web/wordpress_bricks_builder_plugin_rce.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
