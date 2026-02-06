# Fortinet Appliance Auth bypass

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects attempts to exploit CVE-2022-40684, a Fortinet appliance authentication bypass vulnerability. It identifies REST API requests to the /api/v2/ endpoint using various HTTP methods (GET, POST, PUT, DELETE) that may indicate unauthorized modifications, such as adding SSH keys or creating new users. This detection leverages the Web datamodel to monitor specific URL patterns and HTTP methods. This activity is significant as it can lead to unauthorized access and control over the appliance. If confirmed malicious, attackers could gain persistent access, reroute network traffic, or capture sensitive information.

## MITRE ATT&CK

- T1190
- T1133

## Analytic Stories

- CVE-2022-40684 Fortinet Appliance Auth bypass

## Data Sources

- Palo Alto Network Threat

## Sample Data

- **Source:** pan:threat
  **Sourcetype:** pan:threat
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/fortigate/fortinetcve202240684.log


---

*Source: [Splunk Security Content](detections/web/fortinet_appliance_auth_bypass.yml)*
