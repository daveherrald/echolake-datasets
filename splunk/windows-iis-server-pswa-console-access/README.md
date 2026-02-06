# Windows IIS Server PSWA Console Access

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This analytic detects access attempts to the PowerShell Web Access (PSWA) console on Windows IIS servers. It monitors web traffic for requests to PSWA-related URIs, which could indicate legitimate administrative activity or potential unauthorized access attempts. By tracking source IP, HTTP status, URI path, and HTTP method, it helps identify suspicious patterns or brute-force attacks targeting PSWA. This detection is crucial for maintaining the security of remote PowerShell management interfaces and preventing potential exploitation of this powerful administrative tool.

## MITRE ATT&CK

- T1190

## Analytic Stories

- CISA AA24-241A

## Data Sources

- Windows IIS

## Sample Data

- **Source:** ms:iis:splunk
  **Sourcetype:** ms:iis:splunk
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/pswa/iis_pswaaccess.log


---

*Source: [Splunk Security Content](detections/web/windows_iis_server_pswa_console_access.yml)*
