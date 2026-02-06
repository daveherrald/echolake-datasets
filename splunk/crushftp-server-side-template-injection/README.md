# CrushFTP Server Side Template Injection

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

This analytic is designed to identify attempts to exploit a server-side template injection vulnerability in CrushFTP, designated as CVE-2024-4040. This severe vulnerability enables unauthenticated remote attackers to access and read files beyond the VFS Sandbox, circumvent authentication protocols, and execute arbitrary commands on the affected server. The issue impacts all versions of CrushFTP up to 10.7.1 and 11.1.0 on all supported platforms. It is highly recommended to apply patches immediately to prevent unauthorized access to the system and avoid potential data compromises. The search specifically looks for patterns in the raw log data that match the exploitation attempts, including READ or WRITE actions, and extracts relevant information such as the protocol, session ID, user, IP address, HTTP method, and the URI queried. It then evaluates these logs to confirm traces of exploitation based on the presence of specific keywords and the originating IP address, counting and sorting these events for further analysis.

## MITRE ATT&CK

- T1190

## Analytic Stories

- CrushFTP Vulnerabilities
- Hellcat Ransomware

## Data Sources

- CrushFTP

## Sample Data

- **Source:** crushftp
  **Sourcetype:** crushftp:sessionlogs
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/crushftp/crushftp.log


---

*Source: [Splunk Security Content](detections/application/crushftp_server_side_template_injection.yml)*
