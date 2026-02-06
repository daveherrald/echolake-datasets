# CrushFTP Max Simultaneous Users From IP

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

The following analytic identifies instances where CrushFTP has blocked access due to exceeding the maximum number of simultaneous connections from a single IP address. This activity may indicate brute force attempts, credential stuffing, or automated attacks against the CrushFTP server. This detection is particularly relevant following the discovery of CVE-2025-31161, an authentication bypass vulnerability in CrushFTP versions 10.0.0 through 10.8.3 and 11.0.0 through 11.3.0.

## MITRE ATT&CK

- T1110.001
- T1110.004

## Analytic Stories

- CrushFTP Vulnerabilities

## Data Sources

- CrushFTP

## Sample Data

- **Source:** crushftp
  **Sourcetype:** crushftp:sessionlogs
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/crushftp/crushftp11_session.log


---

*Source: [Splunk Security Content](detections/web/crushftp_max_simultaneous_users_from_ip.yml)*
