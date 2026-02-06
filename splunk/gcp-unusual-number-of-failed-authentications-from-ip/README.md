# GCP Unusual Number of Failed Authentications From Ip

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic identifies a single source IP failing to authenticate into Google Workspace with multiple valid users, potentially indicating a Password Spraying attack. It uses Google Workspace login failure events and calculates the standard deviation for source IPs, applying the 3-sigma rule to detect unusual failed authentication attempts. This activity is significant as it may signal an adversary attempting to gain initial access or elevate privileges. If confirmed malicious, this could lead to unauthorized access, data breaches, or further exploitation within the environment.

## MITRE ATT&CK

- T1110.003
- T1110.004
- T1586.003

## Analytic Stories

- GCP Account Takeover

## Data Sources

- Google Workspace

## Sample Data

- **Source:** gws_login
  **Sourcetype:** gws:reports:login
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1110.003/gcp_gws_multiple_login_failure/gws_login.json


---

*Source: [Splunk Security Content](detections/cloud/gcp_unusual_number_of_failed_authentications_from_ip.yml)*
