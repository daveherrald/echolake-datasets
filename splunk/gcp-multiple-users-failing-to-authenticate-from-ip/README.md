# GCP Multiple Users Failing To Authenticate From Ip

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects a single source IP address failing to authenticate into more than 20 unique Google Workspace user accounts within a 5-minute window. It leverages Google Workspace login failure events to identify potential password spraying attacks. This activity is significant as it may indicate an adversary attempting to gain unauthorized access or elevate privileges within the Google Cloud Platform. If confirmed malicious, this behavior could lead to unauthorized access to sensitive resources, data breaches, or further exploitation within the environment.

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

*Source: [Splunk Security Content](detections/cloud/gcp_multiple_users_failing_to_authenticate_from_ip.yml)*
