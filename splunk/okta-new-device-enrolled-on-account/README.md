# Okta New Device Enrolled on Account

**Type:** TTP

**Author:** Michael Haag, Mauricio Velazco, Splunk

## Description

The following analytic identifies when a new device is enrolled on an Okta account. It uses OktaIm2 logs ingested via the Splunk Add-on for Okta Identity Cloud to detect the creation of new device enrollments. This activity is significant as it may indicate a legitimate user setting up a new device or an adversary adding a device to maintain unauthorized access. If confirmed malicious, this could lead to potential account takeover, unauthorized access, and persistent control over the compromised Okta account. Monitoring this behavior is crucial for detecting and mitigating unauthorized access attempts.

## MITRE ATT&CK

- T1098.005

## Analytic Stories

- Okta Account Takeover
- Scattered Lapsus$ Hunters

## Data Sources

- Okta

## Sample Data

- **Source:** Okta
  **Sourcetype:** OktaIM2:log
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1098.005/okta_new_device_enrolled/okta_new_device_enrolled.log


---

*Source: [Splunk Security Content](detections/application/okta_new_device_enrolled_on_account.yml)*
