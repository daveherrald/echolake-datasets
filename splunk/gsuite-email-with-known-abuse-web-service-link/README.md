# Gsuite Email With Known Abuse Web Service Link

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects emails in Gsuite containing links to known abuse web services such as Pastebin, Telegram, and Discord. It leverages Gsuite Gmail logs to identify emails with these specific domains in their links. This activity is significant because these services are commonly used by attackers to deliver malicious payloads. If confirmed malicious, this could lead to the delivery of malware, phishing attacks, or other harmful activities, potentially compromising sensitive information or systems within the organization.

## MITRE ATT&CK

- T1566.001

## Analytic Stories

- Dev Sec Ops

## Data Sources

- G Suite Gmail

## Sample Data

- **Source:** http:gsuite
  **Sourcetype:** gsuite:gmail:bigquery
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_susp_url/gsuite_susp_url.log


---

*Source: [Splunk Security Content](detections/cloud/gsuite_email_with_known_abuse_web_service_link.yml)*
