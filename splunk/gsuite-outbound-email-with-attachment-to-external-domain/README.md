# Gsuite Outbound Email With Attachment To External Domain

**Type:** Hunting

**Author:** Teoderick Contreras, Stanislav Miskovic, Splunk

## Description

The following analytic detects outbound emails with attachments sent from an internal email domain to an external domain. It leverages Gsuite Gmail logs, parsing the source and destination email domains, and flags emails with fewer than 20 outbound instances. This activity is significant as it may indicate potential data exfiltration or insider threats. If confirmed malicious, an attacker could use this method to exfiltrate sensitive information, leading to data breaches and compliance violations.

## MITRE ATT&CK

- T1048.003

## Analytic Stories

- Dev Sec Ops
- Insider Threat

## Data Sources

- G Suite Gmail

## Sample Data

- **Source:** http:gsuite
  **Sourcetype:** gsuite:gmail:bigquery
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1566.001/gsuite_outbound_email_to_external/gsuite_external_domain.log


---

*Source: [Splunk Security Content](detections/cloud/gsuite_outbound_email_with_attachment_to_external_domain.yml)*
