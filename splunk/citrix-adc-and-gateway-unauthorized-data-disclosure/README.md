# Citrix ADC and Gateway Unauthorized Data Disclosure

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects attempts to exploit the Citrix Bleed vulnerability (CVE-2023-4966), which can lead to the leaking of session tokens. It identifies HTTP requests with a 200 status code targeting the /oauth/idp/.well-known/openid-configuration URL endpoint. By parsing web traffic and filtering based on user agent details, HTTP method, source and destination IPs, and sourcetype, it aims to identify potentially malicious requests. This activity is significant for a SOC because successful exploitation can allow attackers to impersonate legitimate users, bypass authentication, and access sensitive data. If confirmed malicious, it could lead to unauthorized data access, network propagation, and critical information exfiltration.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Citrix NetScaler ADC and NetScaler Gateway CVE-2023-4966
- Scattered Lapsus$ Hunters

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/citrix/cve-2023-4966-citrix.log


---

*Source: [Splunk Security Content](detections/web/citrix_adc_and_gateway_unauthorized_data_disclosure.yml)*
