# Citrix ADC and Gateway CitrixBleed 2 Memory Disclosure

**Type:** Anomaly

**Author:** Michael Haag, Splunk

## Description

This detection identifies potential exploitation attempts of CVE-2025-5777 (CitrixBleed 2), a memory disclosure vulnerability in Citrix NetScaler ADC and Gateway.
The vulnerability is triggered by sending POST requests with incomplete form data to the /p/u/doAuthentication.do endpoint, causing the device to leak memory contents including session tokens and authentication materials.
This search looks for POST requests to the vulnerable endpoint that may indicate scanning or exploitation attempts.


## MITRE ATT&CK

- T1190

## Analytic Stories

- Citrix NetScaler ADC and NetScaler Gateway CVE-2025-5777

## Data Sources

- Suricata

## Sample Data

- **Source:** suricata
  **Sourcetype:** suricata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/citrix/suricata_citrixbleed2.log


---

*Source: [Splunk Security Content](detections/web/citrix_adc_and_gateway_citrixbleed_2_memory_disclosure.yml)*
