# Cisco NVM - MSHTML or MSHTA Network Execution Without URL in CLI

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects suspicious use of 'mshta.exe' or 'rundll32.exe' invoking 'mshtml.dll'
or the 'RunHTMLApplication' export without including a direct HTTP/HTTPS URL in the command line.
This pattern could be associated with obfuscated script execution used by threat actors during
initial access or payload staging. The absence of a visible URL may indicate attempts to evade static
detections by embedding the URL via string concatenation, encoding (e.g., hex), or indirect script loaders
like 'GetObject()'.


## MITRE ATT&CK

- T1218.005
- T1059.005

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___mshtml_or_mshta_network_execution_without_url_in_cli.yml)*
