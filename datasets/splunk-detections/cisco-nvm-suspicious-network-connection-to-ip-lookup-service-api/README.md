# Cisco NVM - Suspicious Network Connection to IP Lookup Service API

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk, Janantha Marasinghe

## Description

This analytic identifies non-browser processes reaching out to public IP lookup or geolocation services,
such as `ipinfo.io`, `icanhazip.com`, `ip-api.com`, and others.
These domains are commonly used by legitimate tools, but their usage outside of browsers may indicate
network reconnaissance, virtual machine detection, or staging by malware.
This activity is observed in post-exploitation frameworks, stealer malware, and advanced threat actor campaigns.
The detection relies on Cisco Network Visibility Module (NVM) telemetry and excludes known browser
processes to reduce noise.


## MITRE ATT&CK

- T1590.005
- T1016

## Analytic Stories

- Cisco Network Visibility Module Analytics
- Castle RAT

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___suspicious_network_connection_to_ip_lookup_service_api.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
