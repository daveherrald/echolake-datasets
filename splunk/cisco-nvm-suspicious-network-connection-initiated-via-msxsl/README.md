# Cisco NVM - Suspicious Network Connection Initiated via MsXsl

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic identifies the use of `msxsl.exe` initiating a network connection to a non-private IP address.
Although `msxsl.exe` is a legitimate Microsoft utility used to apply XSLT transformations, adversaries can abuse it
to execute arbitrary code or load external resources in an evasive manner.
This detection leverages Cisco NVM telemetry to identify potentially malicious use of `msxsl.exe` making network connections
that may indicate command and control (C2) or data exfiltration activity.


## MITRE ATT&CK

- T1220

## Analytic Stories

- Cisco Network Visibility Module Analytics

## Data Sources

- Cisco Network Visibility Module Flow Data

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:nvm:flowdata
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_network_visibility_module/cisco_nvm_flowdata/nvm_flowdata.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_nvm___suspicious_network_connection_initiated_via_msxsl.yml)*
