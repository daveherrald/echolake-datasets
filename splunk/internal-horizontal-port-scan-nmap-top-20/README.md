# Internal Horizontal Port Scan NMAP Top 20

**Type:** TTP

**Author:** Dean Luxton

## Description

This analytic identifies instances where an internal host has attempted to communicate with 250 or more destination IP addresses using on of the NMAP top 20 ports. Horizontal port scans from internal hosts can indicate reconnaissance or scanning activities, potentially signaling malicious intent or misconfiguration. By monitoring network traffic logs, this detection helps detect and respond to such behavior promptly, enhancing network security and preventing potential threats.

## MITRE ATT&CK

- T1046

## Analytic Stories

- Network Discovery
- Cisco Secure Firewall Threat Defense Analytics
- China-Nexus Threat Activity
- Scattered Lapsus$ Hunters

## Data Sources

- AWS CloudWatchLogs VPCflow
- Cisco Secure Firewall Threat Defense Connection Event

## Sample Data

- **Source:** aws:cloudwatchlogs:vpcflow
  **Sourcetype:** aws:cloudwatchlogs:vpcflow
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1046/nmap/horizontal.log

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/internal_horizontal_port_scan_nmap_top_20.yml)*
