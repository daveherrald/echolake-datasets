# Internal Vertical Port Scan

**Type:** TTP

**Author:** Dean Luxton, Splunk

## Description

This analytic detects instances where an internal host attempts to communicate with over 500 ports on a single destination IP address. It includes filtering criteria to exclude applications performing scans over ephemeral port ranges, focusing on potential reconnaissance or scanning activities. Monitoring network traffic logs allows for timely detection and response to such behavior, enhancing network security by identifying and mitigating potential threats promptly.

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
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1046/nmap/vertical.log

- **Source:** not_applicable
  **Sourcetype:** cisco:sfw:estreamer
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_secure_firewall_threat_defense/connection_event/connection_events.log


---

*Source: [Splunk Security Content](detections/network/internal_vertical_port_scan.yml)*
