# Detect Large ICMP Traffic

**Type:** TTP

**Author:** Rico Valdez, Dean Luxton, Bhavin Patel, Splunk

## Description

The following analytic identifies ICMP traffic to external IP addresses with total bytes (sum of bytes in and bytes out) greater than 1,000 bytes. It leverages the Network_Traffic data model to detect large ICMP packet that aren't blocked and are directed toward external networks. We use  All_Traffic.bytes in the detection to capture variations in inbound versus outbound traffic sizes, as significant discrepancies or unusually large ICMP exchanges can indicate information smuggling, covert communication, or command-and-control (C2) activities. If validated as malicious, this could signal ICMP tunneling, unauthorized data transfer, or compromised endpoints requiring immediate investigation.

## MITRE ATT&CK

- T1095

## Analytic Stories

- Command And Control
- China-Nexus Threat Activity
- Backdoor Pingpong

## Data Sources

- Palo Alto Network Traffic

## Sample Data

- **Source:** pan:traffic
  **Sourcetype:** pan:traffic
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1095/palologs/large_icmp.log


---

*Source: [Splunk Security Content](detections/network/detect_large_icmp_traffic.yml)*
