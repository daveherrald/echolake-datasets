# Cisco Smart Install Oversized Packet Detection

**Type:** TTP

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

This analytic detects oversized Cisco Smart Install (SMI) protocol messages by inspecting traffic to TCP port 4786
within the Network_Traffic data model. Abnormally large SMI payloads have been associated with exploitation and
protocol abuse (e.g., CVE-2018-0171; activity reported by the "Static Tundra" threat actor). Monitoring message
sizes over time can help identify possible attempts at remote code execution, denial of service, or reconnaissance
against Cisco devices exposing Smart Install.


## MITRE ATT&CK

- T1190

## Analytic Stories

- Cisco Smart Install Remote Code Execution CVE-2018-0171

## Data Sources

- Splunk Stream TCP

## Sample Data

- **Source:** stream:tcp
  **Sourcetype:** stream:tcp
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/cisco/cisco_smart_install/stream_tcp.log


---

*Source: [Splunk Security Content](detections/network/cisco_smart_install_oversized_packet_detection.yml)*
