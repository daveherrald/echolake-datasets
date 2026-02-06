# Cisco Smart Install Port Discovery and Status

**Type:** TTP

**Author:** Bhavin Patel, Michael Haag, Splunk

## Description

This analytic detects network traffic to TCP port 4786, which is used by the Cisco Smart Install protocol. Smart Install is a plug-and-play configuration and image-management feature that helps customers to deploy Cisco switches. This protocol has been exploited via CVE-2018-0171, a vulnerability that allows unauthenticated remote attackers to execute arbitrary code or cause denial of service conditions. Recently, Cisco Talos reported that a Russian state-sponsored threat actor called "Static Tundra" has been actively exploiting this vulnerability to compromise unpatched and end-of-life network devices. Monitoring for traffic to this port can help identify potential exploitation attempts or unauthorized Smart Install activity.

## MITRE ATT&CK

- T1190

## Analytic Stories

- Scattered Lapsus$ Hunters
- Cisco Smart Install Remote Code Execution CVE-2018-0171

## Data Sources

- Splunk Stream TCP

## Sample Data

- **Source:** stream:tcp
  **Sourcetype:** stream:tcp
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1190/cisco/cisco_smart_install/stream_tcp.log


---

*Source: [Splunk Security Content](detections/network/cisco_smart_install_port_discovery_and_status.yml)*
