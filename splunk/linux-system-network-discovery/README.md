# Linux System Network Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic identifies potential enumeration of local network configuration on Linux systems. It detects this activity by monitoring processes such as "arp," "ifconfig," "ip," "netstat," "firewall-cmd," "ufw," "iptables," "ss," and "route" within a 30-minute window. This behavior is significant as it often indicates reconnaissance efforts by adversaries to gather network information for subsequent attacks. If confirmed malicious, this activity could enable attackers to map the network, identify vulnerabilities, and plan further exploitation or lateral movement within the environment.

## MITRE ATT&CK

- T1016

## Analytic Stories

- Data Destruction
- Network Discovery
- Industroyer2
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/atomic_red_team/linux_net_discovery/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_system_network_discovery.yml)*
