# Linux Iptables Firewall Modification

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious command-line activity that modifies the iptables firewall settings on a Linux machine. It leverages data from Endpoint Detection and Response (EDR) agents, focusing on specific command patterns that alter firewall rules to accept traffic on certain TCP ports. This activity is significant as it can indicate malware, such as CyclopsBlink, modifying firewall settings to allow communication with a Command and Control (C2) server. If confirmed malicious, this could enable attackers to maintain persistent access and exfiltrate data, posing a severe security risk.

## MITRE ATT&CK

- T1562.004

## Analytic Stories

- China-Nexus Threat Activity
- Backdoor Pingpong
- Cyclops Blink
- Sandworm Tools

## Data Sources

- Sysmon for Linux EventID 1

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/malware/cyclopsblink/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_iptables_firewall_modification.yml)*
