# Linux Auditd System Network Configuration Discovery

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects suspicious system network configuration discovery activities, which may indicate an adversary's attempt to gather information about the network environment. Such actions typically involve commands or tools used to identify network interfaces, routing tables, and active connections. Detecting these activities is crucial, as they often precede more targeted attacks like lateral movement or data exfiltration. By identifying unusual or unauthorized network discovery efforts, this analytic helps security teams to swiftly detect and respond to potential reconnaissance operations, mitigating the risk of further compromise.

## MITRE ATT&CK

- T1016

## Analytic Stories

- Linux Living Off The Land
- Linux Privilege Escalation
- Linux Persistence Techniques
- Compromised Linux Host

## Data Sources

- Linux Auditd Syscall

## Sample Data

- **Source:** auditd
  **Sourcetype:** auditd
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1016/linux_auditd_net_tool_new/linux_auditd_net_tool_bucket_new.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_auditd_system_network_configuration_discovery.yml)*
