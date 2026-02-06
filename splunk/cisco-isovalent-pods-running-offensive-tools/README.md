# Cisco Isovalent - Pods Running Offensive Tools

**Type:** Anomaly

**Author:** Bhavin Patel, Splunk

## Description

The following analytic detects execution of known offensive tooling from within Kubernetes pods, including network scanners and post-exploitation frameworks (e.g., nmap, masscan, zmap, impacket-*, hashcat, john, SharpHound, kube-hunter, peirates). We have created a macro named `linux_offsec_tool_processes` that contains the list of known offensive tooling found on linux systems. Adversaries commonly introduce these tools into compromised workloads to conduct discovery, lateral movement, credential access, or cluster reconnaissance. This behavior may indicate a compromised container or supply-chain abuse. Extra scrutiny is warranted for namespaces that do not typically run diagnostic scanners and for pods that suddenly begin invoking these binaries outside of normal maintenance activity.

## MITRE ATT&CK

- T1204.003

## Analytic Stories

- Cisco Isovalent Suspicious Activity

## Data Sources

- Cisco Isovalent Process Exec

## Sample Data

- **Source:** not_applicable
  **Sourcetype:** cisco:isovalent:processExec
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/cisco_isovalent/cisco_isovalent.log


---

*Source: [Splunk Security Content](detections/endpoint/cisco_isovalent___pods_running_offensive_tools.yml)*
