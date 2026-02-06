# ESXi Malicious VIB Forced Install

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

Detects potentially malicious installation of VMware Installation Bundles (VIBs) using the --force flag. The --force option bypasses signature and compatibility checks, allowing unsigned, community-supported, or incompatible VIBs to be installed on an ESXi host. This behavior is uncommon in normal administrative operations and is often observed in post-compromise scenarios where adversaries attempt to install backdoored or unauthorized kernel modules, drivers, or monitoring tools to establish persistence or gain deeper control of the hypervisor.

## MITRE ATT&CK

- T1505.006

## Analytic Stories

- ESXi Post Compromise
- Black Basta Ransomware
- China-Nexus Threat Activity

## Data Sources

- VMWare ESXi Syslog

## Sample Data

- **Source:** vmware:esxlog
  **Sourcetype:** vmw-syslog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.006/esxi_malicious_vib/esxi_malicious_vib_forced_install.log


---

*Source: [Splunk Security Content](detections/application/esxi_malicious_vib_forced_install.yml)*
