# Linux Medusa Rootkit

**Type:** TTP

**Author:** Raven Tait, Splunk

## Description

This detection identifies file creation events associated with the installation of the Medusa rootkit, a userland LD_PRELOAD-based rootkit known for deploying shared objects, loader binaries, and configuration files into specific system directories. These files typically facilitate process hiding, credential theft, and backdoor access. Monitoring for such file creation patterns enables early detection of rootkit deployment before full compromise.

## MITRE ATT&CK

- T1014
- T1589.001

## Analytic Stories

- China-Nexus Threat Activity
- Medusa Rootkit
- Hellcat Ransomware
- VoidLink Cloud-Native Linux Malware

## Data Sources

- Sysmon for Linux EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1014/medusa_rootkit/sysmon_linux.log


---

*Source: [Splunk Security Content](detections/endpoint/linux_medusa_rootkit.yml)*
