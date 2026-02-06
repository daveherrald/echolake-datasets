# Windows Impair Defenses Disable HVCI

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the disabling of Hypervisor-protected Code Integrity (HVCI) by monitoring changes in the Windows registry. It leverages data from the Endpoint datamodel, specifically focusing on registry paths and values related to HVCI settings. This activity is significant because HVCI helps protect the kernel and system processes from tampering by malicious code. If confirmed malicious, disabling HVCI could allow attackers to execute unsigned kernel-mode code, potentially leading to kernel-level rootkits or other severe security breaches.

## MITRE ATT&CK

- T1562.001

## Analytic Stories

- BlackLotus Campaign
- Windows Defense Evasion Tactics
- Windows Registry Abuse

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1562.001/atomic_red_team/hvci_windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_impair_defenses_disable_hvci.yml)*
