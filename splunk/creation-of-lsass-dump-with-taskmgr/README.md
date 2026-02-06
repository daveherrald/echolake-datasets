# Creation of lsass Dump with Taskmgr

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

The following analytic detects the creation of an lsass.exe process dump using Windows Task Manager. It leverages Sysmon EventID 11 to identify file creation events where the target filename matches *lsass*.dmp. This activity is significant because creating an lsass dump can be a precursor to credential theft, as the dump file contains sensitive information such as user passwords. If confirmed malicious, an attacker could use the lsass dump to extract credentials and escalate privileges, potentially compromising the entire network.

## MITRE ATT&CK

- T1003.001

## Analytic Stories

- Credential Dumping
- CISA AA22-257A
- Cactus Ransomware
- Seashell Blizzard
- Scattered Lapsus$ Hunters

## Data Sources

- Sysmon EventID 11

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1003.001/atomic_red_team/windows-sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/creation_of_lsass_dump_with_taskmgr.yml)*
