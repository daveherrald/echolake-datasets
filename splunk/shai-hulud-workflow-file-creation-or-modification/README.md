# Shai-Hulud Workflow File Creation or Modification

**Type:** TTP

**Author:** Michael Haag, Splunk

## Description

Detects creation or deletion of malicious GitHub Actions workflow files associated with
Shai-Hulud worm variants on Linux or Windows endpoints. This includes the original shai-hulud-workflow.yml,
the 2.0 backdoor discussion.yaml (enables command injection via GitHub Discussions on self-hosted
runners named SHA1HULUD), and the secrets exfiltration workflow formatter_*.yml pattern. These
files are used to exfiltrate credentials and propagate across repositories.


## MITRE ATT&CK

- T1574.006
- T1554
- T1195

## Analytic Stories

- NPM Supply Chain Compromise

## Data Sources

- Sysmon for Linux EventID 11
- Sysmon EventID 11

## Sample Data

- **Source:** Syslog:Linux-Sysmon/Operational
  **Sourcetype:** sysmon:linux
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/npm/shai_hulud_workflow_sysmon.log

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1195.001/npm/windows_workflow_sysmon.log


---

*Source: [Splunk Security Content](detections/endpoint/shai_hulud_workflow_file_creation_or_modification.yml)*
