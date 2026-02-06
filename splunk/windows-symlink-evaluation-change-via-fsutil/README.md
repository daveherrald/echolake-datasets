# Windows Symlink Evaluation Change via Fsutil

**Type:** Anomaly

**Author:** Nasreddine Bencherchali, Splunk

## Description

This analytic detects the execution of the Windows built-in tool Fsutil.exe with
the "behavior", "set" and "SymlinkEvaluation" parameters.
Attackers can abuse this to alter symlink evaluation behavior on Windows, potentially enabling remote traversal over SMB shares or evading defenses. 
Such changes should be uncommon or even rare in enterprise environments and should be investigated.


## MITRE ATT&CK

- T1222.001

## Analytic Stories

- Windows Post-Exploitation

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1222.001/fsutil_symlink_eval/fsutil_symlink_eval.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_symlink_evaluation_change_via_fsutil.yml)*
