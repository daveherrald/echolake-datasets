# Print Spooler Failed to Load a Plug-in

**Type:** TTP

**Author:** Mauricio Velazco, Michael Haag, Splunk

## Description

The following analytic detects driver load errors in the Windows PrintService Admin logs, specifically identifying issues related to CVE-2021-34527 (PrintNightmare). It triggers on error messages indicating the print spooler failed to load a plug-in module, such as "meterpreter.dll," with error code 0x45A. This detection method leverages specific event codes and error messages. This activity is significant as it may indicate an exploitation attempt of a known vulnerability. If confirmed malicious, an attacker could gain unauthorized code execution on the affected system, leading to potential system compromise.

## MITRE ATT&CK

- T1547.012

## Analytic Stories

- PrintNightmare CVE-2021-34527
- Black Basta Ransomware

## Data Sources

- Windows Event Log Printservice 808
- Windows Event Log Printservice 4909

## Sample Data

- **Source:** WinEventLog:Microsoft-Windows-PrintService/Admin
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-printservice_admin.log


---

*Source: [Splunk Security Content](detections/endpoint/print_spooler_failed_to_load_a_plug_in.yml)*
