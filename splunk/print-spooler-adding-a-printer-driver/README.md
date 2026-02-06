# Print Spooler Adding A Printer Driver

**Type:** TTP

**Author:** Mauricio Velazco, Michael Haag, Teoderick Contreras, Splunk

## Description

The following analytic detects the addition of new printer drivers by monitoring Windows PrintService operational logs, specifically EventCode 316. This detection leverages log data to identify messages indicating the addition or update of printer drivers, such as "kernelbase.dll" and "UNIDRV.DLL." This activity is significant as it may indicate exploitation attempts related to vulnerabilities like CVE-2021-34527 (PrintNightmare). If confirmed malicious, attackers could gain code execution or escalate privileges, potentially compromising the affected system. Immediate isolation and investigation of the endpoint are recommended.

## MITRE ATT&CK

- T1547.012

## Analytic Stories

- PrintNightmare CVE-2021-34527
- Black Basta Ransomware

## Data Sources

- Windows Event Log Printservice 316

## Sample Data

- **Source:** WinEventLog:Microsoft-Windows-PrintService/Operational
  **Sourcetype:** WinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1547.012/printnightmare/windows-printservice_operational.log


---

*Source: [Splunk Security Content](detections/endpoint/print_spooler_adding_a_printer_driver.yml)*
