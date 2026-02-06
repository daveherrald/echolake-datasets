# Windows Chrome Enable Extension Loading via Command-Line

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

The following analytic detects instances where Google Chrome is started with the --disable-features=DisableLoadExtensionCommandLineSwitch flag, effectively enabling the loading of extensions via the command line.
This may indicate attempts to bypass enterprise extension policies, load unauthorized or malicious extensions, or manipulate browser behavior.
Monitoring this activity helps identify potential security policy violations, malware persistence techniques, or other suspicious Chrome modifications.


## MITRE ATT&CK

- T1185

## Analytic Stories

- Browser Hijacking

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1185/chrome_load_extensions/chrome_load_extension.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_chrome_enable_extension_loading_via_command_line.yml)*
