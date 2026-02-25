# Windows Chromium Browser No Security Sandbox Process

**Type:** TTP

**Author:** Teoderick Contreras, Splunk

## Description

This dataset contains sample data for detecting instances where a Chrome or Chromium-based browser is launched with the --no-sandbox flag, a known indicator of potentially malicious or suspicious behavior. While this flag is occasionally used during software development or testing, it is rarely seen in normal user activity. Threat actors often abuse this setting to disable Chrome's built-in security sandbox, making it easier to execute malicious code or escape browser isolation. This behavior is commonly observed in malware droppers or loaders that embed Chromium components for command and control, credential theft, or UI spoofing. Analysts should investigate such events, especially if they originate from unusual parent processes (e.g., powershell.exe, cmd.exe, or unknown binaries), or if accompanied by other indicators such as file drops, process injection, or outbound network activity. Filtering by command-line arguments and process ancestry can help reduce false positives and surface high-fidelity detections.


## MITRE ATT&CK

- T1497

## Analytic Stories

- Malicious Inno Setup Loader

## Data Sources

- Sysmon EventID 1
- Windows Event Log Security 4688
- CrowdStrike ProcessRollup2

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1497/chrom_no_sandbox/chrome-no_sandbox.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_chromium_browser_no_security_sandbox_process.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
