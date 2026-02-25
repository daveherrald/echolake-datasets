# Windows IIS Components Get-WebGlobalModule Module Query

**Type:** Hunting

**Author:** Michael Haag, Splunk

## Description

This dataset contains sample data for identifying the execution of the PowerShell cmdlet Get-WebGlobalModule, which lists all IIS Modules installed on a system. It leverages PowerShell input data to detect this activity by capturing the module names and the image paths of the DLLs. This activity is significant for a SOC because it can indicate an attempt to enumerate installed IIS modules, which could be a precursor to exploiting vulnerabilities or misconfigurations. If confirmed malicious, this could allow an attacker to gain insights into the web server's configuration, potentially leading to further exploitation or privilege escalation.

## MITRE ATT&CK

- T1505.004

## Analytic Stories

- GhostRedirector IIS Module and Rungan Backdoor
- IIS Components
- WS FTP Server Critical Vulnerabilities

## Data Sources

- Powershell Installed IIS Modules

## Sample Data

- **Source:** powershell://AppCmdModules
  **Sourcetype:** Pwsh:InstalledIISModules
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1505.004/pwsh_installediismodules.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_iis_components_get_webglobalmodule_module_query.yml)*


## License

Detection logic: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/security_content](https://github.com/splunk/security_content)). Sample attack data: [Apache License 2.0](https://www.apache.org/licenses/LICENSE-2.0) ([splunk/attack_data](https://github.com/splunk/attack_data)). Both by Splunk, Inc.
