# Windows RDP Server Registry Deletion

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies the deletion of registry keys under HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers\, which store records of previously connected remote systems via Remote Desktop Protocol (RDP). These keys are created automatically when a user connects to a remote host using the native Windows RDP client (mstsc.exe) and can be valuable forensic artifacts for tracking remote access activity. Malicious actors aware of this behavior may delete these keys after using RDP to hide evidence of their activity and avoid detection during incident response. This form of artifact cleanup is a known defense evasion technique, often performed during or after lateral movement. Legitimate users rarely delete these keys manually, making such actions highly suspicious—especially when correlated with RDP usage, unusual logon behavior, or other signs of compromise. Detecting the deletion of these registry entries can provide crucial insight into attempts to cover tracks following interactive remote access.

## MITRE ATT&CK

- T1070.004

## Analytic Stories

- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 12
- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1070.004/terminal_server_reg_deleted/terminal_server_client_reg_deleted.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_server_registry_deletion.yml)*
