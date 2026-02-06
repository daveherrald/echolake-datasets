# Windows RDP Server Registry Entry Created

**Type:** Anomaly

**Author:** Teoderick Contreras, Splunk

## Description

This detection identifies the creation of registry keys under HKEY_CURRENT_USER\Software\Microsoft\Terminal Server Client\Servers\, which occur when a user initiates a Remote Desktop Protocol (RDP) connection using the built-in Windows RDP client (mstsc.exe). These registry entries store information about previously connected remote hosts, including usernames and display settings. Their creation is a strong indicator that an outbound RDP session was initiated from the system. While the presence of these keys is normal during legitimate RDP use, their appearance can be used to track remote access activity, especially in environments where RDP is tightly controlled. In post-compromise scenarios, these artifacts may be created by threat actors using RDP for lateral movement or command-and-control. Monitoring the creation of these registry entries can help defenders detect initial use of RDP from a compromised host, particularly when correlated with unusual user behavior, logon patterns, or network activity.

## MITRE ATT&CK

- T1021.001

## Analytic Stories

- Windows RDP Artifacts and Defense Evasion

## Data Sources

- Sysmon EventID 13

## Sample Data

- **Source:** XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
  **Sourcetype:** XmlWinEventLog
  **URL:** https://media.githubusercontent.com/media/splunk/attack_data/master/datasets/attack_techniques/T1021.001/terminal_server_reg_created/terminal_sever_client_Reg_created.log


---

*Source: [Splunk Security Content](detections/endpoint/windows_rdp_server_registry_entry_created.yml)*
