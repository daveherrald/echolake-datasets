# T1555.003-15: Credentials from Web Browsers — WebBrowserPassView - Credentials from Browser

## Technique Context

MITRE ATT&CK T1555.003 (Credentials from Web Browsers) includes the use of third-party credential recovery utilities. WebBrowserPassView is a GUI and command-line utility by NirSoft that decrypts and displays saved passwords from all major browsers including Chrome, Firefox, Internet Explorer, Edge, and Opera. It is a legitimate password recovery tool frequently abused by threat actors and included in many offensive toolkits. Unlike PowerShell-native staging approaches, WebBrowserPassView is a dedicated executable with browser-specific credential access logic built in.

With Defender disabled, WebBrowserPassView can launch, enumerate browser credential stores, and complete its operation without interception.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 11 seconds. It contains 147 events across four channels: 39 Sysmon, 100 PowerShell, 7 Security, and 1 Application.

**Command executed (Sysmon EID=1 and Security EID=4688):**
```
"powershell.exe" & {Start-Process "C:\AtomicRedTeam\atomics\T1555.003\bin\WebBrowserPassView.exe"
Start-Sleep -Second 4
Stop-Process -Name "WebBrowserPassView"}
```
The full command line appears verbatim in both Security EID=4688 and Sysmon EID=1. The test launches the tool, waits 4 seconds for it to complete its enumeration, then terminates it. Running as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`.

**Security EID=4688 — WebBrowserPassView process creation:** Unlike the defended dataset where the tool never fully started, here Security EID=4688 records `C:\AtomicRedTeam\atomics\T1555.003\bin\WebBrowserPassView.exe` as a new process with creator `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. The tool ran as SYSTEM.

**Security EID=5379 (Credential Manager credentials read):** This event records that the SYSTEM account performed an "Enumerate Credentials" read operation against Windows Credential Manager:
```
Subject: S-1-5-18 (ACME-WS06$)
Read Operation: Enumerate Credentials
```
This is a direct artifact of WebBrowserPassView enumerating the Windows Credential Manager as part of its browser credential recovery sweep.

**Security EID=5381 (Vault credentials read):** A vault credential enumeration event, confirming WebBrowserPassView also queried the Windows Vault:
```
Subject: S-1-5-18 (ACME-WS06$)
This event occurs when a user enumerates stored vault credentials
```

**Sysmon EID=10 (Process Access):** Five EID=10 events showing cross-process access patterns, including PowerShell accessing the WebBrowserPassView process handle.

**Sysmon EID=1 (Process Create):** `whoami.exe` (tagged T1033) and the child PowerShell executing the Start-Process block (tagged T1059.001).

**PowerShell script block logging (EID=4104):** 99 script block events capturing the full command with the path `C:\AtomicRedTeam\atomics\T1555.003\bin\WebBrowserPassView.exe`, the 4-second sleep, and the cleanup `Stop-Process`.

**Sysmon EID=17 (Pipe Created):** Three named pipe events from PowerShell console host infrastructure.

Note: EID=11 (file created) appears once in the full dataset — a PowerShell startup profile artifact from the SYSTEM account.

## What This Dataset Does Not Contain

**WebBrowserPassView in Sysmon EID=1.** The tool appears in Security EID=4688 but not in a Sysmon process create event. The sysmon-modular include-mode ProcessCreate filter does not match `WebBrowserPassView.exe` by name, so no Sysmon EID=1 fires for it. This is a meaningful gap to be aware of when designing detection logic that relies on Sysmon alone.

**Credential output files.** No Sysmon EID=11 events show credential dump files written to disk by WebBrowserPassView. The SYSTEM account profile contains no user browser installations, so WebBrowserPassView found no credentials to dump at the paths it checked. The EID=5379 and EID=5381 events confirm it ran and accessed Credential Manager, but no browser credential databases existed in the SYSTEM profile.

**Defender cloud lookup network connection.** In the defended dataset, a Sysmon EID=3 from `MpDefenderCoreService.exe` to `52.123.249.35:443` was a key indicator — Defender performing a reputation lookup on the WebBrowserPassView binary at launch. With Defender disabled, that network event is absent here.

**Comparison with the defended variant:** In the defended dataset (sysmon: 48, security: 11, powershell: 58), Defender blocked WebBrowserPassView before it fully started — no process creation for the tool appeared in Security 4688, and no EID=5379/5381 were generated. Here, all three of those events appear. The undefended dataset adds the WebBrowserPassView process creation in Security 4688, plus the credential enumeration events (5379, 5381), giving you direct evidence that the tool ran and accessed credential stores.

## Assessment

This dataset provides substantially more forensic value than the defended variant for studying WebBrowserPassView behavior. The Security EID=5379 (Credential Manager enumeration) and EID=5381 (Vault enumeration) are the most technique-specific events in this dataset — they directly record that a credential access operation occurred against Windows credential stores, attributable to the SYSTEM account in the timeframe of the tool's 4-second execution window.

The limitation is environmental: the SYSTEM context means no browser credentials were actually present to dump. The tool ran and completed its enumeration, but found nothing. For analysts focused on detection coverage, the process creation chain and the credential enumeration events provide solid anchors.

## Detection Opportunities Present in This Data

**Security EID=5379 — Credential Manager enumeration by SYSTEM:** The "Enumerate Credentials" read operation from `S-1-5-18` within a short execution window is a high-confidence indicator that a credential harvesting tool ran.

**Security EID=5381 — Vault credentials enumerated:** Vault enumeration in the same window as process creation for a credential-access tool strengthens the correlation.

**Security EID=4688 — WebBrowserPassView.exe process creation:** When command-line auditing is enabled, the process name and parent PowerShell relationship are directly visible in the process creation event.

**PowerShell EID=4104 — explicit path to credential tool:** The script block contains `C:\AtomicRedTeam\atomics\T1555.003\bin\WebBrowserPassView.exe` verbatim. Path references to known credential tools in script block logging are a reliable behavioral indicator.

**Sysmon EID=10 — PowerShell accessing WebBrowserPassView handle:** Cross-process access from the launching PowerShell instance to the credential tool process is consistent with attacker-controlled process management and can serve as a supplementary behavioral signal.
