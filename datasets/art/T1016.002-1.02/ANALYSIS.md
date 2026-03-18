# T1016.002-1: Wi-Fi Discovery — Enumerate Stored Wi-Fi Profiles and Passwords via netsh

## Technique Context

T1016.002 Wi-Fi Discovery targets the wireless network profiles stored on a Windows device. When a user connects to a Wi-Fi network, Windows stores the SSID, security type, and — if the profile was added with key material — the pre-shared key or EAP credentials. The `netsh wlan show profile * key=clear` command retrieves all stored wireless profiles and their cleartext credentials. On laptops that have connected to home networks, hotel Wi-Fi, or corporate wireless, this can yield credentials directly or reveal historically visited locations.

This technique is frequently used in post-compromise operations against laptops and mobile workstations. Even if the current machine is only connected via Ethernet, past Wi-Fi credentials stored in profiles can be valuable for credential reuse, network mapping, or operational security intelligence. The command requires Administrator or SYSTEM-level access to read credentials, which is typically already present in post-compromise contexts.

The technique executes identically with or without Defender — `netsh.exe` is a trusted binary and the `wlan` subcommand group is legitimate administrative functionality. Both the defended and undefended variants produced the same result: `netsh.exe` ran but found no wireless profiles (exit code `0x1`), because this is a desktop workstation (`ACME-WS06`) rather than a laptop.

## What This Dataset Contains

The dataset spans approximately 3 seconds (22:57:47 to 22:57:50), capturing a clean and straightforward execution. The Security channel's 5 EID 4688 events show the complete process chain:

- Parent PowerShell (PID `0x474`) spawns `whoami.exe` for user discovery
- PowerShell spawns `cmd.exe` (PID `0x1e5c`) with `"cmd.exe" /c netsh wlan show profile * key=clear`
- That cmd.exe spawns `netsh.exe` (PID `0x1f88`) with `netsh wlan show profile * key=clear`
- PowerShell spawns a second `whoami.exe` and a cleanup `cmd.exe /c` afterward

All processes run as NT AUTHORITY\SYSTEM (subject `S-1-5-18`, logon `0x3e7`). The `netsh wlan show profile` command and the exact syntax `* key=clear` are captured clearly in the EID 4688 events.

The Security channel is dominated by 588 EID 4664 (hard link creation) events. These reflect the Windows Servicing Stack (via `C:\Windows\WinSxS\amd64_userexperience-fileexp_31bf3856ad364e35_10...`) creating hard links as part of a Windows Update operation running concurrently. This is a large volume of background activity that coincides with the test window but is unrelated to the technique.

The Sysmon channel shows 8 EID 7 (ImageLoad) events for `powershell.exe` (PID 7000) loading the .NET CLR stack — `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `clrjit.dll` — all tagged with `technique_id=T1055` as usual. Sysmon EID 1 shows 5 process create events and EID 10 shows 4 process access events from the test framework monitoring child processes. EID 17 captures the PowerShell named pipe creation.

Compared to the defended version (27 sysmon, 13 security, 34 PowerShell), the undefended run has 19 sysmon, 593 security, 104 PowerShell events. The dramatic security channel increase (13 → 593) is entirely due to the 588 EID 4664 hard link events from the concurrent Windows Update activity, not from the Wi-Fi discovery technique itself. The technique-specific telemetry is essentially identical.

## What This Dataset Does Not Contain

Since `ACME-WS06` is a desktop workstation rather than a laptop, there are no wireless profiles stored — the `netsh wlan show profile` command exits with code `0x1` and produces no output. The dataset therefore cannot show what successful Wi-Fi credential extraction looks like; it shows only the execution pattern.

There are no Sysmon EID 11 (FileCreate) events from the technique itself, since no wireless profile data was written to disk. There are no Sysmon EID 3 (network connection) events since the `wlan show` command is a local query. The PowerShell 4104 samples contain only boilerplate — the `cmd.exe /c netsh wlan show profile * key=clear` invocation is captured in Security 4688 but not in PowerShell script block events since the actual execution is in cmd.exe.

## Assessment

This is a compact, clean dataset focused entirely on the process execution pattern for Wi-Fi credential discovery. The Security EID 4688 command line `netsh wlan show profile * key=clear` is the primary detection surface and is clearly captured. The dataset is useful for building and testing detections that alert on this specific netsh usage pattern. The absence of actual wireless profiles limits its usefulness for testing detections of successful credential extraction — for that scenario, a dataset from a machine with stored Wi-Fi profiles would be needed. The background Windows Update activity (588 EID 4664 events) provides realistic tuning context.

## Detection Opportunities Present in This Data

1. Security EID 4688 showing `netsh.exe` created with arguments `wlan show profile` and `key=clear` is a high-confidence indicator. The `key=clear` parameter specifically requests cleartext credentials and has no legitimate administrative use case that would justify suppressing alerts on it.

2. The parent chain `powershell.exe → cmd.exe → netsh.exe` where cmd.exe carries `netsh wlan show profile * key=clear` can be matched as a behavioral sequence. The `*` wildcard (requesting all profiles) is more suspicious than querying a specific known SSID.

3. Sysmon EID 1 for `netsh.exe` with any command line containing `wlan show profile` and `key=clear` is the Sysmon equivalent of the EID 4688 detection, with additional enrichment fields (file hash, parent process GUID).

4. The pattern of `whoami.exe` immediately preceding `cmd.exe /c netsh wlan show profile * key=clear` from the same parent PowerShell process is the ART test framework reconnaissance-before-technique pattern — modeling this temporal sequence adds specificity.

5. For environments with wireless profile data, successful execution would generate PowerShell EID 4103 events showing the profile names and potentially credential data in the command output — monitoring for `netsh wlan` output containing `Key Content` strings in PowerShell output events would detect successful extraction.

6. `netsh.exe` spawned by any scripting engine (PowerShell, cmd.exe, wscript.exe, cscript.exe) with `wlan` subcommands is more suspicious than the same execution via an interactive terminal — the parent process relationship is a useful discriminator for tuning this detection.
