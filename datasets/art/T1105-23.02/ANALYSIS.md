# T1105-23: Ingress Tool Transfer — Lolbas replace.exe use to copy file

## Technique Context

T1105 (Ingress Tool Transfer) covers the movement of tools and files from one location into a compromised environment. While most attention focuses on network-based downloads, adversaries regularly abuse signed Windows binaries to accomplish the same goal—specifically to sidestep controls that target unsigned executables or outbound HTTP.

Replace.exe is a legitimate Windows file utility, present in every Windows installation at `C:\Windows\System32\replace.exe`, designed to replace files with newer versions. Its `/A` (add) flag changes its behavior: it copies a file to the destination directory even if no existing copy is present. This transforms a mundane maintenance utility into a file staging tool, and because replace.exe is a signed Microsoft binary with a legitimate description ("Replace File Utility"), it tends to attract less scrutiny than a downloaded payload.

This test copies a test `.cab` file using the replace.exe `/A` flag—a representative demonstration of how an adversary might use LOLBin file transfer to stage tools in a writable directory like `%TEMP%`.

## What This Dataset Contains

This dataset was collected on ACME-WS06, a Windows 11 Enterprise domain workstation with Microsoft Defender disabled, ensuring the technique executed to completion without defensive interruption.

**Process Chain (Security EID 4688):**

The execution chain is fully visible across both Security and Sysmon logs. PowerShell (PID 7072) spawns `cmd.exe` with the full attack command:

```
"cmd.exe" /c del %TEMP%\redcanary.cab >nul 2>&1 & C:\Windows\System32\replace.exe "C:\AtomicRedTeam\atomics\T1105\src\redcanary.cab" %TEMP% /A
```

`cmd.exe` (PID 4176) then spawns replace.exe:

```
C:\Windows\System32\replace.exe  "C:\AtomicRedTeam\atomics\T1105\src\redcanary.cab" C:\Windows\TEMP /A
```

**Sysmon Process Creation (EID 1):**

Both cmd.exe (tagged `technique_id=T1059.003`) and replace.exe (tagged `technique_id=T1218`) appear with full command lines, hashes, and parent process attribution. Replace.exe carries SHA1=57070ACE005360C9D374C7AAB78E2F84F1BB3389, MD5=CBA41C2FEA30BDAAE86EF9D11A7F244C.

**File Creation (Sysmon EID 11):**

The payload file `C:\Windows\Temp\redcanary.cab` is created by replace.exe (PID 5608) at 2026-03-14 23:45:22.626, confirming successful transfer. This file creation event is the most direct evidence that the technique achieved its objective.

**Image Loads (Sysmon EID 7):**

Nine DLL load events capture PowerShell's .NET runtime initialization: `mscoree.dll`, `mscoreei.dll`, `clr.dll`, `clrjit.dll`, `mscorlib.ni.dll`, `System.Management.Automation.ni.dll`, and Windows Defender's `MpOAV.dll` and `MpClient.dll`. The Defender DLL loads appear even with Defender disabled—these reflect the passive loading of the AV integration interface by PowerShell, not active scanning.

**Named Pipe (Sysmon EID 17):**

A PSHost pipe `\PSHost.134180055177052185.7072.DefaultAppDomain.powershell` is created by the PowerShell test framework process (PID 7072).

**Process Access (Sysmon EID 10):**

PowerShell (PID 7072) opens `whoami.exe` and `cmd.exe` with access rights `0x1FFFFF` (PROCESS_ALL_ACCESS). This is the ART test framework calling `Start-Process` and waiting for child processes to complete—a consistent pattern across all ART-executed tests.

**PowerShell Script Block Logging (EID 4104):**

93 script block events capture the ART framework internals. The first several are standard error-handling stubs (`$_.PSMessageDetails`, `$_.ErrorCategory_Message`), followed by Invoke-AtomicRedTeam module code.

**Application Log (EID 15):**

An Application log entry records Windows Security Center updating Defender's status to `SECURITY_PRODUCT_STATE_ON`, reflecting the Defender re-enable action that occurs as part of the broader test run sequence.

## What This Dataset Does Not Contain

There is no network connection evidence here—this is a local file copy operation. The source file already existed at `C:\AtomicRedTeam\atomics\T1105\src\redcanary.cab`; no download preceded it.

Sysmon is not configured to log file reads, so you will not see replace.exe reading from the source path. The dataset does not include a Sysmon EID 23 (file delete) for the cleanup `del %TEMP%\redcanary.cab` command that runs first, as that event type is not in the collection profile.

No network telemetry (Sysmon EID 3) is present. There are no registry modifications. The dataset covers a 5-second window (23:45:18Z–23:45:23Z).

## Assessment

This dataset is a clean, complete capture of the replace.exe LOLBin file transfer pattern. You have the full process chain from PowerShell through cmd.exe to replace.exe, command lines on both Security 4688 and Sysmon EID 1, a file creation event confirming the payload landed in `%TEMP%`, and hashes for replace.exe itself.

Compared to the defended variant, the undefended dataset contains fewer Security channel events (4 vs. 14) and the same Sysmon count (18). The defended dataset's higher Security event count reflects additional process creation logging generated during Defender's scanning activity. The core technique evidence—cmd.exe command line with `/A` flag, replace.exe process create, and the file creation at `C:\Windows\Temp\redcanary.cab`—is present in both variants.

## Detection Opportunities Present in This Data

**Replace.exe with /A flag (EID 1 / EID 4688):** The command line `replace.exe <source_path> <dest_dir> /A` is highly anomalous in enterprise environments. Replace.exe rarely appears in process telemetry at all; its invocation from a `cmd.exe /c` chain spawned by PowerShell with the `/A` flag should be treated as high-fidelity.

**Parent-child chain:** `powershell.exe → cmd.exe → replace.exe` with a combined command that first deletes a file then copies it is characteristic of scripted LOLBin staging.

**File creation in %TEMP% by replace.exe (EID 11):** A file appearing in `C:\Windows\Temp\` created by `replace.exe` is not a pattern associated with any legitimate software use case visible in this dataset.

**Sysmon RuleName tags:** Sysmon's built-in ruleset tags replace.exe as `technique_id=T1218,technique_name=System Binary Proxy Execution`—this tag appears on the EID 1 process creation event and provides immediate classification without custom rules.
