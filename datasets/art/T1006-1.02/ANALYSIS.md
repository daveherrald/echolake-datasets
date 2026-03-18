# T1006-1: Direct Volume Access — Read volume boot sector via DOS device path (PowerShell)

## Technique Context

T1006 Direct Volume Access is a defense evasion technique where an attacker bypasses the standard Windows filesystem API by opening raw device objects directly. Instead of using `CreateFile` on a normal file path, the attacker opens `\\.\C:` (or `\\.\PhysicalDrive0`) through the DOS device namespace, which grants byte-level read access to the disk without going through the NTFS driver's access control layer. This means security products monitoring high-level file operations, AV engines scanning file reads, and NTFS-level permissions are all bypassed.

Common uses include reading files that are locked by the OS (like the SAM database or VSS shadow copies), recovering deleted files, or accessing the boot sector and partition structures. In this test, PowerShell opens `\\.\C:` as a `FileStream` and reads the first 11 bytes of the volume — confirming that the NTFS signature (`EB 52 90 4E 54 46 53 20 20 20 20` / `ebRNTFS`) is readable without any special filesystem permissions.

The technique is notable from a detection standpoint because it is largely invisible to file-monitoring controls. Sysmon's EID 11 (FileCreate) is not triggered by raw device reads. Detection requires monitoring at the process/command-line level or using kernel-mode telemetry that captures raw device I/O.

In the defended version, this test actually succeeded even with Defender enabled — Defender does not block raw volume access via `FileStream`. This undefended dataset therefore represents the same successful execution but with the Defender scanning overhead removed. The main difference is in the volume of concurrent OS activity rather than the technique outcome.

## What This Dataset Contains

The Security channel's EID 4688 events capture the complete execution. The key entry shows a child PowerShell spawning with the command line:

```
"powershell.exe" & {$buffer = New-Object byte[] 11
$handle = New-Object IO.FileStream "\\.\C:", 'Open', 'Read', 'ReadWrite'
$handle.Read($buffer, 0, $buffer.Length)
$handle.Close()
Format-Hex -InputObject $buffer}
```

This creates a `FileStream` directly against the raw device path `\\.\C:`, reads 11 bytes into a buffer, and pipes the result through `Format-Hex`. The defended dataset confirmed that the output `"00000000   EB 52 90 4E 54 46 53 20 20 20 20   ebRNTFS       "` was written to the PowerShell output, showing the NTFS signature was successfully read.

The Sysmon channel shows 14 EID 29 (File Executable Detected) events from `mpam-5817d33a.exe` (Windows Defender's signature update process running as `NT AUTHORITY\NETWORK SERVICE`) creating files in `C:\Windows\SERVIC~1\NETWOR~1\AppData\Local\Temp\` — these are Defender VDM update files running concurrently. The Application channel's EID 15 events confirm Defender updating its status to `SECURITY_PRODUCT_STATE_ON`, which is routine.

The Sysmon EID 1 event captures `whoami.exe` executing (PID 3696, parent PowerShell PID 1296) with the rule tag `technique_id=T1033`. Sysmon EID 7 (ImageLoad) shows Defender's update binary `mpam-5817d33a.exe` loading from the Network Service temp directory — flagged as `technique_id=T1574.002,technique_name=DLL Side-Loading` by the Sysmon ruleset, though this is the Defender update mechanism rather than an attack.

Compared to the defended version (27 sysmon, 10 security, 43 PowerShell), the undefended run has 98 sysmon events, 188 security events, and 93 PowerShell events — the increase is driven largely by concurrent Windows Update and Defender update activity rather than the technique itself producing additional telemetry.

## What This Dataset Does Not Contain

As expected with direct volume access, there are no Sysmon EID 11 (FileCreate) events showing the raw device read. The `\\.\C:` handle is opened and closed entirely in memory — no file path is created or modified, so file monitoring is silent. This absence is itself a detection signal: when a PowerShell process executes `IO.FileStream` against a device path, the lack of corresponding file creation telemetry distinguishes it from normal file I/O.

There are no network events (Sysmon EID 3) since this technique is purely local. There are no registry modifications. The PowerShell EID 4103 (CommandInvocation) events showing the actual `FileStream` creation and the hex output of the boot sector are not in the five sampled events, though 6 EID 4103 events exist in the full dataset and would contain this detail.

## Assessment

This dataset is well-suited for building detections around the PowerShell raw volume access pattern. The Security EID 4688 command line is the primary detection surface, capturing the `IO.FileStream` constructor call with `\\.\C:` as the path argument. The confirmed success of this technique in both the defended and undefended environments makes this dataset particularly useful for demonstrating what the telemetry looks like for a fully-executed technique. Defenders who focus on file-monitoring approaches will find this dataset valuable for understanding their blind spot with direct device access.

## Detection Opportunities Present in This Data

1. Security EID 4688 with a PowerShell command line containing `IO.FileStream` combined with a device path (`\\.\C:`, `\\.\PhysicalDrive`, or equivalent) is a high-fidelity indicator. The `New-Object IO.FileStream` pattern with device paths is nearly never seen in legitimate administrative scripts.

2. PowerShell EID 4104 ScriptBlock events containing `\\.\C:` or `\\.\PhysicalDrive` as string literals in the ScriptBlockText field — the full event stream (not just the samples) will contain this content.

3. PowerShell EID 4103 CommandInvocation events showing `Format-Hex` being called with a buffer argument shortly after a `FileStream` creation against a device path is a behavioral sequence indicator.

4. Sysmon EID 1 (ProcessCreate) for `powershell.exe` with the device path string in the command line, where the parent process is also PowerShell (parent-child powershell → powershell pattern) is characteristic of ART-style execution and should be investigated.

5. The absence of Sysmon EID 11 events from a PowerShell process that Security EID 4688 shows is performing file I/O can serve as a corroborating indicator — the process is accessing storage without triggering file creation monitoring, suggesting raw device access.

6. Access to the DOS device path `\\.\C:` can also be detected via Windows Kernel Trace or ETW-based monitoring of `IRP_MJ_CREATE` calls to device objects — outside the scope of this dataset, but worth noting as a complementary detection layer.
