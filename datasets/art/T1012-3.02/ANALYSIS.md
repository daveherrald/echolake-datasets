# T1012-3: Query Registry — Enumerate COM Objects in Registry with PowerShell

## Technique Context

T1012 Query Registry covers adversaries reading the Windows registry to gather system intelligence. This test targets a specific and information-rich registry location: `HKEY_CLASSES_ROOT\CLSID`, which contains entries for every registered Component Object Model (COM) object on the system. COM objects underpin a large portion of Windows functionality — from shell extensions to ActiveX controls to WMI providers — and their enumeration reveals what software is installed, which COM servers are available for potential hijacking (T1546.015), and what automation interfaces an attacker might leverage without dropping additional tools.

The technique goes further than simple enumeration. After listing all CLSIDs and writing them to `%TEMP%\clsids.txt`, the script attempts to instantiate each COM object using `[activator]::CreateInstance([type]::GetTypeFromCLSID($CLSID))` and then calls `get-member` on the resulting object to enumerate its exposed methods and properties, writing results to `%TEMP%\T1592.002Test1.txt`. This turns passive registry enumeration into active capability discovery — the attacker learns not just what COM objects exist but what each one can do.

A side effect of this approach is that it actually instantiates COM servers, which can spawn child processes (like `ielowutil.exe` for Internet Explorer's COM server) and make network calls. This makes the technique noisier than a pure registry read. Detection focuses on the PowerShell command line targeting `HKCR:\CLSID`, the high volume of EID 4103 events from the per-CLSID loop, and child process activity from COM server instantiation.

## What This Dataset Contains

This dataset has by far the most events in this batch: 38,339 Security events, 1,127 Sysmon events, 1,493 PowerShell events, spanning from 22:53:52 to 22:55:56 — a nearly 2-minute execution window that reflects the time needed to iterate hundreds of COM CLSIDs.

The Security EID 4688 sample captures the complete PowerShell command line:

```
"powershell.exe" & {New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT -Name HKCR;
Get-ChildItem -Path HKCR:\CLSID -Name | Select -Skip 1 > $env:temp\clsids.txt;
ForEach($CLSID in Get-Content "$env:temp\clsids.txt"){...}}
```

And a second 4688 shows the cleanup: `"powershell.exe" & {remove-item $env:temp\T1592.002Test1.txt -force -erroraction silentlycontinue; remove-item $env:temp\clsids.txt -force -erroraction silentlycontinue}` — confirming both output files were created and cleaned up.

The most striking feature of this dataset is the Security channel's 27,118 EID 4663 (object access attempt) events and 10,639 EID 4660 (object deleted) events. These reflect the COM object instantiation loop triggering access auditing as COM servers are created and torn down across the hundreds of CLSID iterations. The 473 EID 4907 events record security descriptor changes — also byproducts of COM server lifecycle events. This volume of security events is itself a detection signal.

Sysmon EID 2 (File Timestamp Changed) contributes 876 events — the dominant event type in the Sysmon channel. These likely reflect COM server DLL loading and timestamp normalization side effects from the `dismhost.exe` process (`C:\$WinREAgent\Scratch\...`) which is writing files to the WinRE agent scratch directory concurrently. The WMI channel's EID 5858 records a query error: `SELECT State FROM Win32_Service` with result `0x80041032` (asynchronous provider not ready) — WMI being invoked as part of the COM enumeration or a background service check.

The TaskScheduler channel's EID 140 records `ACME\ACME-WS06$` updating the `\Microsoft\Windows\SoftwareProtectionPlatform\SvcRestartTask`, which is the Software Protection Platform rescheduling itself — a routine background event coinciding with the test window.

The defended version had 1,421 PowerShell events — nearly identical to the undefended run's 1,493. The primary difference is the security channel: 38,339 events vs. 54, driven by the object access auditing on COM servers. This suggests the undefended VM had different audit policy configuration (Object Access auditing enabled) rather than the COM objects themselves behaving differently.

## What This Dataset Does Not Contain

The Sysmon EID 1 samples show only `dismhost.exe` activity (WinRE agent operations), not the `powershell.exe` process creation for the COM enumeration itself or the child processes spawned by COM server instantiation (like `ielowutil.exe` or `iexplore.exe` with CLSID arguments). These process creations are present in the full 12 Sysmon EID 1 events but not in the 5 sampled events.

There are no Sysmon EID 3 (network connection) events in the samples, though COM server instantiation can trigger network connections (e.g., Internet Explorer COM objects may try to reach out to networks). The full dataset may contain these.

The actual CLSID enumeration output (`clsids.txt`) and method enumeration output (`T1592.002Test1.txt`) were cleaned up and are not retained in the telemetry.

## Assessment

This dataset is exceptionally rich for building detections around mass COM object enumeration. The combination of the EID 4688 command line evidence, the high-volume EID 4103 pattern from the per-CLSID loop, the Security channel object access auditing storm (27K EID 4663 events), and the child process spawning from COM server instantiation provides multiple independent detection surfaces. The two-minute execution window and cleanup commands also provide a complete lifecycle view. This is one of the more complete datasets in this batch for building behavioral analytics.

## Detection Opportunities Present in This Data

1. Security EID 4688 with a PowerShell command line containing `New-PSDrive -PSProvider registry -Root HKEY_CLASSES_ROOT` combined with `Get-ChildItem -Path HKCR:\CLSID` is specific to CLSID enumeration and rarely seen in legitimate administrative work.

2. A rapid burst of 1,000+ PowerShell EID 4103 CommandInvocation events within a 2-minute window from a single PowerShell process suggests automated bulk enumeration rather than interactive use — volume thresholding is an effective detection approach here.

3. The sequence in EID 4104 ScriptBlock events: `New-PSDrive` for HKCR, followed by `Get-ChildItem HKCR:\CLSID`, followed by file creation in `%TEMP%`, followed by a ForEach loop with `[activator]::CreateInstance` — this specific multi-step pattern is the COM enumeration fingerprint.

4. Sysmon EID 11 creating `clsids.txt` in `%TEMP%` combined with subsequent creation of `T1592.002Test1.txt` in the same directory from the same PowerShell process is a file artifact indicator.

5. Security EID 4663 volume exceeding several thousand events within a 2-minute window from a single process is anomalous — normal admin operations don't generate this density of object access audit events.

6. Child process spawning of `ielowutil.exe` or `iexplore.exe` with `-CLSID:` arguments in the command line from a PowerShell parent is a secondary indicator of COM object instantiation being driven by a script (Sysmon EID 1 or Security EID 4688).

7. Security EID 4688 showing a cleanup command (`remove-item ... clsids.txt ... T1592.002Test1.txt`) immediately after the enumeration in the same PowerShell session confirms file artifacts were created and suggests intentional anti-forensics.
