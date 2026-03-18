# T1059.001-10: PowerShell — Fileless Script Execution via Registry-Stored Payload

## Technique Context

T1059.001 PowerShell execution encompasses a range of techniques, and this test implements one of the more operationally sophisticated variants: storing a Base64-encoded PowerShell script in the Windows registry and executing it in-memory using `Invoke-Expression`. This "fileless" approach avoids writing script content to disk — the payload lives in the registry until execution time, at which point it is decoded and run entirely in memory. The registry serves as a persistence and staging mechanism while the in-memory execution avoids leaving a `.ps1` file on the filesystem.

This pattern is commonly used in real-world attacks for exactly the reasons it evades basic defenses: file-scanning antivirus has nothing to scan, forensic investigators examining the filesystem find no script, and endpoint protection tools focused on file activity miss the payload. Detection requires visibility into registry write operations (creating or modifying the key storing the payload), PowerShell script block logging (which captures the decoded content at execution time), and process command line monitoring (which captures the PowerShell invocation that reads and executes the registry value).

When Defender is enabled, AMSI intercepts the decoded payload before `Invoke-Expression` can run it. Without Defender, the decoded content executes, and PowerShell's script block logging captures the decoded script. The defended dataset showed 25 sysmon and 41 PowerShell events; this undefended version shows 23 and 96 respectively — the significantly higher PowerShell event count reflects the successful execution generating additional script block telemetry from the decoded payload.

## What This Dataset Contains

The dataset spans three seconds (2026-03-14T23:18:08Z to 23:18:11Z) and records 124 events across four channels: Sysmon (23), PowerShell (96), Security (4), and Application (1).

**Security EID 4688** provides the clearest command-line evidence. The technique invocation shows:

```
"powershell.exe" & {# Encoded payload in next command is the following "Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team"" <Base64 payload follows>}
```

The comment in the script block reveals the decoded payload: `Set-Content -path "$env:SystemRoot/Temp/art-marker.txt" -value "Hello from the Atomic Red Team"`. This is the actual payload that executes — writing a marker file to `C:\Windows\Temp\`. The cleanup command in the second Security EID 4688 event shows `Remove-Item -path C:\Windows\Temp\art-marker.txt` and `Remove-Item HKCU:\Software\Classes\AtomicRedTeam`, confirming that the payload was stored in `HKCU:\Software\Classes\AtomicRedTeam` in the registry.

**Sysmon EID 8 (CreateRemoteThread)** appears once. The source is `powershell.exe` and the target is `<unknown process>` with `StartAddress: 0x00007FF77E8753A0`, tagged `technique_id=T1055,technique_name=Process Injection`. This event indicates that the fileless execution involved in-memory code injection to a target process — consistent with `Invoke-Expression` executing code that performs process injection as part of its payload, or with the PowerShell test framework itself performing thread injection during execution.

**Sysmon EID 7 (ImageLoad)** contributes 14 events — slightly more than comparable tests — including the standard .NET DLL chain and Defender libraries.

**Sysmon EID 11 (FileCreate)** records a file created by `MsMpEng.exe` (the Defender scan engine): `C:\Windows\Temp\01dcb408d035a8c3`. This is a temporary file created by the Defender process during its scan of the Windows Temp directory, triggered by the `art-marker.txt` file that the payload wrote. Even though Defender is "disabled," MsMpEng.exe is still running in a passive state and creates temporary files during filesystem scanning. The presence of this file is an artifact of Defender's passive scanning, not an attack artifact.

**PowerShell EID 4104** contributes 93 events. The encoded payload, once decoded, creates additional script block logging entries beyond the boilerplate — these additional blocks represent the decoded `Set-Content` command and the registry storage/retrieval operations. The higher event count (96 vs. ~35 in defended tests for the same technique) reflects the decoded content executing successfully and generating its own telemetry.

**Application EID 15** (Windows Defender status update: `Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON`) is the notification that Defender's service state was toggled during the test run.

## What This Dataset Does Not Contain

No Sysmon EID 13 (RegistryValueSet) or EID 12 (RegistryCreateAndDelete) events appear, which means the registry key creation and modification (`HKCU:\Software\Classes\AtomicRedTeam`) is not captured in these samples. Registry monitoring is one of the primary detection vectors for this technique, and its absence here is a gap. Whether this reflects the Sysmon configuration filtering registry events for this path, or a sampling artifact, is unclear.

No explicit EID for `reg.exe` or PowerShell registry cmdlets appears in Sysmon process creation samples. The registry operations were performed entirely within the PowerShell process via cmdlets.

The PowerShell sample set does not show the actual decoded script block containing `Set-Content`. This is a sampling artifact — the full dataset contains it.

## Assessment

This dataset provides solid evidence of fileless registry-based execution at the command-line level (Security EID 4688) and behavioral level (Sysmon EID 8 / CreateRemoteThread). The cleanup command in Security EID 4688 reveals the registry key used (`HKCU:\Software\Classes\AtomicRedTeam`), which is valuable forensic information showing the staging location. The higher PowerShell EID 4104 event count compared to the defended version confirms successful payload execution.

The main gap is the absence of registry write events, which would complete the full kill-chain evidence. Analysts using this dataset for detection engineering should pair it with Windows Registry monitoring data to capture the storage step. The existing artifacts are sufficient for detecting the execution step, but not the staging step.

## Detection Opportunities Present in This Data

1. **`Invoke-Expression` or `IEX` combined with Base64 decoding in Security EID 4688 command line**: The command line references an encoded payload stored in the registry. Patterns like `[System.Convert]::FromBase64String`, `[System.Text.Encoding]::Unicode.GetString`, or `iex` combined with registry reads in PowerShell command lines are high-fidelity fileless execution indicators.

2. **Registry key `HKCU:\Software\Classes\AtomicRedTeam` or similar non-standard HKCU\Software\Classes paths**: The cleanup command in Security EID 4688 explicitly names the registry staging location. Monitoring for registry writes to `HKCU:\Software\Classes\` paths with non-standard names (not COM ProgIDs or extension associations) is a detection opportunity for fileless payload staging.

3. **Sysmon EID 8 (CreateRemoteThread) from powershell.exe with unknown target**: The injection event with `<unknown process>` target at `StartAddress: 0x00007FF77E8753A0` indicates successful in-memory code execution. This is the behavioral indicator that the fileless technique produced actual execution, not just script loading.

4. **PowerShell EID 4104 event count significantly exceeding baseline for a short execution window**: The 93 EID 4104 events in a 3-second window reflect both test framework boilerplate and decoded payload execution. An anomalously high script block event count for a brief PowerShell session may indicate payload execution generating additional blocks.

5. **C:\Windows\Temp writes followed by immediate deletion**: The payload writes `art-marker.txt` to `C:\Windows\Temp\` and the cleanup immediately deletes it. File creation followed by rapid deletion in system temp directories by a PowerShell process is a behavioral indicator of transient payload activity.

6. **MsMpEng.exe creating temporary files in C:\Windows\Temp**: Sysmon EID 11 captures Defender creating `C:\Windows\Temp\01dcb408d035a8c3` during passive scanning. Correlating Defender temp file creation with the timing of suspicious PowerShell activity helps establish that Defender scanned the written file, which in turn confirms file system contact occurred even in a "fileless" execution.
