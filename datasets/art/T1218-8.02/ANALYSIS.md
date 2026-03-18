# T1218-8: System Binary Proxy Execution — DiskShadow Command Execution

## Technique Context

T1218 System Binary Proxy Execution includes the abuse of `DiskShadow.exe`, a Microsoft-signed command-line utility included with Windows Server and Windows 10/11 for managing Volume Shadow Copy Service (VSS) operations. DiskShadow can process a script file via its `-S` flag, executing a sequence of commands from a text file. When an attacker controls the content of that script file, they can embed `exec` directives that instruct DiskShadow to run arbitrary programs as part of what appears to be a shadow copy management operation.

The technique is effective against allowlisting controls because DiskShadow is a legitimate signed Windows binary expected to appear in administrative contexts. The `-S` flag processing turns DiskShadow into a general-purpose command interpreter for the commands in the supplied text file. In this test, the script file is `C:\AtomicRedTeam\atomics\T1218\src\T1218.txt`.

The execution runs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`. DiskShadow is typically found on Windows Server systems rather than workstations, so its presence on a workstation endpoint is itself an anomaly signal.

## What This Dataset Contains

The dataset spans approximately 5 seconds (2026-03-17T16:43:56Z–16:44:01Z) and contains 147 total events: 106 PowerShell events (105 EID 4104, 1 EID 4103), 4 Security events (all EID 4688), and 37 Sysmon events (25 EID 7, 4 EID 1, 4 EID 10, 3 EID 17, 1 EID 11).

The critical Sysmon EID 1 event captures a PowerShell child process with the command line: `"powershell.exe" & {C:\Windows\System32\diskshadow.exe -S C:\AtomicRedTeam\atomics\T1218\src\T1218.txt}` — tagged by Sysmon as `technique_id=T1218,technique_name=System Binary Proxy Execution`. This is the ART test framework spawning a new PowerShell process to invoke DiskShadow with the script file, rather than invoking DiskShadow directly via cmd.exe. The parent of this PowerShell process is the test framework `powershell` process running as SYSTEM.

This event structure differs from tests like T1218-3 where the technique binary (InfDefaultInstall.exe) appears as its own EID 1. Here, the Sysmon rule fires on the PowerShell process that wraps the DiskShadow invocation — because the test framework uses `& {<command>}` syntax to invoke DiskShadow within a PowerShell script block, the PowerShell process is what gets captured.

Three Sysmon EID 17 named pipe creation events capture PSHost pipes, indicating three distinct PowerShell hosting sessions active during this test window — the main test framework session and the child session(s) spawned for the technique invocation.

The 25 Sysmon EID 7 image load events reflect the DLL loading activity of both the test framework PowerShell session and the DiskShadow-invoking PowerShell process. DiskShadow itself loads various VSS-related DLLs that would appear in the full EID 7 stream.

One Sysmon EID 11 file creation event is present. The ART cleanup command `Invoke-AtomicTest T1218 -TestNumbers 8 -Cleanup -Confirm:$false` is visible in the PowerShell EID 4103 record.

Compared to the defended dataset (sysmon: 36, security: 12, powershell: 45), the undefended run has more Sysmon events (37 vs. 36) and fewer Security events (4 vs. 12). The near-parity in Sysmon counts suggests that DiskShadow execution generates a consistent level of process and DLL activity regardless of Defender's state. The larger Security event count in the defended run again reflects Defender-generated process activity.

## What This Dataset Does Not Contain

A Sysmon EID 1 process creation event for `DiskShadow.exe` itself is not present in the 20-event Sysmon sample. The sysmon-modular configuration does not appear to have an include rule that fires specifically on DiskShadow.exe process creation, so the binary's own appearance in the process list is not captured in the sample set (though it would be in the full raw stream if PowerShell's script block execution was followed through).

The content of `T1218.txt` — the DiskShadow script file containing the `exec` directive — is not visible in any event. Understanding what command DiskShadow was instructed to execute requires examining the file contents, which are not captured in any of the three telemetry channels.

No EID 1 events capture the process spawned by DiskShadow's `exec` directive. Whatever DiskShadow was instructed to run does not appear as a child process creation in the sample.

No network connection events (EID 3), registry modification events (EID 13), or DNS query events (EID 22) are present.

## Assessment

This dataset captures the technique's setup and test framework invocation effectively: the PowerShell process that calls `diskshadow.exe -S <path>` is present as a Sysmon EID 1 event with the full command line and the `-S` flag pointing to an attacker-controlled script file. This is the primary detection-relevant observable.

The gap in this dataset is the absence of DiskShadow.exe itself as a process creation event and the absence of whatever process DiskShadow spawns via its `exec` directive. In a real attack scenario, the spawned process would be the payload (a reverse shell, reconnaissance tool, or other capability), and its absence in the Sysmon sample is a meaningful gap for forensic completeness.

The three Sysmon EID 17 named pipe events provide useful temporal anchoring for the three PowerShell sessions, and the 25 EID 7 DLL load events characterize the DLL loading profile of DiskShadow execution. The undefended dataset's near-parity with the defended Sysmon event count is notable — DiskShadow generates consistent telemetry regardless of Defender's state.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — diskshadow.exe -S with non-standard script path:** The command line argument `-S C:\AtomicRedTeam\atomics\T1218\src\T1218.txt` identifies a DiskShadow script file at a non-standard path. Legitimate DiskShadow use in enterprise environments typically occurs via backup software that supplies its own script files from known, managed locations. Any DiskShadow invocation with `-S` pointing to a user-controlled path warrants investigation.

**DiskShadow.exe on a workstation endpoint:** DiskShadow is a server-grade VSS utility. Its presence and execution on a Windows 11 workstation, particularly when invoked from PowerShell running as SYSTEM, is anomalous. Legitimate workstation scenarios for DiskShadow execution are rare.

**PowerShell → PowerShell child process spawning DiskShadow:** The process chain PowerShell (SYSTEM) → PowerShell (SYSTEM, with diskshadow.exe embedded in command line) is not characteristic of legitimate backup or administrative operations. This level of nesting with a VSS utility embedded in a PowerShell script block argument is characteristic of deliberate LOLBAS use.

**Sysmon EID 17 — multiple PSHost named pipes:** Three concurrent PSHost named pipe creation events indicate multiple PowerShell hosting sessions open simultaneously. On a workstation in SYSTEM context, this pattern is more consistent with scripted/automated attack tooling than interactive administration.
