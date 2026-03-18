# T1490-13: Inhibit System Recovery — Delete Volume Shadow Copies via Diskshadow

## Technique Context

T1490 (Inhibit System Recovery) covers adversary actions that prevent system restoration after an attack. Deleting Volume Shadow Copies (VSCs) is the single most reliable pre-encryption step in ransomware operations — it eliminates the snapshots that Windows and third-party backup tools use for point-in-time recovery, ensuring that encryption cannot be reversed by simply rolling back to a shadow copy.

Test T1490-13 uses `diskshadow.exe` to delete all shadow copies by piping the command string directly to the binary: `"delete shadows all" | diskshadow.exe`. This approach is notable for two reasons. First, `diskshadow.exe` is a Microsoft-signed binary (a Living Off the Land Binary, or LOLBin) with legitimate use in the VSS service administration, making process-name-based detections insufficient. Second, because the deletion command is passed via stdin rather than as a command-line argument, signature-based detections that inspect only the `diskshadow.exe` command-line argument string will not see `delete shadows all` there — it would appear as no arguments at all.

In the defended variant, Defender blocked the execution. This undefended dataset captures what happens when `diskshadow.exe` runs without interference.

## What This Dataset Contains

**Security EID 4688** records the decisive event. PowerShell spawns a child `powershell.exe` process with:

```
"powershell.exe" & {"delete shadows all" | diskshadow.exe}
```

This command uses the PowerShell pipeline operator to send the string `"delete shadows all"` as stdin to `diskshadow.exe`. The child PowerShell process exits with `0x0` — the deletion command was accepted and executed. All shadow copies on this system were deleted.

Note that `diskshadow.exe` itself does not appear as a separate Security EID 4688 process creation event. When PowerShell uses the `|` operator to pipe to an external executable, the executable is spawned as a child process but the Security log auditing does not consistently record this as a separate 4688 event in this execution environment. The parent `powershell.exe` command line is the primary evidence.

**Sysmon EID 1** captures two ProcessCreate events: the test framework `whoami.exe` and the technique child `powershell.exe` with the full piped command. The child PowerShell is tagged `technique_id=T1059.001,technique_name=PowerShell`. As with Security EID 4688, `diskshadow.exe` itself does not appear as a Sysmon EID 1 event because the sysmon-modular include-mode ProcessCreate filter does not have a matching rule for `diskshadow.exe`.

**Sysmon EID 17** (PipeCreate): Three named pipe events are present. Two capture the PowerShell host pipes (`\PSHost.*.DefaultAppDomain.powershell`) for the parent and child PowerShell sessions. These are the most reliable secondary indicator in this dataset that two separate PowerShell sessions ran.

**Sysmon EID 7** (ImageLoad): 25 DLL load events document the full .NET and PowerShell assembly stack. The high count (25 events) compared to simpler tests is consistent with `diskshadow.exe` loading additional COM components as it interacts with the VSS service.

**Sysmon EID 10** (ProcessAccess): 4 events show PowerShell monitoring child processes.

**Sysmon EID 11** (FileCreate): Two file creation events for PowerShell profile writes (`StartupProfileData-NonInteractive`), one for each PowerShell session.

The PowerShell channel (108 events: 107 EID 4104 + 1 EID 4103) contains test framework boilerplate. The `"delete shadows all" | diskshadow.exe` command itself is not captured in EID 4104 script block logging in the available samples, though the Security EID 4688 command line preserves it in full.

**Compared to the defended variant** (26 Sysmon / 10 Security / 45 PowerShell): The undefended run has more Sysmon events (38 vs. 26) and fewer Security events (4 vs. 10). The significantly higher Sysmon count (38 vs. 26) in the undefended run reflects `diskshadow.exe` actually running and loading COM components to interact with the VSS service. In the defended run, Defender killed the PowerShell process before `diskshadow.exe` could complete its work, resulting in fewer DLL loads. The successful `0x0` exit code is the key differentiator confirming that shadow copies were actually deleted.

## What This Dataset Does Not Contain

`diskshadow.exe` does not appear as a separate Sysmon EID 1 or Security EID 4688 process creation event. This is a gap: `diskshadow.exe` must have been spawned as a child process to accept stdin, but neither the security auditing subsystem nor the sysmon-modular filter captured it. Detection rules relying specifically on a `diskshadow.exe` process creation event will not fire on this execution pattern.

There are no VSS provider or application log entries confirming which shadow copies existed before deletion, how many were removed, or confirmation that the deletion completed. The VSS Operational log (`Microsoft-Windows-VSS/Operational`) is not included in the bundled channels. No WMI activity log events are present for the VSS interaction `diskshadow.exe` performs internally.

## Assessment

This dataset captures a completed, successful shadow copy deletion via the `diskshadow.exe` stdin pipe technique. The parent PowerShell command line containing `"delete shadows all" | diskshadow.exe` is preserved in Security EID 4688, and the `0x0` exit code confirms successful execution. The higher Sysmon EID 7 count (25 image loads) compared to the defended run (fewer loads due to early kill) provides a behavioral indicator of completed vs. interrupted execution.

The central detection gap is the absence of `diskshadow.exe` as its own process creation event. Defenders relying on process-name based detection for this technique will see only the PowerShell process with the piped command in its command line. The piped command string `"delete shadows all"` embedded in the PowerShell command line is the reliable detection anchor.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `powershell.exe` command line containing `"delete shadows all"` piped to `diskshadow.exe`. This string in any PowerShell command line context is a high-confidence indicator regardless of whether `diskshadow.exe` appears as a separate process event.
- **Sysmon EID 1**: Child `powershell.exe` spawned by parent `powershell.exe` with `diskshadow.exe` in the command line. The parent-child PowerShell spawning pattern combined with VSS-related content is distinctive.
- **Sysmon EID 7**: The quantity of DLL loads (25) in the technique PowerShell process exceeds what a simple test framework-only execution produces (~9 loads). Elevated image load counts for `powershell.exe` processes that contain `diskshadow` in their command lines may indicate the `diskshadow.exe` subprocess loaded COM and VSS components before the parent's image load count accumulated.
- **Sysmon EID 17**: Two PowerShell host pipes present simultaneously indicate two concurrent or sequential PowerShell sessions — the parent test framework and the technique child — a behavioral signature of script-driven tool execution.
- **The absence of `diskshadow.exe` as a separate EID 4688/Sysmon EID 1 event** when the parent PowerShell exits `0x0` with `diskshadow` in its command line is itself a detection gap to document: this execution path evades process-name-based detections on `diskshadow.exe`.
