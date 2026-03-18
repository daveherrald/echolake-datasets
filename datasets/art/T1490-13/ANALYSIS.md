# T1490-13: Inhibit System Recovery — Delete Volume Shadow Copies via Diskshadow

## Technique Context

MITRE ATT&CK T1490 (Inhibit System Recovery) covers shadow copy deletion via multiple command interfaces. `diskshadow.exe` is a Microsoft-signed command interpreter for the Shadow Copy service that accepts commands interactively or via pipe. The technique in this test pipes the string `"delete shadows all"` directly to `diskshadow.exe` to delete all shadow copies in a single command. This approach is notable for two reasons: `diskshadow.exe` is a signed Microsoft binary (a Living Off the Land Binary), and because the deletion command is passed via stdin rather than as a command-line argument, some argument-based detections will not match it. The technique has been observed in ransomware operations and has been highlighted in Microsoft threat intelligence reports as a stealthier VSC deletion path.

## What This Dataset Contains

**Sysmon (Event ID 1) — ProcessCreate:**
The test framework launches `"powershell.exe" & {"delete shadows all" | diskshadow.exe}`. This PowerShell invocation is captured and tagged `technique_id=T1059.001`. However, `diskshadow.exe` itself does **not** appear as a separate Sysmon ProcessCreate event. The sysmon-modular include-mode filter does not have a rule matching `diskshadow.exe`, so its process creation is not captured in Sysmon. Only the `whoami.exe` preflight and the PowerShell wrapper appear as Sysmon EID 1 events.

**Security (Event IDs 4688/4689/4703):**
`whoami.exe` and `powershell.exe` creation events are present. The `powershell.exe` process exits with `0x0`. Notably, `diskshadow.exe` is **absent** from Security EID 4688 as a separate process entry — the pipe `|` syntax causes PowerShell to pass the string to `diskshadow.exe` via stdin, but `diskshadow.exe` must still be spawned as a child process. Its creation should appear in a fully instrumented environment's Security log. The absence here is unexpected and suggests either that Security process creation auditing is not capturing all child processes in this execution chain, or that the `|` operator in PowerShell uses a different execution path that doesn't generate a standard 4688 event for `diskshadow.exe` as a separate process.

**PowerShell (Event ID 4104) — Script Block Logging:**
Two script block entries capture the technique command:
- `& {"delete shadows all" | diskshadow.exe}`
- `{"delete shadows all" | diskshadow.exe}`

These are the clearest indicators in this dataset. The exact string `"delete shadows all"` passed to `diskshadow.exe` is fully visible, and the PowerShell wrapper command is recorded before execution.

**Sysmon (Event IDs 7, 17, 10, 11):** DLL load events and named pipe creation for the PowerShell process are present, consistent with normal PowerShell startup. No `diskshadow.exe`-specific artifacts appear.

## What This Dataset Does Not Contain

- **No Sysmon EID 1 for `diskshadow.exe`** — the sysmon-modular include-mode ProcessCreate filter does not match `diskshadow.exe`, so the child process creation is not logged by Sysmon. This is a direct consequence of include-mode filtering.
- **No Security EID 4688 for `diskshadow.exe`** — unexpectedly absent; this is a gap in the collection rather than an expected filtering outcome.
- **No confirmation of deletion success or failure.** There are no Application log VSS events, no `diskshadow.exe` exit code, and no shadow copy enumeration showing the pre/post state.
- **No Sysmon EID 3 network events** related to the VSS operation.

## Assessment

This dataset illustrates both the value and the limits of layered telemetry. The PowerShell script block logging (EID 4104) is the primary detection surface and captures the technique with high fidelity — the `"delete shadows all" | diskshadow.exe` string is unambiguous. However, `diskshadow.exe` itself is invisible in this dataset because include-mode Sysmon filtering misses it and Security 4688 does not capture it as a separate process. This is a real detection gap that defenders face: the LOLBin (`diskshadow.exe`) is not directly observed. Detection engineering for this variant must rely on PowerShell script block logging or process creation visibility for `diskshadow.exe` itself. Adding `diskshadow.exe` to the sysmon-modular include list and investigating the Security EID 4688 gap would substantially improve this dataset.

## Detection Opportunities Present in This Data

1. **PowerShell EID 4104 — script block containing `diskshadow.exe` with `"delete shadows all"` piped via stdin** — this is the highest-confidence indicator in this dataset and captures the technique regardless of argument-based detection evasion.
2. **PowerShell EID 4104 — `"delete shadows all"` string** — even without the diskshadow.exe filename, this literal string in a script block is a reliable indicator; it has no legitimate use context.
3. **Sysmon EID 1 — PowerShell command line containing `diskshadow.exe`** — even though `diskshadow.exe` itself is not captured, the PowerShell parent process command line references the binary.
4. **Security EID 4688 — PowerShell launched from `C:\Windows\TEMP\` as SYSTEM** with a command line referencing `diskshadow.exe` — the execution context anchors the detection to the attacker scenario.
5. **Absence of `diskshadow.exe` in process telemetry as a gap indicator** — defenders using include-mode Sysmon should add `diskshadow.exe` to their ProcessCreate include rules to close this visibility gap; its legitimate use is rare enough to make it a low-noise include target.
