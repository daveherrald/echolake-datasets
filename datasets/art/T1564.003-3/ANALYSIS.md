# T1564.003-3: Hidden Window — Conhost Execution

## Technique Context

T1564.003 (Hidden Window) includes a lesser-known variant that abuses `conhost.exe` (the Windows Console Host process) as a proxy launcher. `conhost.exe` accepts a `--headless` flag originally introduced for Windows Subsystem for Linux and certain internal console uses. When invoked with `--headless`, it runs a child process without attaching a visible console window. Adversaries exploit this to achieve hidden execution using a signed Windows system binary that is less likely to be flagged than a PowerShell `-WindowStyle hidden` invocation, and which may bypass script block logging for the actual payload since `conhost.exe` is not a PowerShell engine.

## What This Dataset Contains

The test executes: `conhost.exe --headless calc.exe`

**Security log (4688)** records the outer `powershell.exe` invocation with command line `"powershell.exe" & {conhost.exe --headless calc.exe}`, followed by `calc.exe` creation and termination. `calc.exe` exits with status `0x0`, confirming the hidden execution succeeded end-to-end.

**Sysmon EID 1** captures both the `powershell.exe` launcher (tagged `technique_id=T1059.001`) and the `powershell.exe` child that contains the `conhost.exe --headless calc.exe` invocation. The full command line is preserved in the Sysmon record.

**PowerShell 4104** records the script block `{conhost.exe --headless calc.exe}` verbatim. This is notable: even though `conhost.exe` itself is not a PowerShell interpreter, the ART test framework wraps it in a PowerShell script block, so script block logging captures the exact technique command.

**4703 (Token Right Adjusted)** records SYSTEM-context privilege enablement for the parent `powershell.exe` session, consistent with execution under the machine account.

All process terminations complete with `0x0` status, including `calc.exe`, confirming the technique achieved its objective.

## What This Dataset Does Not Contain (and Why)

`conhost.exe` itself does not appear as a Security 4688 process creation. The conhost process is launched within the cmd/PS invocation chain but `conhost.exe` processes attached to console sessions are generally spawned by the kernel session manager, not via a standard `CreateProcess` call that would generate a 4688. The observable artifact is the `calc.exe` child that conhost spawns.

No Sysmon EID 1 for `conhost.exe` appears, for the same reason — the sysmon-modular include rules do not match `conhost.exe` launching child processes in this context. Security 4688 provides the `calc.exe` process creation to fill the visibility gap.

No Sysmon EID 1 for `calc.exe` appears because `calc.exe` is not in the sysmon-modular ProcessCreate include rules. Security 4689 confirms its termination with exit code 0x0.

## Assessment

The technique executed successfully: `calc.exe` ran hidden under `conhost.exe --headless` and exited cleanly. The command line is preserved in three sources (Security 4688, Sysmon EID 1, PowerShell 4104), providing strong detection coverage. The `conhost.exe`-as-launcher pattern is particularly useful for detection engineering because `conhost.exe --headless` spawning an arbitrary binary is rare in legitimate enterprise usage.

## Detection Opportunities Present in This Data

- **`conhost.exe --headless` in any command line**: this argument is extremely unusual in enterprise environments and should be treated as a high-confidence indicator whenever `conhost.exe` appears with `--headless` followed by a non-standard child process.
- **PowerShell 4104 script block containing `conhost.exe --headless`**: script block logging captures the wrapper invocation verbatim, enabling reliable keyword detection.
- **Security 4688 command line**: `conhost.exe --headless` in any process's command line is a detectable string that will appear even without Sysmon deployed.
- **Sysmon EID 1 parent chain**: `powershell.exe` spawning a child `powershell.exe` that contains `conhost.exe --headless` in its command line provides a multi-level indicator for behavioral analytics.
- **Unusual parent for `calc.exe`** (or other binaries): `calc.exe` (or any unexpected binary) appearing as a child of a PowerShell process that itself has a `conhost --headless` invocation in its command line is a strong behavioral signal.
