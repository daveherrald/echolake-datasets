# T1036.003-7: Rename Legitimate Utilities — Masquerading - windows exe running as different windows exe

## Technique Context

T1036.003 (Rename Legitimate Utilities) includes the scenario where one Windows-signed binary is renamed to impersonate a different Windows-signed binary. This test copies `cmd.exe` (referenced via `$env:ComSpec`) to `$env:TEMP\svchost.exe` and executes it. Unlike T1036.003-6 where the underlying binary was a non-Windows payload, here both the source and the impersonated name are legitimate Windows executables — making signature-based detection insufficient, since the binary is genuinely Microsoft-signed.

This variant is operationally important because it defeats common detection approaches that check whether a process's digital signature is valid or whether it was signed by Microsoft. The binary is legitimately signed; only the path and the mismatch between `OriginalFileName` (`Cmd.Exe`) and the running process name (`svchost.exe`) reveals the masquerade. Security tooling that performs path normalization and `OriginalFileName` validation will detect it, but tooling that validates only signature status will not.

Real attackers use this approach when they need a functional shell or execution environment but want to blend in with the system process list. Running `cmd.exe` as `svchost.exe` from a temp directory provides a command interpreter that appears superficially legitimate in process lists.

## What This Dataset Contains

This dataset contains 169 events: 100 PowerShell events, 21 Security events, 48 Sysmon events, and 2 Application events. This is notably larger than the defended variant (46 Sysmon, 15 Security, 40 PowerShell), with the increase concentrated in Sysmon (48 vs. 46) and Security (21 vs. 15).

The Security channel (EID 4688) captures the core execution. PowerShell spawns a child PowerShell with: `copy "$env:ComSpec" ($env:TEMP + "\svchost.exe")` then `Start-Process -PassThru -FilePath ($env:TEMP + "\svchost.exe")`. The masqueraded process appears: `CommandLine: "C:\Windows\TEMP\svchost.exe"`, `NewProcessName: C:\Windows\Temp\svchost.exe`, `ParentProcessName: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`. Cleanup: `Remove-Item ($env:TEMP + "\svchost.exe") -Force -ErrorAction Ignore`. The 16 EID 4985 events (work item state change) are Windows transaction log housekeeping triggered by the process executions.

Sysmon shows 24 EID 7 image load events — reflecting that the masqueraded `svchost.exe` (actually `cmd.exe`) loaded several DLLs on startup. EID 3 (network connection) appears: `MsMpEng.exe` connecting to `48.211.71.202:443`, tagged `technique_id=T1036,technique_name=Masquerading` — this is Defender's cloud protection service phoning home in response to observing the renamed binary, even with real-time protection disabled. EID 11 captures `powershell.exe` creating `C:\Windows\Temp\svchost.exe`. EID 17 (pipe create) shows two new PowerShell hosting pipes. EID 29 (file executable detected) would fire on the new executable creation.

The 5 EID 3 network connections are a notable feature of this dataset — Defender's cloud lookup (even in a GPO-disabled state, the MsMpEng process may still be running and performing limited telemetry) generates network traffic tagged as masquerading-related.

The 2 Application events include an EID 15 message about Defender status being `SECURITY_PRODUCT_STATE_ON` — an artifact of the GPO state tracking, not actual protection being active.

## What This Dataset Does Not Contain

As with other T1036.003 variants, Sysmon EID 1 does not capture the masqueraded process's `OriginalFileName` because the process running from `$env:TEMP\svchost.exe` falls outside the Sysmon include rules. The `OriginalFileName: Cmd.Exe` that would identify the binary is not visible in the Sysmon process creation events for the masqueraded process itself.

No output or activity from the masqueraded `cmd.exe` running as `svchost.exe` is captured — the process was launched and immediately stopped, so no child processes or interesting activity appears.

## Assessment

This is one of the most instructive datasets in the T1036.003 series for detection engineers. It cleanly demonstrates a scenario where signature checking alone is insufficient — the binary is a legitimate Microsoft binary, yet the deployment is clearly malicious. The combination of Sysmon EID 11 (file creation at `$env:TEMP\svchost.exe`), the parent-child relationship (`powershell.exe` → `svchost.exe` from temp), and the Defender cloud lookup network event (EID 3 tagged masquerading) together provide a rich multi-source detection picture. The Defender network event appearing even with real-time protection disabled is an interesting operational note.

## Detection Opportunities Present in This Data

1. Sysmon EID 11 (file create) for `C:\Windows\Temp\svchost.exe` (or any system process name in a writable directory) created by `powershell.exe` is a strong drop indicator.

2. EID 4688 for `C:\Windows\Temp\svchost.exe` with parent `powershell.exe` — legitimate `svchost.exe` is always parented by `services.exe` and never runs from `\Temp\`.

3. Sysmon EID 3 (network connection) from `MsMpEng.exe` tagged `technique_id=T1036,technique_name=Masquerading` indicates Defender's cloud lookup fired on the renamed binary, which can be used as a secondary signal even when real-time protection is disabled.

4. The temporal sequence of PowerShell creating an executable file with a system process name in `$env:TEMP`, immediately followed by a process launch from that path, is a reliable behavioral indicator.

5. Comparing a process's `OriginalFileName` (from PE header, available in Sysmon EID 1 if captured) against the running image name — `Cmd.Exe` vs. `svchost.exe` — is the definitive detection method for same-vendor binary masquerading.

6. The 16 Security EID 4985 (work item state) events accompanying the execution are a volume anomaly that correlates with the launch of the masqueraded process — unusual spikes in transaction-related events can indicate process execution in controlled environments.
