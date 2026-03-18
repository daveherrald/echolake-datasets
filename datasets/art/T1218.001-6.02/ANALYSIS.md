# T1218.001-6: Compiled HTML File — Invoke CHM with Script Engine and Help Topic

## Technique Context

T1218.001 covers the abuse of `hh.exe` and compiled HTML files for arbitrary code execution. Test 6 uses the `Invoke-ATHCompiledHelp` ATH function without specifying a storage handler or double-click simulation, instead invoking the CHM with a "Script Engine and Help Topic" configuration. This variant exercises a different code path in the Windows HTML Help subsystem — one that directly specifies a scripting engine context when processing the compiled help content.

The "Script Engine and Help Topic" invocation method is relevant because it represents a more direct manipulation of the CHM parsing infrastructure. CHM files can contain multiple topic pages with embedded scripts, and specifying the script engine explicitly when opening a CHM may bypass some content security policies that apply to CHM files opened through default shell association. This variant demonstrates that the CHM technique has multiple distinct execution sub-paths, each with different behavioral signatures.

Execution runs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`. This test generates the most diverse security event profile of the T1218.001 series, including a logon event and special privilege assignment.

## What This Dataset Contains

The dataset spans approximately 5 seconds (2026-03-17T16:49:07Z–16:49:12Z) and contains 144 total events across four channels: 106 PowerShell events (105 EID 4104, 1 EID 4103), 30 Sysmon events (18 EID 7, 4 EID 10, 4 EID 1, 2 EID 11, 2 EID 17), 8 Security events (6 EID 4688, 1 EID 4672, 1 EID 4624), and 1 Application event (EID 16394).

The defining Sysmon EID 1 event captures: `"powershell.exe" & {}` (tagged T1059.001, PowerShell) — the ATH function call for this test variant results in a PowerShell child process with an effectively empty command argument (`{}`). This is the most minimal command-line representation in the entire T1218.001 series. The actual technique invocation logic is embedded within the Invoke-ATHCompiledHelp function executing in-process rather than visible in the child process command line.

Two `whoami.exe` EID 1 events (T1033) bookend the execution. A fourth EID 1 event captures the empty-argument PowerShell child process described above.

The Security channel contains the most distinctive events in this test. EID 4624 records a Type 5 (Service) logon by ACME-WS06$ (the computer account), indicating a service-related logon event that occurred during this window — likely triggered by the ATH function's execution path requiring a new service-context logon. EID 4672 records special privileges assigned to the SYSTEM logon (0x3E7), including `SeAssignPrimaryTokenPrivilege`, `SeTcbPrivilege`, and `SeSecurityPrivilege` — the full SYSTEM privilege set being assigned to a new logon session. These logon events are more intrusive than the simple process creation events in tests 3–5.

Four Sysmon EID 10 process access events record full-access handle opens (0x1FFFFF) from the test framework PowerShell to child processes (whoami.exe ×2, and two PowerShell processes), tagged T1055.001.

Two Sysmon EID 11 file creation events: one captures `C:\Windows\Logs\waasmedic\waasmedic.20260317_164905_390.etl` created by svchost.exe (Windows Update Medic Service ETL log — routine background activity), and one captures the PowerShell startup profile data file.

The Application EID 16394 ("Offline downlevel migration succeeded") is a Windows licensing subsystem event unrelated to the technique.

The ATH cleanup `Invoke-AtomicTest T1218.001 -TestNumbers 6 -Cleanup -Confirm:$false` is visible in the PowerShell EID 4103 record.

Compared to the defended dataset (sysmon: 46, security: 10, powershell: 53), the undefended run has fewer Sysmon events (30 vs. 46) but more Security events (8 vs. 10). The larger defended Sysmon count again reflects Defender's process scanning activity.

## What This Dataset Does Not Contain

The content of the ATH function's CHM access via the "Script Engine and Help Topic" path is not captured in the PowerShell script block log or in any process creation event. The empty `{}` argument in the child PowerShell command line means the actual CHM access is occurring through internal function mechanics rather than through an inspectable command line.

`hh.exe` does not appear as its own Sysmon EID 1 event. No network, DNS, or registry events are present.

## Assessment

Test 6 produces the most opaque command-line evidence of the T1218.001 series: the child PowerShell process's command line is `"powershell.exe" & {}` — essentially empty — making direct command-line detection of the specific CHM technique impossible from this event alone. The detection value must come from the parent-child context (SYSTEM PowerShell spawning an empty-argument PowerShell) and from the Security channel's logon events.

The Security EID 4624 (Type 5 service logon) and EID 4672 (special privilege assignment) events are the most distinctive features of this dataset compared to tests 3–5. The appearance of a service-type logon and full SYSTEM privilege assignment during a CHM test invocation suggests that this execution path triggers the creation of a new logon session, perhaps to establish a scripting engine context with the required privilege level. This behavioral difference is forensically meaningful — it distinguishes this CHM variant from others that do not generate logon events.

The presence of waasmedic ETL logging (svchost.exe writing to `C:\Windows\Logs\waasmedic\`) provides another OS noise calibration point: Windows Update Medic Service runs continuously and generates ETL files on its own schedule, independent of any test activity.

## Detection Opportunities Present in This Data

**Security EID 4624 + 4672 correlated with PowerShell (SYSTEM) execution:** The combination of a new SYSTEM logon event (Type 5 service logon) and special privilege assignment occurring within seconds of a suspicious SYSTEM PowerShell process creating child processes is a higher-specificity indicator than the PowerShell activity alone. This correlation distinguishes test 6's execution path from the simpler process-only signatures of tests 3–5.

**Sysmon EID 1 — PowerShell with empty {} argument from PowerShell parent:** A child PowerShell process launched with `"powershell.exe" & {}` (an empty scriptblock argument) from another PowerShell parent running as SYSTEM is not a pattern that occurs in legitimate administrative operations. The empty scriptblock indicates in-process invocation logic rather than a meaningful command-line operation.

**Sysmon EID 10 — four full-access process opens from SYSTEM PowerShell:** The test framework opens full-access (0x1FFFFF) handles to whoami.exe (×2) and two PowerShell processes. This access pattern — a SYSTEM PowerShell process opening full access to multiple child processes in rapid succession — is characteristic of script-based automation monitoring child execution rather than interactive administration.

**Parent PowerShell → child PowerShell with different command arguments across T1218.001 variants:** Across tests 3, 4, 5, and 6, the distinguishing observable is always the argument to the child PowerShell's `& {<invocation>}` block. A detection approach that monitors for SYSTEM-context PowerShell spawning PowerShell children with `Invoke-ATHCompiledHelp` arguments or with empty `& {}` arguments, combined with Security logon events, provides coverage across the entire T1218.001 ATH test series.
