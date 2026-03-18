# T1218-3: System Binary Proxy Execution — InfDefaultInstall.exe .inf Execution

## Technique Context

T1218 System Binary Proxy Execution includes the abuse of `InfDefaultInstall.exe`, a legitimate Windows binary located in `C:\Windows\System32\`. This executable is the default handler for `.inf` (Setup Information File) execution — the same file format used to install device drivers and hardware configurations. When invoked with a path to an INF file, `InfDefaultInstall.exe` processes the directives within that file, which can include running arbitrary programs, copying files, and modifying registry entries.

Adversaries craft malicious INF files containing `RunPreSetupCommands`, `RunPostSetupCommands`, or similar directives to execute arbitrary commands during the "installation" process. Because `InfDefaultInstall.exe` is a signed Windows system binary, and INF file processing is a normal part of device driver management, this technique can evade defenses that focus on signed binary allowlisting.

This test invokes `InfDefaultInstall.exe` with a pre-crafted INF file from the Atomic Red Team repository (`Infdefaultinstall.inf`). Execution occurs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17T16:43:43Z–16:43:47Z) and contains 114 total events: 96 PowerShell events (95 EID 4104, 1 EID 4103), 4 Security events (all EID 4688), and 14 Sysmon events (6 EID 7, 4 EID 1, 3 EID 10, 1 EID 17). This is one of the more compact datasets in this batch.

Two Sysmon EID 1 events are particularly significant here. The first captures `cmd.exe` with the command line `"cmd.exe" /c InfDefaultInstall.exe "C:\AtomicRedTeam\atomics\T1218\src\Infdefaultinstall.inf"` — the ART test framework wrapping the invocation in a cmd.exe shell, tagged T1059.003 (Windows Command Shell). The second captures `InfDefaultInstall.exe` itself: `InfDefaultInstall.exe "C:\AtomicRedTeam\atomics\T1218\src\Infdefaultinstall.inf"` — tagged directly as `technique_id=T1218,technique_name=System Binary Proxy Execution`. The parent of `InfDefaultInstall.exe` is the cmd.exe from the first event, establishing the full chain.

This is one of only a few tests in this batch where the actual technique binary (`InfDefaultInstall.exe`) appears as its own Sysmon EID 1 record in the sample — a result of the sysmon-modular rules including this specific binary in its process monitoring configuration.

Two `whoami.exe` invocations (T1033) bookend the execution as the test framework's pre- and post-test identity checks.

The ART cleanup command is visible in the PowerShell EID 4103 record: `Invoke-AtomicTest T1218 -TestNumbers 3 -Cleanup -Confirm:$false`.

The 3 Sysmon EID 10 process access events capture full-access handle opens (0x1FFFFF) from the test framework PowerShell to child processes — the standard test framework monitoring pattern.

Compared to the defended dataset (sysmon: 37, security: 12, powershell: 36), the undefended run shows fewer Sysmon events (14 vs. 37) and fewer Security events (4 vs. 12) while the PowerShell channel is similar (96 vs. 36). The substantially lower Sysmon count in the undefended run reflects the absence of Defender-generated process activity.

## What This Dataset Does Not Contain

No events from the INF file's actual payload execution are visible in this dataset. The `Infdefaultinstall.inf` file's directives — which would spawn commands, copy files, or modify the registry — are not represented as separate process creation or file modification events in the samples. Whether the INF file's payload executed successfully is not directly observable from the captured telemetry alone.

No network connection, DNS query, or registry modification events are present. INF file processing can modify the registry as part of driver installation procedures, but no such events appear in this dataset.

No Sysmon EID 7 DLL load events specifically attributable to InfDefaultInstall.exe or its INF-triggered activity are in the sample set (only 6 total EID 7 events).

## Assessment

This dataset provides one of the cleaner technique execution records in this batch: both the cmd.exe invocation and the `InfDefaultInstall.exe` binary invocation are captured as Sysmon EID 1 events with full command lines. The command line `InfDefaultInstall.exe "C:\AtomicRedTeam\atomics\T1218\src\Infdefaultinstall.inf"` is the defining observable, and it is directly present in the data.

The brevity of this dataset (14 Sysmon events, 4 seconds) reflects the quick execution of InfDefaultInstall.exe — the binary processes the INF file directives and exits without a prolonged process lifetime. This makes the process creation and exit sequence the primary forensic artifact.

Compared to the defended dataset, this undefended run has notably fewer Sysmon events, confirming that Windows Defender's presence generates substantial additional process-level telemetry even when the technique executes successfully in both scenarios.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — InfDefaultInstall.exe in process chain:** The appearance of `C:\Windows\System32\InfDefaultInstall.exe` as a child of `cmd.exe` (which is itself a child of PowerShell) is anomalous. Legitimate INF-based device driver installation through Windows Update or device management pipelines does not typically produce this parent-child chain.

**InfDefaultInstall.exe with an explicit INF file path argument:** In normal Windows operation, InfDefaultInstall.exe processes INF files through the shell association handler (right-click → Install on an INF file). Explicit command-line invocation with a file path — particularly a path outside of `%SystemRoot%\INF\` or `%SystemRoot%\System32\DriverStore\` — is characteristic of deliberate abuse rather than normal driver installation.

**Command line contains an AtomicRedTeam path:** The path `C:\AtomicRedTeam\atomics\T1218\src\Infdefaultinstall.inf` is specific to test environments, but it reveals the pattern: any INF file path in a non-standard location (user profile, temp directory, download folder) being passed to InfDefaultInstall.exe from a scripted context is worth investigating.

**SYSTEM context on a workstation:** InfDefaultInstall.exe running as SYSTEM from a PowerShell-invoked cmd.exe on a domain workstation is an atypical execution context for legitimate driver installation, which typically occurs through the Windows hardware installation pipeline.
