# T1218.001-5: Compiled HTML File — Invoke CHM Simulate Double Click

## Technique Context

T1218.001 covers abuse of compiled HTML help files via `hh.exe`. Test 5 uses the `Invoke-ATHCompiledHelp` ATH function with the `-SimulateUserDoubleClick` flag, which instructs the framework to invoke the CHM file using the same code path that Windows Explorer would use when a user double-clicks a `.chm` file — the shell file association handler. This is distinct from direct command-line invocation of `hh.exe` and from the InfoTech Storage protocol handler (test 4).

The simulated double-click execution path is significant because it is the most realistic representation of how CHM-based phishing payloads reach victims: the user receives a CHM file (via email, download, or removable media) and opens it by double-clicking. This invocation path uses `ShellExecute` or similar shell APIs to open the file through its registered handler, producing a different parent process and invocation context than scripted execution.

Execution runs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`.

## What This Dataset Contains

The dataset spans approximately 4 seconds (2026-03-17T16:48:56Z–16:49:00Z) and contains 135 total events across three channels: 106 PowerShell events (105 EID 4104, 1 EID 4103), 3 Security events (all EID 4688), and 26 Sysmon events (17 EID 7, 3 EID 10, 3 EID 1, 2 EID 17, 1 EID 11).

The defining Sysmon EID 1 event captures the ATH PowerShell invocation: `"powershell.exe" & {Invoke-ATHCompiledHelp -SimulateUserDoubleClick -CHMFilePath Test.chm}` (tagged T1059.001, PowerShell). Note the different Sysmon rule tag compared to tests 3 and 4 (which were tagged T1083): the absence of the `-HHFilePath` parameter and the presence of `-SimulateUserDoubleClick` causes the Sysmon rule to match a different rule set — the T1059.001 PowerShell execution rule rather than the T1083 file discovery rule. The command line is also shorter, reflecting that `Invoke-ATHCompiledHelp -SimulateUserDoubleClick` does not specify the hh.exe path explicitly.

The remaining Sysmon EID 1 events are two `whoami.exe` invocations (T1033).

The ATH cleanup command `Invoke-AtomicTest T1218.001 -TestNumbers 5 -Cleanup -Confirm:$false` is visible in the PowerShell EID 4103 record.

Three Sysmon EID 10 process access events (all tagged T1055.001) capture the test framework monitoring child processes with full access (0x1FFFFF).

The event totals are identical to T1218.001-3 and T1218.001-4 (26 Sysmon, 106 PowerShell, 3 Security), confirming the ATH framework produces a consistent footprint across CHM test variants.

Compared to the defended dataset (sysmon: 26, security: 10, powershell: 40), the undefended run shows identical Sysmon counts (26) and fewer PowerShell events (106 vs. 40). The defended Sysmon count matching the undefended count here is unusual — in most other tests the defended count is higher. This suggests that the `-SimulateUserDoubleClick` variant generates less Defender-triggered activity than other CHM test variants.

## What This Dataset Does Not Contain

As with tests 3 and 4, `hh.exe` does not appear as its own Sysmon EID 1 event. The simulated double-click path presumably opens the CHM through a shell API call from within the ATH function's PowerShell process rather than as an explicit new process creation.

The process that the simulated double-click would spawn in a real user context (Explorer → hh.exe) is not present because the test runs under SYSTEM context from PowerShell rather than from a user-facing shell.

No network, registry, or DNS events are present.

## Assessment

This test produces the most compressed view of a CHM double-click execution: a single PowerShell child process with `Invoke-ATHCompiledHelp -SimulateUserDoubleClick -CHMFilePath Test.chm` in its command line. The change in Sysmon rule tag (T1059.001 vs. T1083) compared to tests 3 and 4 highlights that minor variations in ATH function parameters can cause events to be attributed to different MITRE techniques by Sysmon's detection rules — a useful calibration point for rule-based detection tuning.

The defended and undefended Sysmon counts being identical (both 26) for this test — unique in this batch where the defended count is typically higher — may indicate that Defender's real-time scanning does not generate additional process activity for the `-SimulateUserDoubleClick` invocation path. This is consistent with the shell API-based execution producing fewer child processes for Defender to inspect compared to the multi-step cmd.exe → hh.exe chain in tests 1 and 2.

In a real-world scenario, the simulated double-click path would be the most common phishing delivery mechanism. The process chain would originate from Explorer or Outlook (not SYSTEM PowerShell), and the user context would be a domain user's logon session, not SYSTEM. The SYSTEM context here is the ART test framework artifact.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — Invoke-ATHCompiledHelp -SimulateUserDoubleClick:** The `Invoke-ATHCompiledHelp -SimulateUserDoubleClick` command line in a PowerShell process is specific to ATH-based testing. In real attacks, the double-click invocation would not involve a named ATH function — the adversary would deliver the CHM file and rely on the user opening it directly.

**Sysmon rule tag change (T1083 → T1059.001):** The shift in Sysmon's technique attribution from T1083 (File and Directory Discovery) in tests 3/4 to T1059.001 (PowerShell) in test 5 illustrates how detection rule specificity affects event attribution. The same underlying technique (CHM abuse) appears as a different technique ID in the Sysmon log depending on which parameters are passed to the ATH function. This is a calibration point for detection coverage: rules that depend on specific Sysmon RuleName values may miss technique variations that use slightly different execution paths.

**CHM file access from SYSTEM context:** Any process opening a `.chm` file (through any mechanism — hh.exe, ShellExecute, or COM automation) while running as SYSTEM on a domain workstation is worth investigating. Legitimate help file access is always user-initiated and runs in the user's session context.

**Four-second execution window:** Tests 3, 4, and 5 all complete in approximately 4 seconds with identical event distributions. This consistency is characteristic of ATH-framework execution rather than real-world CHM payload delivery, which would involve user interaction time, payload execution duration, and potentially network activity extending the observable window significantly.
