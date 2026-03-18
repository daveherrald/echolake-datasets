# T1218-15: System Binary Proxy Execution — LOLBAS Msedge to Spawn Process

## Technique Context

T1218 covers the broad category of System Binary Proxy Execution — using legitimate, trusted Windows binaries or application binaries to execute attacker-controlled code. Test 15 specifically abuses Microsoft Edge (`msedge.exe`) as a LOLBAS (Living Off the Land Binaries and Scripts) to spawn arbitrary processes. Edge supports command-line arguments that can be used to open URLs, and in certain invocation patterns the browser process will spawn child processes or interpret handler URIs in ways that can be leveraged for indirect execution.

This test is representative of a maturing category of LOLBAS techniques targeting Chromium-based browsers. Because `msedge.exe` is present on nearly every modern Windows 11 system, is code-signed by Microsoft, and is expected to make network connections and spawn child processes in normal operation, distinguishing malicious use from normal browser activity requires attention to the specific invocation pattern rather than the binary itself.

The test executes as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`.

## What This Dataset Contains

The dataset spans approximately 9 seconds (2026-03-17T16:43:16Z–16:43:25Z) and contains 177 total events across four channels: 114 PowerShell events (108 EID 4104, 6 EID 4103), 8 Security events (all EID 4688), 53 Sysmon events (31 EID 7, 8 EID 10, 7 EID 1, 4 EID 11, 3 EID 17), and 2 Application events (both EID 15).

The key Sysmon EID 1 event captures a PowerShell child process spawned by the SYSTEM test framework with the command line: `"powershell.exe" & {$edgePath64 = \"C:\Program Files\Microsoft\Edge\Application\msedge.exe\"` (truncated in the sample, but establishing that the test dynamically resolves the Edge installation path on the system before invoking it). Sysmon tags this process with `technique_id=T1083,technique_name=File and Directory Discovery` due to the `Test-Path` call within the script block checking for Edge's presence in both 64-bit and 32-bit locations.

The 8 Sysmon EID 10 process access events record the ART test framework's PowerShell process opening handles to the spawned PowerShell subprocess and to `whoami.exe` with `GrantedAccess: 0x1FFFFF` (full access). All are tagged `technique_id=T1055.001,technique_name=Dynamic-link Library Injection` by the Sysmon rule, which fires on full-access process opens from PowerShell to other processes. This is a consistent artifact of the Invoke-AtomicTest framework and is not specific to the Edge-based proxy execution technique itself.

Three Sysmon EID 17 named pipe creation events capture the PSHost pipes from the SYSTEM PowerShell sessions, providing timestamp anchors.

Sysmon EID 11 file creation events include `C:\Windows\Temp\01dcb62d26b9fa2d` created by `MsMpEng.exe` — Windows Defender's engine executable — and two PowerShell startup profile data files (`StartupProfileData-NonInteractive`, `StartupProfileData-Interactive`). Even with Defender disabled for real-time protection, the engine process (`MsMpEng.exe`) remains active and writes working files.

The 2 Application EID 15 events record "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON" — these are status update notifications from the Security Center, which appear here as a timing artifact of the test running during a period when Defender's status was being tracked.

Compared to the defended dataset (sysmon: 49, security: 18, powershell: 40), this undefended run produces more total Sysmon events (53 vs. 49) and significantly more PowerShell events (114 vs. 40), while the Security channel is similar (8 vs. 18). The additional PowerShell volume in the undefended run reflects the lack of interference with the scripting session.

## What This Dataset Does Not Contain

The dataset does not contain a direct Sysmon EID 1 process creation event for `msedge.exe` itself being launched. Edge's process creation — the central act of the technique — is not captured in the Sysmon EID 1 sample set, likely because `msedge.exe` did not match an include-mode rule that triggers on browser processes in the sysmon-modular configuration deployed in this environment.

No network connection events (Sysmon EID 3) are present. Edge's normal operation involves network connections, and any connections made during the technique execution are not captured here. Similarly, no DNS query events (EID 22) are present.

No Registry modification events (EID 13) or WMI events are present in this dataset.

The payload spawned by Edge — the actual process that would constitute the "malicious" outcome — is not visible as a separate EID 1 event in the samples.

## Assessment

This dataset captures the setup and test framework activity surrounding the Edge LOLBAS test, but the core technique artifact — Edge launching and spawning a child process — is not directly observable in the Sysmon EID 1 sample set due to filtering gaps. The most useful forensic artifacts are the PowerShell command block showing the test dynamically locating msedge.exe via `Test-Path`, and the secondary process access events showing the test framework monitoring child processes.

The presence of `MsMpEng.exe` writing a temp file (`C:\Windows\Temp\01dcb62d26b9fa2d`) provides a real-world calibration point: even with real-time protection disabled, Defender's engine process is active and generates file system activity. Analysts should not interpret the presence of MsMpEng.exe file activity as evidence that Defender is fully operational.

The undefended run's 9-second duration and 53 Sysmon events provide a reasonable baseline for what Edge-related LOLBAS execution looks like without AV interference. The higher PowerShell event volume (114 vs. 40 in the defended run) demonstrates that endpoint protection can substantially affect the observable telemetry volume even when the technique executes successfully in both cases.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — PowerShell locating msedge.exe via Test-Path:** A SYSTEM-context PowerShell process running a script block that checks for `C:\Program Files\Microsoft\Edge\Application\msedge.exe` existence before executing it is inconsistent with normal administrative activity. Legitimate administrative tools do not typically discover and then invoke the browser as a proxy execution mechanism.

**Parent process context for Edge invocations:** In a normal browsing scenario, `msedge.exe` is launched by a user process (explorer.exe, a taskbar shell, or a shortcut) rather than by SYSTEM-context PowerShell. The parent process of any Edge invocation is a high-value context field that distinguishes technique abuse from legitimate browser use.

**Sysmon EID 10 — full-access process handles from PowerShell to child processes:** The pattern of a SYSTEM PowerShell process opening `0x1FFFFF` (full access) handles to child processes including `whoami.exe` is a consistent ART test framework artifact, but the underlying mechanism — PowerShell monitoring child process execution — is also present in post-exploitation frameworks. The combination of SYSTEM context, workstation endpoint, and full-access child process handles warrants attention.

**Application EID 15 — Defender status transitions:** While not directly attributable to the technique, Defender status update events appearing in the Application log around the time of suspicious process activity can indicate that an adversary has modified Defender's operational state as part of pre-execution preparation.
