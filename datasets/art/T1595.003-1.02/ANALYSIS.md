# T1595.003-1: Wordlist Scanning — Web Server Wordlist Scan

## Technique Context

T1595.003 (Active Scanning: Wordlist Scanning) covers adversary enumeration of web servers by requesting paths from a predefined wordlist. The goal is to discover hidden directories, backup files, administrative interfaces, configuration files, and other exposed resources that are not linked from the application's public surface. This technique is foundational to web application reconnaissance and is used by both automated scanners (gobuster, dirbuster, ffuf, nikto) and purpose-built scripts.

This test uses an Atomic Red Team PowerShell module (`WebServerScan.ps1`) that wraps `Invoke-WebRequest` to probe a local web server (`http://localhost`) with a wordlist from `C:\AtomicRedTeam\atomics/T1595.003/src/wordlist.txt`, saving results to a temp file. Scanning localhost rather than a remote target means the test is self-contained and does not generate external network traffic, but the behavioral telemetry generated — a PowerShell process issuing many sequential HTTP requests — is representative of real-world wordlist scanning activity.

## What This Dataset Contains

The dataset captures 127 events across two log sources: PowerShell (114 events: 111 EID 4104, 3 EID 4103) and Security (13 events: 8 EID 4689, 4 EID 4688, 1 EID 4703). All events were collected on ACME-WS06 (Windows 11 Enterprise, domain-joined, Defender disabled).

**The scanner execution is captured in Security EID 4688.** PowerShell spawned a child PowerShell process with the full scan command:

```
"powershell.exe" & {Import-Module "C:\AtomicRedTeam\atomics/T1595.003/src/WebServerScan.ps1"
Invoke-WordlistScan -Target "http://localhost" -Wordlist "C:\AtomicRedTeam\atomics/T1595.003/src/wordlist.txt"
  -Timeout "5" -OutputFile "$env:TMPDIR/wordlist_scan.txt"
Write-Host "Scan complete. Results saved to: $env:TMPDIR/wordlist_scan.txt"}
```

This confirms:
- The ART scanner module was imported from its atomics path
- The target was `http://localhost`
- A wordlist file was used for path enumeration
- Results were written to a temp file

A cleanup `cmd.exe` process was created with an empty command (`"powershell.exe" & {}`), reflecting the ART cleanup stub for a test that has no persistent artifacts to remove beyond the output file.

All four EID 4688 process creation events exited at `0x0`, confirming the scan completed.

Security EID 4703 records PowerShell (PID 0x42f4) receiving elevated privileges including `SeLoadDriverPrivilege`, `SeRestorePrivilege`, `SeDebugPrivilege`, and `SeSecurityPrivilege` — consistent with SYSTEM-context execution.

## What This Dataset Does Not Contain

**No Sysmon events are present.** Without Sysmon EID 3 (Network Connection), you do not have individual HTTP request records showing each probe sent to `http://localhost`. Without Sysmon EID 22 (DNS query), there are no DNS records (though scanning localhost would not generate external DNS queries). Without Sysmon EID 11 (File Created), the output file written to `$env:TMPDIR/wordlist_scan.txt` is not captured as a file write event.

**No network-level telemetry.** Because the target is `http://localhost`, there are no external network connections visible in the Sysmon or Security channels. A real-world wordlist scan against an external target would generate Sysmon EID 3 events and potentially firewall/proxy logs.

**No output file content.** The scan results written to the temp file are not captured. You cannot determine from this dataset which paths returned non-404 responses or what the actual web server returned.

**No web server access logs.** The dataset captures the attacker-side telemetry only. Correlating with IIS or web server access logs would be necessary to see the individual HTTP requests that constituted the scan.

## Assessment

The defended variant recorded 27 Sysmon, 12 Security, and 40 PowerShell events. Sysmon in that run would have included network connection events for the HTTP requests to localhost. The undefended run produced 0 Sysmon, 13 Security, and 114 PowerShell events.

The undefended dataset confirms the scan ran to completion — the child PowerShell process exited at `0x0` and `Write-Host "Scan complete"` would have executed. The defended run may have had similar outcomes since wordlist scanning localhost is unlikely to be blocked by Defender itself; the event count differences primarily reflect Sysmon coverage rather than blocking behavior.

The key observation is that this dataset captures the scanner launch and the imported module path clearly in EID 4688. The absence of network telemetry means the individual scan requests are not visible here, but the intent and tooling are fully documented in the process creation events.

## Detection Opportunities Present in This Data

**EID 4688 — PowerShell importing a custom web scanning module from the ART atomics path and invoking `Invoke-WordlistScan`.** The function name `Invoke-WordlistScan` with `http://localhost` as a target and a wordlist file path in the command line is a direct indicator. In a real attack, the module and wordlist would have different paths, but the pattern — a PowerShell-based HTTP scanner with an explicit wordlist parameter — is detectable through process command line analysis.

**EID 4688 — Child PowerShell spawned from PowerShell to run a web enumeration task.** Powershell spawning a child PowerShell to execute a web probe module (`WebServerScan.ps1`) is not a legitimate administrative pattern. Production web testing uses purpose-built tools or CI/CD pipelines, not ad-hoc PowerShell from a SYSTEM context.

**Output file written to temp directory.** The scan output is written to `$env:TMPDIR/wordlist_scan.txt`. Monitoring for new `.txt` files in temp directories created by PowerShell processes — particularly when the creating process has a web-scanning command line — can surface this behavior.

**PowerShell privilege escalation event (EID 4703) preceding web scanner execution.** The token privilege adjustment for the parent PowerShell process (receiving `SeDebugPrivilege`, `SeLoadDriverPrivilege`, etc.) in the same time window as the scanner launch provides process-level context for why the scanning process ran with elevated capabilities.
