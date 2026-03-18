# T1595.003-1: Wordlist Scanning — Web Server Wordlist Scan

## Technique Context

T1595.003 (Active Scanning: Wordlist Scanning) covers adversary enumeration of web servers by requesting paths from a wordlist to discover hidden directories, backup files, administrative interfaces, and other exposed resources. This is a foundational reconnaissance technique used by both automated scanners (gobuster, dirbuster, ffuf) and purpose-built scripts. This test uses an Atomic Red Team PowerShell module (`WebServerScan.ps1`) that wraps `Invoke-WebRequest` to probe a local web server (`http://localhost`) with a wordlist, saving results to a temp file.

## What This Dataset Contains

The dataset spans roughly 5 seconds across three log sources (27 Sysmon events, 12 Security events, 40 PowerShell events).

**PowerShell Event 4104** captures the complete attack payload:

```
Import-Module "C:\AtomicRedTeam\atomics/T1595.003/src/WebServerScan.ps1"
Invoke-WordlistScan -Target "http://localhost" -Wordlist "C:\AtomicRedTeam\atomics/T1595.003/src/wordlist.txt"
  -Timeout "5" -OutputFile "$env:TMPDIR/wordlist_scan.txt"
Write-Host "Scan complete. Results saved to: $env:TMPDIR/wordlist_scan.txt"
```

Additional 4104 events capture the scanner module source code itself as it is loaded:
- `Test-Target`: a wrapper around `Invoke-WebRequest` that checks reachability of the target URL
- `Invoke-WordlistScan`: iterates the wordlist, calling `Test-Target` for each path and recording hits

**Sysmon Event 1** (ProcessCreate) shows `whoami.exe` (tagged `technique_id=T1033`) from the ART test framework and a cleanup PowerShell process (tagged `technique_id=T1083`). The second PowerShell process is tagged under File and Directory Discovery because cleanup likely checks for the output file.

**Sysmon Event 10** (ProcessAccess) records the test framework process accessing child processes, tagged `technique_id=T1055.001`.

**Sysmon Event 7** (ImageLoad) shows .NET runtime and Windows Defender DLL loads into each PowerShell instance.

**Security Event 4688** records `powershell.exe` and `whoami.exe` creation. Event 4703 records token adjustments.

## What This Dataset Does Not Contain

Network connection events (Sysmon Event 3) are absent. The scan targets `http://localhost` — connections to the loopback interface may not generate Sysmon network events depending on configuration, or the web server may not be running (causing the `Test-Target` reachability check to return false and abort the scan). No DNS query (Sysmon Event 22) is generated for `localhost`. No file write for the output file `wordlist_scan.txt` is captured in Sysmon Event 11 — either the scan aborted early or the output path resolved to a location outside the monitored temp directory.

The scan module's `Invoke-WebRequest` calls would generate HTTP requests visible in network traffic, but no network collection is included in this dataset. Web server access logs (IIS, Apache) are not present.

The Sysmon ProcessCreate include-mode filter does not match `powershell.exe` running a pure web-request loop, so the actual scanning process's process creation is captured only in Security Event 4688, not in Sysmon Event 1.

## Assessment

The PowerShell script block log fully discloses the scan intent, target URL, wordlist path, and output file. The scanner module's full source code is also captured as it loads, which is unusual and useful: the `Invoke-WordlistScan` and `Test-Target` function bodies appear verbatim in Event 4104, allowing defenders to understand the exact scanning logic. The absence of network telemetry is the main gap — confirming whether the scan actually executed against the web server requires additional data sources. Defender was active and did not block this test.

## Detection Opportunities Present in This Data

- **PowerShell Event 4104**: `Import-Module` followed by `Invoke-WordlistScan` or any function that iterates a wordlist file against a web target; the function name and target URL are present in clear text.
- **PowerShell Event 4104**: Loading a custom `.ps1` module from an atomics or tool directory (e.g., `C:\AtomicRedTeam\`, non-standard paths) warrants scrutiny regardless of the module's specific content.
- **PowerShell Event 4103**: `Invoke-WebRequest` called repeatedly in a loop (visible via module logging iterations) with different URI paths is a high-confidence indicator of programmatic web scanning.
- **Sysmon Event 3** (if present in other deployments): Bursts of outbound HTTP connections from `powershell.exe` to a single host at high frequency would indicate wordlist-style scanning.
- **Security Event 4688**: PowerShell as NT AUTHORITY\SYSTEM invoking a custom module against a local or remote web server.
