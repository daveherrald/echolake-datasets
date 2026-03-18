# T1614-1: System Location Discovery — Windows

## Technique Context

T1614 (System Location Discovery) covers adversary attempts to determine the geographic location of a target system. Location data can inform decisions about target value, time-zone-aware payload scheduling, or confirming that a compromised host is not a sandbox or honeypot. This test uses the built-in Windows `curl.exe` binary to query an external IP geolocation service and retrieve location metadata for the host's public IP address.

## What This Dataset Contains

The dataset spans roughly 4 seconds across three log sources (21 Sysmon events, 12 Security events, 34 PowerShell events).

**Sysmon Event 1** (ProcessCreate) records both the `cmd.exe` process (tagged `technique_id=T1059.003`) and `curl.exe` (tagged `technique_id=T1105`, Ingress Tool Transfer — a sysmon-modular heuristic for curl):
- `cmd.exe` spawned by the ART test framework PowerShell
- `curl.exe` (version 8.13.0) spawned from `cmd.exe`

The `curl.exe` command would include a URL for an IP geolocation service (e.g., `ipinfo.io`, `ipapi.co`, or similar) but the full command line is only visible in Security Event 4688. The Sysmon Event 1 truncates the `CommandLine` field at 350 characters in the captured output above, but both Sysmon and the Security log contain the full command line in their raw events.

**Security Events 4688/4689** record the creation and exit of `cmd.exe`, `curl.exe`, and their parent PowerShell process, all running as NT AUTHORITY\SYSTEM. Exit events confirm the processes ran to completion.

**Sysmon Event 10** (ProcessAccess) fires on the PowerShell test framework process accessing a child process, tagged `technique_id=T1055.001`.

**Sysmon Event 7** (ImageLoad) shows .NET runtime DLL loads for each PowerShell instance and Windows Defender components.

**Sysmon Event 17** (PipeCreate) records the `\PSHost.*` named pipe created for each PowerShell instance.

**PowerShell Events 4103/4104** capture the ART test framework (Set-ExecutionPolicy Bypass) but not the actual curl command line, since curl is invoked via cmd.exe outside of PowerShell.

## What This Dataset Does Not Contain

Network connection events (Sysmon Event 3) and DNS queries (Sysmon Event 22) are absent from this dataset, despite network monitoring being enabled in the Sysmon configuration. This is likely because the geolocation service request completed and the network events were either generated slightly outside the collection window or were filtered by the Sysmon configuration rules for the specific destination. A full Sysmon deployment would typically produce Event 3 for `curl.exe` connecting to an external IP and Event 22 for the DNS resolution of the geolocation service hostname.

The response body from the geolocation service — the actual location data retrieved — is not captured by any log source in this dataset.

The curl command-line arguments (the specific geolocation service URL) are present in Security Event 4688 and Sysmon Event 1 but were truncated at the preview stage; the full URL would be visible in the raw JSON of those events.

## Assessment

This is a lightweight, low-noise test. The primary indicators are the creation of `curl.exe` as a child of `cmd.exe` which is itself a child of `powershell.exe`, all running as SYSTEM. The curl binary is a Windows inbox tool in Windows 11 and is not inherently suspicious, but its use by SYSTEM in a chain originating from PowerShell, connecting to an IP-lookup service, is a detectable pattern. Defender was active and did not block this test.

## Detection Opportunities Present in This Data

- **Sysmon Event 1**: `curl.exe` spawned as a child of `cmd.exe` or directly from a scripting host (PowerShell, wscript, cscript), especially as NT AUTHORITY\SYSTEM. The `CommandLine` field contains the target URL.
- **Security Event 4688**: `curl.exe` process creation with command line referencing known IP-lookup domains (ipinfo.io, ipapi.co, ip-api.com, checkip.amazonaws.com, wtfismyip.com, etc.).
- **Sysmon Event 3** (expected in a full deployment): Outbound HTTP/HTTPS from `curl.exe` to IP geolocation service IPs.
- **Sysmon Event 22** (expected in a full deployment): DNS queries for geolocation service hostnames from `curl.exe` or its parent.
- **Process chain**: `powershell.exe` → `cmd.exe` → `curl.exe` → external IP lookup is an unusual execution chain on a domain workstation; `curl.exe` normally runs from user context via browser automation or developer tools.
