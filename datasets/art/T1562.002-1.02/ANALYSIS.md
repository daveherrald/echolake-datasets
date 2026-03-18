# T1562.002-1: Disable Windows Event Logging — Disable Windows IIS HTTP Logging

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test disables HTTP access logging on IIS using `appcmd.exe`, the IIS command-line administration tool. IIS HTTP logging records every web request processed by the web server — source IP, URI, method, response code, and timing. Disabling it erases evidence of web-based payload delivery, exploitation via web application vulnerabilities, or C2 activity channeled through an IIS-hosted page. The command sets the `dontLog` flag to `true` on the Default Web Site's `httpLogging` configuration section in `applicationHost.config`.

This technique is relevant when attackers compromise an IIS server and want to suppress evidence of their web-based activity, or when a compromised host running IIS is used as a staging platform.

## What This Dataset Contains

The dataset spans roughly six seconds and captures 115 events across PowerShell (111) and Security (4) channels.

**Security (EID 4688):** Four process creation events document the attack and cleanup. PowerShell (parent) spawns `whoami.exe` (ART test framework identity check), then spawns a child `powershell.exe` with the attack command visible in its command-line field:

```
"powershell.exe" & {C:\Windows\System32\inetsrv\appcmd.exe set config "Default Web Site" /section:httplogging /dontLog:true}
```

The cleanup invocation also appears as a `powershell.exe` process creation:

```
"powershell.exe" & {if(Test-Path "C:\Windows\System32\inetsrv\appcmd.exe"){
 C:\Windows\System32\inetsrv\appcmd.exe set config "Default Web Site" /section:httplogging /dontLog:false *>$null
}}
```

This cleanup event confirms IIS was present on the test host and `appcmd.exe` was found at the expected path, meaning the technique was attempted against a real IIS installation.

**PowerShell (EID 4103 + 4104):** 111 events. Three EID 4103 (module logging) events record test framework-level cmdlet invocations. EID 4104 events include `Set-ExecutionPolicy Bypass -Scope Process -Force` (test framework setup), `$ErrorActionPreference = 'Continue'`, and the cleanup script blocks showing the `appcmd.exe` path test and `/dontLog:false` reversal. The attack invocation itself (`/dontLog:true`) is captured in both the `& {...}` wrapper block and the inner content block.

## What This Dataset Does Not Contain

**No `appcmd.exe` process creation event.** `appcmd.exe` is not matched by the Security 4688 audit policy in this environment for process creation, and Sysmon is absent from this dataset. The `appcmd.exe` invocation is confirmed by the parent PowerShell command line and the PowerShell script block logging, but no EID 4688 for `appcmd.exe` itself appears.

**No Sysmon events.** The defended variant captured 36 Sysmon events including EID 1 (process creates for `whoami.exe` and PowerShell), image loads, named pipe events, and process access events. None of that is present here.

**No IIS configuration change event.** IIS does not write to the Windows event log when `httpLogging` settings change. The modification takes effect in `applicationHost.config` without generating a Windows event. No EID 4656/4663 events for the configuration file appear (object access auditing is not active for that path).

**No IIS service events.** Disabling HTTP logging does not require IIS to restart. No `W3SVC` service events appear.

**Fewer events than the defended variant.** The defended run produced 36 Sysmon + 10 Security + 45 PowerShell events (91 total). The undefended run produced 111 PowerShell + 4 Security events (115 total). The PowerShell count is significantly higher in the undefended run due to additional test framework runspace activity — the core attack evidence (the `appcmd.exe` command in the process command line) is present in both.

## Assessment

The technique executed successfully. IIS was installed on the test host (confirmed by the existence of `C:\Windows\System32\inetsrv\appcmd.exe` and the successful cleanup reversal). The Security EID 4688 events capture the exact `appcmd.exe` command in the parent PowerShell's command-line field, providing a clear record of what was done. The absence of a dedicated `appcmd.exe` EID 4688 event is a genuine coverage gap — process creation auditing for non-standard executables depends on either enhanced auditing or Sysmon.

Because Defender was disabled, there was no behavioral block on this execution. `appcmd.exe` is a signed Microsoft binary and this operation would not trigger AV in any environment, so the undefended vs. defended comparison here is less about blocks and more about the Sysmon telemetry difference.

## Detection Opportunities Present in This Data

- **Security EID 4688 (parent PowerShell command line):** The string `appcmd.exe set config` followed by `/dontLog:true` is visible in the spawning PowerShell's command-line field — a clear indicator even without a dedicated `appcmd.exe` process creation event.
- **PowerShell EID 4104:** Script blocks containing `appcmd.exe set config "Default Web Site" /section:httplogging /dontLog:true` provide a second independent record with high specificity.
- **PowerShell EID 4103:** The test framework `Set-ExecutionPolicy Bypass` block combined with an `appcmd.exe` invocation in the same session is an unusual pairing that warrants investigation on IIS hosts.
- **Process ancestry:** `powershell.exe` spawned by `powershell.exe` (not a user shell or service host) is itself an indicator in environments where double-powershell execution is uncommon.
