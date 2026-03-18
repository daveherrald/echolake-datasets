# T1112-59: Modify Registry — Modify Internet Zone Protocol Defaults in Current User Registry (cmd)

## Technique Context

T1112 (Modify Registry) applied to Internet Explorer Zone Protocol Defaults manipulates how IE's security model handles different network protocols. This test sets `http` and `https` protocol default zone values to `0` under `HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults`, which places these protocols into Zone 0 — the "My Computer" zone, IE's most permissive security zone.

Internet Explorer's security model assigns web content to zones: Internet (3), Local Intranet (1), Trusted Sites (2), and My Computer (0). Zone 0 applies the same trust level as locally running code: scripts execute without prompts, ActiveX loads automatically, file downloads proceed without confirmation, and NTLM authentication credentials can be passed transparently. By remapping HTTP and HTTPS to Zone 0, an attacker causes IE and any Windows component using IE's security model to treat web traffic as if it came from the local machine — bypassing nearly all browser security controls.

This technique is distinct from the Zone Map domain additions in T1112-5. Rather than adding specific domains to the Trusted Sites list, this modifies the protocol-level defaults, affecting all HTTP and HTTPS traffic globally. It is a more aggressive and broader security control bypass.

The `ProtocolDefaults` key is checked by Internet Explorer and by Windows components that use the `IInternetSecurityManager` interface — including legacy ActiveX-dependent applications, Windows Help systems, and some Office components. Setting protocol defaults to Zone 0 is a highly effective bypass technique on systems that still rely on IE's security model.

In the defended variant, this dataset produced 36 Sysmon, 14 Security, and 34 PowerShell events. The undefended capture produced 18 Sysmon, 5 Security, and 93 PowerShell events. The Security event count is 5 in both variants, consistent with this test running two separate `reg add` commands (two `reg.exe` process creations plus `whoami.exe` plus `cmd.exe` plus one additional process).

## What This Dataset Contains

Like T1112-58, this technique uses a single `cmd.exe` invocation with two chained `reg add` commands. Sysmon EID 1 captures `cmd.exe` (PID 4496) spawned by PowerShell (PID 4904) with the full chain:

```
"cmd.exe" /c reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v http /t REG_DWORD /d 0 /F & reg add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v https /t REG_DWORD /d 0 /F
```

The first `reg.exe` instance (PID 5728) is captured in Sysmon EID 1:

```
reg  add "HKEY_CURRENT_USER\SOFTWARE\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults" /v http /t REG_DWORD /d 0 /F
```

The full parent command line (including both `reg add` commands) also appears as the `ParentCommandLine` in the `reg.exe` EID 1 event, confirming the chained execution structure.

Security EID 4688 records 5 process creation events: `whoami.exe`, `cmd.exe`, and three additional processes (the two `reg.exe` instances plus one more). The `cmd.exe` creation event contains the full chained command line.

Sysmon EID 10 records PowerShell accessing `whoami.exe` and `cmd.exe`. The pre-execution `whoami.exe` (PID 6868) ran approximately three seconds before the `cmd.exe` chain.

The PowerShell channel (93 EID 4104 events) contains ART test framework boilerplate, including a cleanup invocation: `Invoke-AtomicTest T1112 -TestNumbers 59 -Cleanup -Confirm:$false`.

## What This Dataset Does Not Contain

There are no Sysmon EID 12 or EID 13 events. The `HKCU\Software\Microsoft\Windows\CurrentVersion\Internet Settings\ZoneMap\ProtocolDefaults` path is not covered by the sysmon-modular registry monitoring configuration. The actual registry writes are not directly confirmed in Sysmon telemetry.

The dataset contains no Internet Explorer activity, no network events, and no authentication events. The zone mapping is established but no browsing or HTTP activity occurs within this capture window to demonstrate the effect.

There is no WMI or Application event log activity corresponding to IE security zone configuration changes. The modification is silent from the perspective of application-layer logging.

## Assessment

This dataset demonstrates a broad HTTP/HTTPS security bypass technique through a concise execution chain. The full command lines in Security EID 4688 and Sysmon EID 1 contain both the target registry path (`ProtocolDefaults`) and the zone value (`/d 0`), making the intent unmistakably clear: all HTTP and HTTPS traffic is being remapped to Zone 0.

Compared to T1112-5 (which added a specific domain to Trusted Sites), this technique is more impactful in scope. However, its detection footprint is similar — both rely on command-line telemetry since neither generates Sysmon registry events.

The 93 PowerShell events in the undefended run (compared to 34 in the defended run) is a substantial difference, likely reflecting that the defended run suppressed some ART test framework script block logging through Defender's interception of certain PowerShell operations.

The value `/d 0` setting HTTP and HTTPS to Zone 0 (My Computer) is the most operationally impactful registry write in this entire batch of tests. Most of the other T1112 tests disable notifications or configure thresholds; this one effectively eliminates IE's browser security model for all web traffic.

## Detection Opportunities Present in This Data

**`reg.exe` command line targeting `ProtocolDefaults` with `/d 0`.** The combination of the `ZoneMap\ProtocolDefaults` path and DWORD value `0` is a precise indicator of zone bypass. The value `0` maps to Zone 0 (My Computer), which is an unambiguously anomalous assignment for `http` or `https` protocols.

**Chained `cmd.exe /c reg add ... & reg add ...` for ZoneMap paths.** The `&` pattern with two sequential `reg add` calls on HKCU ZoneMap paths is consistent with automated script execution and indicates the attacker is systematically modifying multiple zone settings.

**HTTP/HTTPS ProtocolDefaults modifications from non-IE processes.** Internet Explorer itself modifies `ProtocolDefaults` during installation and security zone resets, using `IEXPLORE.EXE` as the process. A modification from `reg.exe` launched from a PowerShell chain is anomalous.

**Combination of T1112-5 and T1112-59 in the same session.** T1112-5 targeted specific domain entries in `ZoneMap\Domains`; T1112-59 targeted global protocol defaults. Together, these two modifications create comprehensive IE security zone bypass. Detecting either in proximity to the other reinforces the interpretation that a systematic browser security bypass is underway.
