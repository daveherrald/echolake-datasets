# T1562.002-7: Disable Windows Event Logging — Makes Eventlog Blind with Phant0m

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test uses a pre-compiled `Phant0m.exe` native binary to target the Windows Event Log service by killing its processing threads. The binary is pre-staged in the ART atomics repository at `C:\AtomicRedTeam\atomics\T1562.002\bin\Phant0m.exe` and is invoked directly via `cmd.exe` without any PowerShell script execution. This is distinct from T1562.002-3 (Invoke-Phant0m), which downloads the PowerShell variant from GitHub at runtime. Using a pre-compiled native binary avoids PowerShell script block logging and reduces the attack's dependence on internet connectivity.

## What This Dataset Contains

The dataset spans roughly five seconds and captures 126 events across PowerShell (107), Security (17), System (1), Application (1), and WMI (1) channels.

**Security (EID 4688):** Five process creation events. PowerShell (parent) spawns `whoami.exe` (test framework identity check), then spawns `cmd.exe` with the attack command:

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\T1562.002\bin\Phant0m.exe"
```

`cmd.exe` exits (EID 4689) — and crucially, no EID 4688 for `Phant0m.exe` itself appears. In the defended environment this was explained by Defender blocking the execution before process creation could be recorded. In this undefended environment, Phant0m was not blocked by Defender, so the absence requires a different explanation: either the process creation was not captured by the audit policy in the brief window, or Phant0m executed and completed so quickly that its creation and termination events were missed.

Additional Security events: `svchost.exe -k netsvcs -p -s BITS` (PID 0x46b8) was created by `services.exe` — this is the BITS (Background Intelligent Transfer Service) service starting, a background system event.

A SYSTEM batch logon sequence appears: EID 4624 (Logon Type 5, SYSTEM, from `C:\Windows\System32\services.exe`), EID 4627 (group membership enumeration, showing `Administrators`, `Everyone`, `Authenticated Users`, `High Mandatory Level`), and EID 4672 (special privileges assigned: SeAssignPrimaryTokenPrivilege, SeTcbPrivilege, SeSecurityPrivilege, SeLoadDriverPrivilege, SeBackupPrivilege, SeRestorePrivilege, SeDebugPrivilege, SeAuditPrivilege, SeImpersonatePrivilege, and others).

EID 4799 events (security-enabled local group membership enumerated): `svchost.exe` (PID 0x46b8, the BITS service) enumerated the `Administrators` and `Backup Operators` local groups — standard BITS startup behavior.

EID 4703 (token right adjusted): `powershell.exe` enabled a large set of privileges (SeAssignPrimaryTokenPrivilege, SeIncreaseQuotaPrivilege, SeSecurityPrivilege, SeTakeOwnershipPrivilege, SeLoadDriverPrivilege, SeSystemtimePrivilege, SeBackupPrivilege, SeRestorePrivilege, SeShutdownPrivilege, and others) — this is the PowerShell process asserting SYSTEM-level privileges.

Cleanup `cmd.exe`:
```
"cmd.exe" /c echo "Sorry you have to reboot"
```
This cleanup message — "Sorry you have to reboot" — is the ART test framework's acknowledgment that Phant0m executed and killed Event Log threads; recovery requires a reboot. This is the clearest indicator of successful execution.

**System (EID 7040):** The start type of the Background Intelligent Transfer Service changed from demand start to auto start — unrelated background configuration activity.

**Application (EID 15):** "Updated Windows Defender status successfully to SECURITY_PRODUCT_STATE_ON." — Windows Security Center background update.

**WMI (EID 5860):** A WMI temporary subscription was registered in `ROOT\CIMV2` with query `SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` — a WMI event subscription watching for WinRM process starts, placed by `NT AUTHORITY\SYSTEM` process 18104. This is background system management infrastructure, not related to the technique.

**PowerShell (EID 4103 + 4104):** 107 events. Three EID 4103 events record test framework-level cmdlets. EID 4104 events consist of ART test framework boilerplate across multiple runspace instances.

## What This Dataset Does Not Contain

**No EID 4688 for `Phant0m.exe`.** Unlike the defended run (where Phant0m was blocked before process creation), in this undefended run Phant0m either executed successfully without being captured by process creation auditing, or terminated so quickly that its creation and exit events were missed in the collection window. The cleanup message "Sorry you have to reboot" strongly implies successful execution.

**No thread termination events.** Windows does not generate security or system events for user-mode thread termination. Even in an undefended environment with full auditing, killing Event Log service threads leaves no Windows event trail beyond the evidence that the Event Log service is no longer writing events.

**No Sysmon events.** The defended variant had 16 Sysmon events including EID 1 (cmd.exe process create), EID 10 (process access), and EID 11 (file creates). Sysmon data is absent from this undefended dataset.

**More background noise than the defended variant.** The undefended dataset includes a SYSTEM batch logon sequence (4624/4627/4672), BITS service startup (4688, 4799), WMI subscription registration (5860), and BITS service type change (7040) that did not appear in the defended run. These are real Windows background activities that happened to coincide with the test window — they are not filtered out.

## Assessment

Phant0m executed successfully in the undefended environment. The cleanup message "Sorry you have to reboot" in the Security EID 4688 command line is a hard indicator of successful execution — the ART test framework only prints this message after Invoke-Phant0m or Phant0m runs. The absence of `Phant0m.exe` in EID 4688 is consistent with a very fast execution that completes before process creation auditing captures it, which is plausible for a tool that does targeted thread enumeration and termination.

Compared to the defended variant (which produced 0 Phant0m execution evidence because Defender blocked it), the undefended run demonstrates what successful execution looks like: the only direct indicators are the `cmd.exe` invocation command line and the cleanup message.

The rich background Security events (BITS startup, SYSTEM logon, WMI subscription) in this dataset illustrate authentic Windows environmental noise — a real system has constant background activity that co-occurs with attack telemetry in any given collection window.

## Detection Opportunities Present in This Data

- **Security EID 4688 (cmd.exe):** Command line `cmd.exe /c "C:\AtomicRedTeam\atomics\T1562.002\bin\Phant0m.exe"` — or more generally, any invocation of `Phant0m.exe` from any path.
- **Security EID 4688 (cleanup):** The string "Sorry you have to reboot" in any command line is a Phant0m post-execution indicator.
- **Absence of expected events:** After a successful Phant0m execution, Security channel events (4624, 4688, etc.) will stop being generated despite the system remaining active. Monitoring for sudden silence from a previously active host is a viable detection strategy.
- **Security EID 4688 (process chain):** `powershell.exe` → `cmd.exe` → `[binary from C:\AtomicRedTeam\]` as a general pattern for ART-staged binary execution warrants hunting, though the path would vary in real-world attacks.
- **WMI EID 5860 + Security 4799 (background noise):** The co-occurrence of BITS startup, WMI subscriptions, and group enumeration events near the attack window are real environmental noise — they should not be treated as attack indicators in isolation, but may appear in any dataset collected around this technique.
