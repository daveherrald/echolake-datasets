# T1562.002-4: Disable Windows Event Logging — Impair Windows Audit Log Policy

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test uses `auditpol.exe` to disable multiple audit policy subcategories across several categories (Account Logon, Logon/Logoff, Detailed Tracking, and others) using a single chained `cmd.exe` command. Disabling audit policy prevents Security event log entries from being generated for covered activity — logons, process creation, and other events cease to be recorded. This is a direct, immediate impairment of Windows Security audit logging.

## What This Dataset Contains

The dataset captures 93 events across Sysmon (20), Security (36), PowerShell (35), Application (2), and TaskScheduler (1) channels over a four-second window.

**Sysmon Event ID 1 (process create)** captures `cmd.exe` with the full attack command line:

```
"cmd.exe" /c auditpol /set /category:"Account Logon" /success:disable /failure:disable & auditpol /set /category:"Logon/Logoff" /success:disable /failure:disable & auditpol /set /category:"Detailed Tracking" /success:disable
```

This single cmd.exe process chains multiple `auditpol /set` commands to disable audit policy across multiple categories in one execution.

**Security Event ID 4719 (audit policy change)** fires multiple times, recording each subcategory modification. Captured subcategories include:
- Account Logon: Kerberos Service Ticket Operations — "Success removed, Failure removed"
- Account Logon: Credential Validation — "Success removed, Failure removed"
- Account Logon: Other Account Logon Events — "Success removed, Failure removed"
- Account Logon: Kerberos Authentication Service — "Success removed, Failure removed"
- Logon/Logoff: Logon — "Success removed, Failure removed"
- Logon/Logoff: IPsec Quick Mode, Main Mode, Extended Mode — "Success removed, Failure removed"
- Logon/Logoff: User / Device Claims, Network Policy Server — "Success removed, Failure removed"

This is the most direct possible telemetry for this technique: the audit subsystem generates 4719 events for each subcategory disabled, before those changes take effect (so the events are recorded even though the policy being changed would have generated them).

**PowerShell 4104** records the ART test framework invocation: `& {Set-ExecutionPolicy ...}` and the `whoami.exe` command. **Security 4688/4689** record process creates and exits for `whoami.exe`, `cmd.exe`, `powershell.exe`, and `conhost.exe` under `NT AUTHORITY\SYSTEM`.

**Application event** (ID 16384) and TaskScheduler 140 record background system events during the test window.

## What This Dataset Does Not Contain (and Why)

There are no Sysmon Event ID 1 records for the individual `auditpol.exe` child processes. The sysmon-modular include-mode filter does not match `auditpol.exe`, so the individual audit policy modification processes are not captured by Sysmon. Security 4688 also does not show `auditpol.exe` creates — it records only the `cmd.exe` that wraps the chained command. This is because the audit policy changes take effect as part of `auditpol.exe` execution, but the Security log captures the chained `cmd.exe` process.

The dataset does not include the full list of all subcategories disabled — the 4719 events present represent those captured within the time window. Several additional policy changes may have completed slightly outside the collection boundary.

## Assessment

The technique executed successfully. The chained `auditpol` command is confirmed via Sysmon process create, and the corresponding 4719 audit policy change events confirm the policy modifications took effect. This is a clean execution — Windows Defender does not block `auditpol.exe` as it is a legitimate administrative tool.

The irony of this technique is that its primary detection mechanism (Security 4719) fires precisely because auditing is still active at the moment the change is made. An attacker who disables auditing in this way leaves a complete record of what they disabled. However, if an attacker could disable 4719 auditing itself (Policy Change category), they could prevent that record from being written — though the process create events would remain.

## Detection Opportunities Present in This Data

- **Security 4719 (audit policy change):** Multiple 4719 events with "Success removed, Failure removed" changes across Account Logon and Logon/Logoff categories is a very high-fidelity detection. A single 4719 event with these parameters warrants investigation; a burst of them within seconds is definitive.
- **Sysmon 1 / Security 4688:** `cmd.exe` executing `auditpol /set` with `/success:disable /failure:disable` across multiple categories in a single chained command is directly detectable from command-line telemetry.
- **Parent process:** `cmd.exe` launched from `powershell.exe` running as `NT AUTHORITY\SYSTEM` with chained `auditpol` commands is anomalous in most environments.
- **Rate of change:** Multiple Security 4719 events within a 1-2 second window (especially all setting policies to disabled) is a reliable behavioral indicator independent of command-line content.
