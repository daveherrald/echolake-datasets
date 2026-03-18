# T1562.002-5: Disable Windows Event Logging — Clear Windows Audit Policy Config

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test uses `auditpol /clear` combined with `auditpol /remove /allusers` to completely wipe all advanced audit policy configuration. Unlike T1562.002-4 which targets specific subcategories, this approach resets the entire audit policy to a baseline state with no subcategories configured, and then removes all per-user audit policy settings. The net effect is that all Security event auditing is disabled until policy is reapplied, typically by Group Policy refresh.

## What This Dataset Contains

The dataset captures 93 events across Sysmon (30), Security (29), and PowerShell (34) channels over a five-second window.

**Sysmon Event ID 1 (process create)** captures `cmd.exe` with the full attack command:

```
"cmd.exe" /c auditpol /clear /y & auditpol /remove /allusers
```

The `/y` flag suppresses the confirmation prompt, making this suitable for non-interactive execution. The command runs from `C:\Windows\TEMP\` under `NT AUTHORITY\SYSTEM`.

**Security Event ID 4719** fires multiple times recording each subcategory being cleared. Subcategories captured include Policy Change: Audit Policy Change, IPsec Driver, Authentication Policy Change; System: Security State Change; Object Access: Kernel Object — all showing "Success removed, Failure removed". This burst of 4719 events represents the audit policy system recording the removal of its own configuration entries.

**Security 4688/4689** records process lifecycle for `cmd.exe`, `powershell.exe`, `conhost.exe`, and `whoami.exe` as SYSTEM. The `cmd.exe` exits with status `0x0`, confirming success.

**Sysmon Event IDs 7, 10, 11, 13, 17** are present from the PowerShell test framework startup. The Sysmon 13 events capture background system registry writes (WSearch service configuration, UpdateOrchestrator scheduled task), not the audit policy modification itself — `auditpol.exe` operates through the LSA interface rather than writing directly to a registry key that Sysmon monitors.

**PowerShell 4104** records the ART test framework script blocks and the `whoami.exe` invocation. The `auditpol` command is visible in Security 4688 command-line logging rather than in a PowerShell script block, since it is executed by `cmd.exe` as a native process.

## What This Dataset Does Not Contain (and Why)

There are no Sysmon Event ID 1 events for `auditpol.exe` itself — the include-mode filter does not match it. Only `cmd.exe` and the PowerShell/whoami test framework processes appear in Sysmon process create events.

The 4719 events present are a representative sample from the test window. `auditpol /clear` removes all configured subcategories, which could generate dozens of 4719 events. The dataset contains those that fell within the capture window.

Unlike T1562.002-4, no `auditpol /set` commands appear — the clear operation is atomic rather than per-subcategory, so the command line shows only `/clear /y`.

## Assessment

The technique executed successfully. The `cmd.exe` exit status `0x0` and the burst of 4719 events confirm that audit policy was cleared. `auditpol /remove /allusers` is particularly impactful in a domain environment as it removes per-user audit policy overrides, which cannot be recovered without explicit re-application.

The same detection irony as T1562.002-4 applies here: the audit policy system generates 4719 events documenting its own destruction while it still can. The clear operation is slightly harder to detect post-execution because it leaves the policy table empty rather than showing explicit "disabled" entries, making differential analysis more challenging.

## Detection Opportunities Present in This Data

- **Security 4719:** A burst of 4719 events with "Success removed, Failure removed" changes is the primary indicator. Multiple such events within seconds of each other, across diverse categories, is characteristic of a bulk audit policy removal.
- **Security 4688 / Sysmon 1:** `cmd.exe` with `auditpol /clear /y` or `auditpol /remove /allusers` in the command line is a direct, high-fidelity detection. The `/y` flag is significant — it is used specifically to suppress interactive prompts for automation.
- **Process context:** `cmd.exe` spawned from `powershell.exe` running as SYSTEM from `C:\Windows\TEMP\` is contextually suspicious and should be investigated regardless of the command content.
- **Absence detection:** A security monitoring system that detects the *absence* of expected 4719 events (i.e., audit policy went from configured to empty without corresponding Group Policy application) provides coverage even after the fact.
