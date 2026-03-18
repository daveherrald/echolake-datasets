# T1562.001-21: Disable or Modify Tools — Stop and Remove Arbitrary Security Windows Service

## Technique Context

MITRE ATT&CK T1562.001 (Impair Defenses: Disable or Modify Tools) includes stopping and
unregistering security-related Windows services. Endpoint Detection and Response (EDR) and
Data Loss Prevention (DLP) products commonly run as named Windows services. An adversary
with sufficient privilege can use PowerShell's `Stop-Service` and `Remove-Service` cmdlets
to halt and deregister these agents. This technique is particularly notable because it
requires no specialized tools — the native service control functionality available in
PowerShell 6+ is sufficient. The ART test targets `McAfeeDLPAgentService` as a representative
security service.

## What This Dataset Contains

The dataset captures 35 Sysmon events, 8 Security events, and 50 PowerShell events spanning
approximately 5 seconds on ACME-WS02 (Windows 11 Enterprise, domain member of acme.local).

The attack payload is clearly visible in multiple log sources. Sysmon EID 1 captures the
child PowerShell process create with `RuleName: technique_id=T1059.001,technique_name=PowerShell`:

```
CommandLine: "powershell.exe" & {Stop-Service -Name McAfeeDLPAgentService
             Remove-Service -Name McAfeeDLPAgentService}
```

Security 4688 records the same command line. PowerShell 4104 script block logging records
both the wrapped ART invocation form and the unwrapped form:

```powershell
& {Stop-Service -Name McAfeeDLPAgentService
Remove-Service -Name McAfeeDLPAgentService}
```

The process lineage is: parent PowerShell (PID 1372, ART test framework) → child PowerShell
(PID 3212, attack payload). The `whoami.exe` pre-execution check appears in Sysmon EID 1
and Security 4688. All processes exit with status 0x0.

The absence of additional service control events is notable: both PowerShell processes
exit cleanly, but there are no Service Control Manager events (System log channel, not
collected here) to confirm whether the service was actually present or successfully stopped.

## What This Dataset Does Not Contain (and Why)

**No McAfee DLP service.** `McAfeeDLPAgentService` is not installed on this host.
`Stop-Service` against a non-existent service returns an error but does not cause the
PowerShell process to exit with a non-zero code when the error is not treated as terminating.
The exit code 0x0 confirms the command ran, not that it succeeded. Real-world attackers
would target services they have confirmed are running.

**No System log events.** The Service Control Manager logs service stop and removal events
to the System channel (`Microsoft-Windows-Service Control Manager`). The collection
configuration for this dataset does not include the System channel, so those events are
absent regardless of whether the service was present.

**No Security 4656/4663 (object access).** Audit policy has object access auditing disabled.
Service object access events that would appear under an object access policy are not present.

**No Sysmon EID 13 (registry).** Unregistering a service deletes its registry key under
`HKLM\SYSTEM\CurrentControlSet\Services\`. Since the service did not exist, no registry
deletion occurred.

## Assessment

The attack was executed and PowerShell exited cleanly. Without the target service installed,
the operation produced no observable service state change, but the command itself — the
intent artifact — is fully captured in Sysmon EID 1, Security 4688, and PowerShell 4104.
This dataset is representative of the detection surface for service-based security tool
removal regardless of whether the targeted service is present.

## Detection Opportunities Present in This Data

- **PowerShell 4104 script block containing `Stop-Service` + `Remove-Service` in combination
  with a service name**: The simultaneous use of both cmdlets is a strong signal. Legitimate
  service management rarely chains stop and remove in a single script block.

- **Security 4688 and Sysmon EID 1 command line**: The full command is captured at the
  process creation layer. Pattern matching on `Remove-Service` in PowerShell command lines
  is effective — this cmdlet has very few legitimate administrative uses in most environments.

- **Service name intelligence**: The target service name `McAfeeDLPAgentService` is specific
  to a known security product. Alerting on `Stop-Service` or `Remove-Service` targeting
  known security product service names provides targeted coverage.

- **Test framework context**: The parent PowerShell and child PowerShell relationship with execution
  policy bypass preceding the service manipulation is contextually consistent with automated
  attack tooling.
