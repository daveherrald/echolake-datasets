# T1562.002-10: Disable Windows Event Logging — Modify Event Log Access Permissions via Registry - PowerShell

## Technique Context

T1562.002 (Disable Windows Event Logging) covers adversary actions to prevent or degrade Windows event log collection. This test modifies the Security Descriptor on a Windows event log channel by writing a restrictive `CustomSD` registry value that denies read access to everyone. The specific command sets `CustomSD` on `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\System` to `O:SYG:SYD:(D;;0x1;;;WD)` — an SDDL string that denies `0x1` (read) to `WD` (World/Everyone). This prevents any principal other than SYSTEM and the event log service from reading the System event log, potentially blocking SIEM agents, log collectors, and analyst queries.

## What This Dataset Contains

The dataset captures 87 events across Sysmon (39), Security (10), and PowerShell (38) channels over a five-second window.

**Sysmon Event ID 1 (process create)** captures `powershell.exe` with the full attack command line:

```
"powershell.exe" & {Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System -Name "CustomSD" -Value "O:SYG:SYD:(D;;0x1;;;WD)"}
```

The PowerShell process create is captured by Sysmon (rule: `T1083`) because the command line matches a file/directory discovery pattern, or more likely because the path contains `EventLog` which is covered by the include-mode rules.

**Sysmon Event ID 13 (registry value set)** records the direct result:

```
Registry value set
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
TargetObject: HKLM\System\CurrentControlSet\Services\EventLog\System\CustomSD
Details: O:SYG:SYD:(D;;0x1;;;WD)
User: NT AUTHORITY\SYSTEM
```

This is the authoritative record of the permission modification — the SDDL string `O:SYG:SYD:(D;;0x1;;;WD)` directly visible in the registry event.

**PowerShell 4104 (script block logging)** records the exact command twice (wrapper and inner block):

```
Set-ItemProperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\EventLog\System -Name "CustomSD" -Value "O:SYG:SYD:(D;;0x1;;;WD)"
```

**PowerShell 4103 (module logging)** is absent for this command — `Set-ItemProperty` executed inline does not generate a separate 4103 entry beyond what 4104 captures.

Additional Sysmon 13 events capture background WMI security descriptor changes (`HKLM\System\CurrentControlSet\Control\WMI\Security\*`) made by `svchost.exe` as a coincident system activity.

**Security 4688/4689** records process lifecycle for `powershell.exe`, `whoami.exe`, and `conhost.exe` under SYSTEM. Exit status `0x0` confirms success.

## What This Dataset Does Not Contain (and Why)

There are no Security 4719 events. Modifying `CustomSD` on an event log channel is a registry operation, not an audit policy change, so it does not trigger 4719. It also does not generate any dedicated Windows event log security event.

There are no application or system log events reflecting the permission change taking effect. The Windows Event Log service reads `CustomSD` at channel open time, so the impact would only be observed when a subsequent log read or forwarding operation fails — which is outside the capture window.

Object access auditing is disabled, so no 4656/4663 events appear for the registry key write. The Sysmon 13 event is the primary record of the change.

## Assessment

The technique executed successfully. The Sysmon 13 event explicitly records the SDDL value written to `CustomSD`, and the Security 4689 exit status `0x0` confirms success. This is a particularly interesting technique because it does not kill or stop the event log service — the log continues running and appearing healthy, but log readers (including Cribl Edge, Windows Event Forwarding, or wevtutil queries) will be denied access when they attempt to read the System log.

The combination of Sysmon Event ID 13 and PowerShell 4104 provides two independent records of this action, making it well-covered in this instrumentation environment.

## Detection Opportunities Present in This Data

- **Sysmon 13 (registry value set):** Writing to `HKLM\SYSTEM\CurrentControlSet\Services\EventLog\*\CustomSD` is a directly detectable indicator. No legitimate administrative process writes a deny-all SDDL to this key. A rule on `CustomSD` writes to EventLog service registry keys is high-fidelity.
- **PowerShell 4104:** The SDDL string `O:SYG:SYD:(D;;0x1;;;WD)` or any DACL containing `(D;;...;;;WD)` in a `Set-ItemProperty` targeting an EventLog path is a detectable pattern. More broadly, any `Set-ItemProperty` call writing to `HKLM:\SYSTEM\CurrentControlSet\Services\EventLog` with a `CustomSD` name should be alerted.
- **Sysmon 1 / Security 4688:** `powershell.exe` with `Set-ItemProperty` targeting `EventLog` registry paths is detectable from command-line content.
- **Operational impact detection:** If a SIEM or log forwarder loses access to the System event log with an access denied error following an anomalous registry write, that operational failure is itself a detection signal.
