# T1562.002-9: Disable Windows Event Logging — PowerShell

## Technique Context

T1562.002 covers actions that disable or degrade Windows event logging. Test 9 is a variant of
test 8: rather than targeting an existing WINEVT channel key, it creates a new key under the
Group Policy path `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup` and sets a
`ChannelAccess` value there with a deny-all SDDL (`O:SYG:SYD:(D;;0x1;;;WD)`). Group Policy–
sourced WINEVT channel permissions override the default per-channel settings. The test then
restarts the Event Log service to apply the change. Because it uses `New-Item` to create the
policy key before writing the value, it is slightly more invasive than test 8.

## What This Dataset Contains

**Sysmon (42 events):** Sysmon ID 1 captures the PowerShell process with the ART command line:

```
"powershell.exe" & {New-Item -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup -Force
Set-ItemProperty -Path HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\Setup
-Name "ChannelAccess" -Value "O:SYG:SYD:(D;;0x1;;;WD)"
Restart-Service -Name EventLog -Force -ErrorAction Ignore}
```

There is no Sysmon 13 (registry value set) for the policy key write, because the sysmon-modular
include rules do not specifically target `SOFTWARE\Policies\Microsoft\Windows\EventLog`. However,
the EventLog service restart is captured: `svchost.exe -k LocalServiceNetworkRestricted -p -s
EventLog` appears as a Sysmon 1 event, and `lastalive0.dat` / `lastalive1.dat` file creation
events (Sysmon 11) confirm the restart. Image load (Sysmon 7) and named pipe creation (Sysmon 17)
events for the PowerShell process are present.

**Security (15 events):** Process creation and termination (4688/4689) for PowerShell and the
Event Log svchost. Security 1100 is present, confirming the Event Log service stopped. Token
adjustment (4703) is captured. No logon cluster this time — the service restart was under the
existing SYSTEM session.

**PowerShell (40 events):** Script block (4104) captures the full invocation including
`New-Item`, `Set-ItemProperty`, and `Restart-Service`. Module logging (4103) records each cmdlet
separately with all parameter bindings. ART test framework boilerplate (`Set-ExecutionPolicy Bypass`) is
present in multiple script block fragments along with the standard PowerShell error-handling inner
functions (`$_.PSMessageDetails`, `$_.ErrorCategory_Message`, etc.).

## What This Dataset Does Not Contain (and Why)

**No Sysmon 13 for the policy registry write.** The sysmon-modular config targets common attack
paths but does not include `SOFTWARE\Policies\Microsoft\Windows\EventLog` in its registry
monitoring rules. The write is confirmed only through PowerShell 4103 module logging.

**No registry delete/cleanup.** The ART cleanup step (restoring or removing the policy key) is
outside the collection window.

**No Windows Security audit policy changes.** This test targets only WINEVT channel access via
the policy hive.

**Sysmon ProcessCreate filtering** means only processes matching include rules appear in Sysmon 1;
Security 4688 provides complementary full-coverage process auditing.

## Assessment

The test completed successfully. The PowerShell script block and module log fully document the
attack sequence. Security 1100 and the EventLog svchost restart confirm the service was restarted.
The absence of a Sysmon 13 for the policy key is a genuine detection gap that analysts should
be aware of — registry monitoring rules should extend to `SOFTWARE\Policies\Microsoft\Windows\
EventLog`.

## Detection Opportunities Present in This Data

- **Sysmon 1 / Security 4688:** PowerShell launched with `New-Item` targeting
  `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog` and `Set-ItemProperty` setting
  `ChannelAccess` in the same command block.
- **PowerShell 4103:** `New-Item` on `HKLM:\SOFTWARE\Policies\Microsoft\Windows\EventLog\*`
  combined with `Set-ItemProperty` writing an SDDL deny value is a near-unique indicator.
- **PowerShell 4104:** The SDDL string `O:SYG:SYD:(D;;0x1;;;WD)` in any script block targeting
  EventLog policy paths should alert.
- **Security 1100 + 4688 svchost EventLog restart:** Programmatic restart of the Event Log
  service immediately after a PowerShell invocation is suspicious in isolation.
- **Registry monitoring gap:** Defenders should ensure EDR/Sysmon registry rules cover
  `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog` — this path is not caught by default
  sysmon-modular rules used here.
