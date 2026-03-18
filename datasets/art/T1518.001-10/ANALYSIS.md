# T1518.001-10: Security Software Discovery — Security Software Discovery - Windows Firewall Enumeration

## Technique Context

T1518.001 (Security Software Discovery) encompasses reconnaissance of host-based security
controls. This test specifically enumerates the Windows Firewall configuration using built-in
PowerShell networking cmdlets. Adversaries collect firewall profile state, global settings,
and rule listings to understand what network traffic may be blocked or monitored, informing
decisions about C2 protocols, lateral movement paths, and data exfiltration vectors.

## What This Dataset Contains

The test executes three firewall enumeration cmdlets in a single PowerShell command block as
NT AUTHORITY\SYSTEM:

```
powershell.exe & {Get-NetFirewallProfile | Format-Table Name, Enabled
Get-NetFirewallSetting
Get-NetFirewallRule | select DisplayName, Enabled, Description}
```

**Sysmon (47 events, EIDs 1, 7, 10, 11, 17):**
The EID 1 ProcessCreate captures the full command line verbatim, classified by sysmon-modular
as `technique_id=T1083,technique_name=File and Directory Discovery`. The preceding
`whoami.exe` spawn (EID 1, `technique_id=T1033`) is the ART test framework pre-flight. The remaining
Sysmon events are EID 7 ImageLoad events (DLLs loaded by the PowerShell processes, tagged
with `T1055`, `T1059.001`, `T1574.002`), EID 17 named pipe creates (`\PSHost.*`), EID 11
file creation in the SYSTEM profile temp path, and EID 10 process access events.

**Security (14 events, EIDs 4688, 4689, 4703):**
4688 records `whoami.exe` and the child `powershell.exe` with the full enumeration command
line. Both exit with status 0x0 (4689). A 4703 token right adjustment event is present for
the SYSTEM session.

**PowerShell (39 events, EIDs 4103, 4104):**
Two 4103 module logging events record `Set-ExecutionPolicy -Scope Process -Force -ExecutionPolicy Bypass` — the standard ART test framework execution policy bypass. The remaining 37
events are 4104 script block records for PowerShell's internal formatter methods
(`$_.PSMessageDetails`, `$_.ErrorCategory_Message`, `$_.OriginInfo`, etc.). These are
boilerplate from PowerShell's object formatting pipeline, not from the enumeration script
itself. The actual cmdlet invocations appear only in the command line visible in 4688 and
Sysmon EID 1.

**System (1 event, EID 7040):**
A single System channel event records that the Background Intelligent Transfer Service (BITS)
start type changed from auto to demand start. This is an OS-level side effect during the
test window, not caused by the firewall enumeration test.

**WMI (1 event, EID 5858):**
A WMI error event records a failed `ExecNotificationQuery` attempting to subscribe to
`Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` — a WMI subscription setup
that returned `0x80041032` (subscription was too complex or quota was exceeded). This is a
background system activity unrelated to the test, likely from another monitoring component
running on the system.

## What This Dataset Does Not Contain (and Why)

**Firewall rule enumeration results:** `Get-NetFirewallRule` can return hundreds or thousands
of entries on a configured Windows host. None of this output is captured in any event log
channel. Script block logging records what was run, not what was returned.

**Sysmon EID 3 (network connections):** The firewall enumeration cmdlets are read-only WMI
queries. They do not establish outbound network connections, so there are no EID 3 events
from this test.

**Defender alerts or blocks:** Windows Defender did not flag or block any aspect of this
test. Native Windows networking cmdlets querying firewall state are not considered malicious
by Defender's behavior monitoring. No 0xC0000022 exit codes are present.

**DNS queries or network telemetry:** All activity is local WMI/COM; no network lookups occur.

## Assessment

The test completed successfully — all cmdlets ran to completion as SYSTEM with 0x0 exit
codes. The firewall configuration was enumerated without triggering any defensive response.
The BITS service type change and WMI error are incidental background events unrelated to
this test. The core detection surface is the command line in 4688 and Sysmon EID 1, which
is distinctive and reliable.

## Detection Opportunities Present in This Data

- **Sysmon EID 1 / Security 4688:** Command line contains `Get-NetFirewallProfile`,
  `Get-NetFirewallSetting`, and `Get-NetFirewallRule` in a single inline block. Any of these
  cmdlets invoked from a non-interactive SYSTEM session (TerminalSessionId 0) with no
  script path warrants scrutiny.
- **Sysmon EID 1 / Security 4688:** `whoami.exe` spawned from `powershell.exe` with
  SYSTEM integrity and session ID 0, paired with subsequent firewall enumeration, is a
  recognizable automated reconnaissance pattern.
- **PowerShell EID 4103:** `Set-ExecutionPolicy Bypass -Scope Process` as the first logged
  PowerShell command in the session is a reliable indicator of test framework-style execution.
- **Contextual chain:** The three T1518.001 tests in this dataset (tests 9, 10, 11) ran
  within a 90-second window, all from the same parent PowerShell process on the SYSTEM
  account. A detection that correlates multiple security software discovery queries within
  a short window from a non-interactive session would catch this cluster.
