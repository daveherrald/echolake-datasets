# T1547.010-1: Port Monitors — Port Monitors - Add Port Monitor Persistence in Registry

## Technique Context

T1547.010 (Port Monitors) exploits the Windows print architecture's ability to load arbitrary DLLs as port monitors. Port monitor DLLs are registered under `HKLM\System\CurrentControlSet\Control\Print\Monitors\` and are loaded by the Print Spooler service (`spoolsv.exe`) when it starts. Because the Spooler runs as SYSTEM, any DLL loaded as a port monitor executes with SYSTEM-level privileges. Adding a malicious entry to this registry path requires only SYSTEM or Administrator access, and the DLL is loaded automatically every time the Spooler service starts — which happens at every boot. This technique was used by Stuxnet and has appeared in multiple post-exploitation frameworks.

## What This Dataset Contains

The test uses `cmd.exe` and `reg.exe` to write a port monitor registry entry. A Sysmon EID 13 (RegistryEvent - Value Set) captures the write with the rule tag `technique_id=T1547.010,technique_name=Port Monitors`:

```
Registry value set:
  RuleName: technique_id=T1547.010,technique_name=Port Monitors
  Image: C:\Windows\system32\reg.exe
  TargetObject: HKLM\System\CurrentControlSet\Control\Print\Monitors\AtomicRedTeam\Driver
  Details: C:\AtomicRedTeam\atomics\T1547.010\bin\PortMonitor.dll
  User: NT AUTHORITY\SYSTEM
```

This is one of the few tests in this batch where the sysmon-modular rule correctly fires with the expected T1547 technique tag.

Sysmon EID 1 captures three processes: `whoami.exe` (T1033), `cmd.exe` (T1083), and `reg.exe` (T1083). The `cmd.exe` and `reg.exe` command lines are both captured:

```
cmd.exe: "cmd.exe" /c reg add "hklm\system\currentcontrolset\control\print\monitors\AtomicRedTeam"
         /v "Driver" /d "C:\AtomicRedTeam\atomics\T1547.010\bin\PortMonitor.dll" /t REG_SZ /f

reg.exe: reg add "hklm\system\currentcontrolset\control\print\monitors\AtomicRedTeam"
         /v "Driver" /d "C:\AtomicRedTeam\atomics\T1547.010\bin\PortMonitor.dll" /t REG_SZ /f
```

Sysmon event counts: 18 events across EID 1 (3), EID 7 (9), EID 10 (2), EID 11 (2), EID 13 (1), EID 17 (1). Security events: 12 events (4688 × 3, 4689 × 8, 4703 × 1). PowerShell events: 32, predominantly boilerplate; no substantive EID 4104 entries because `reg.exe` is invoked via cmd rather than a PowerShell cmdlet.

## What This Dataset Does Not Contain

**No DLL loading by spoolsv.exe** — the PortMonitor.dll is only loaded when the Print Spooler restarts, which does not occur during this test window. No Sysmon EID 7 for the DLL is present.

**No Print Spooler restart** — the test does not stop and restart the Spooler after writing the registry entry. In T1547.012-1 (Print Processors), the Spooler is explicitly restarted; here it is not.

**No PowerShell EID 4104 with attack content** — the technique is implemented via cmd.exe/reg.exe, bypassing PowerShell script block logging for the attack action itself. PowerShell is only present as the ART test framework wrapper.

**No Sysmon EID 12 (key creation)** — the `AtomicRedTeam` key under `Print\Monitors` is created as a new key, but Sysmon EID 12 is not in the captured events. Only EID 13 (value set for the `Driver` value) is captured.

**Object access auditing is disabled**, so no Security EID 4657 events are present.

## Assessment

The test ran to completion. The port monitor registry entry is confirmed by Sysmon EID 13 with correct T1547.010 rule tagging, and by the `reg.exe` command lines captured in both Sysmon EID 1 and Security EID 4688. This is a clean, well-instrumented capture of the registry write phase. The `reg.exe`-based implementation means detection relies primarily on registry event monitoring and command-line inspection rather than PowerShell logging.

## Detection Opportunities Present in This Data

- **Sysmon EID 13**: The sysmon-modular ruleset correctly tags this event as T1547.010. Any write to `HKLM\System\CurrentControlSet\Control\Print\Monitors\*\Driver` by a process other than a trusted printer driver installer is a high-confidence indicator.
- **Sysmon EID 1 / Security EID 4688**: The `reg.exe` command line contains the full `Print\Monitors` path and `PortMonitor.dll` value, providing detection via process creation auditing independent of registry monitoring.
- **Security EID 4688**: `cmd.exe /c reg add` with `Print\Monitors` in the argument string is a reliable detection rule with low expected false-positive rate.
- The process chain `powershell.exe` → `cmd.exe` → `reg.exe` targeting a Print registry path is a compact, detectable attack sequence.
- Monitoring for new keys created under `HKLM\System\CurrentControlSet\Control\Print\Monitors\` (other than known printer driver installations) is a proactive detection approach for this technique.
