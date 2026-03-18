# T1547.003-1: Time Providers — Create a New Time Provider

## Technique Context

T1547.003 (Time Providers) covers persistence via Windows Time Service (W32Time) DLL plugins. W32Time loads registered time provider DLLs at service startup, running them in the context of `svchost.exe`. An attacker can create a new time provider registry key under `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\` pointing to a malicious DLL, achieving persistence with `NT AUTHORITY\LOCAL SERVICE` or SYSTEM privileges. This technique requires administrator rights and survives reboots through the time service startup sequence. It is notable because the W32Time service is active on all domain-joined Windows hosts and the time provider mechanism is obscure relative to run keys, making it an evasion-friendly persistence path.

## What This Dataset Contains

The dataset captures an 8-second window on ACME-WS02 with unusually rich telemetry across four log sources (Sysmon, Security, PowerShell, System).

**PowerShell 4104 script block logging** captures the full test payload:

```powershell
net stop w32time
Copy-Item "C:\AtomicRedTeam\atomics\T1547.003\bin\AtomicTest.dll" C:\Users\Public\AtomicTest.dll
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\AtomicTest" /t REG_SZ /v "DllName" /d "C:\Users\Public\AtomicTest.dll" /f
reg add "...\AtomicTest" /v "Enabled" /t REG_DWORD /d 1 /f
reg add "...\AtomicTest" /v "InputProvider" /t REG_DWORD /d 1 /f
net start w32time
```

**Sysmon Event 13 (RegistrySetValue)** events confirm the three registry writes:

- `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\AtomicTest\DllName` → `C:\Users\Public\AtomicTest.dll`
- `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\AtomicTest\Enabled` → `DWORD (0x00000001)`
- `HKLM\System\CurrentControlSet\Services\W32Time\TimeProviders\AtomicTest\InputProvider` → `DWORD (0x00000001)`

None of these Sysmon 13 events carry a T1547.003 RuleName — they fired on the default catch-all rule (RuleName: `-`), indicating sysmon-modular does not have a named rule for the W32Time provider path. There is also a svchost-sourced Sysmon 13 write to `NtpClient\SpecialPollTimeRemaining` — a legitimate W32Time service reaction to the service restart.

**Sysmon Event 29 (FileExecutableDetected)** — `C:\Users\Public\AtomicTest.dll` is detected as a PE file written to a world-writable path, tagged `technique_id=T1059.001`. This event fires because Sysmon monitors for executable files created in suspicious locations.

**Sysmon Event 1 (ProcessCreate):** `whoami.exe` (T1033), `net.exe`/`net1.exe` (T1018) for the service stop/start, `powershell.exe` (T1083), and three `reg.exe` (T1083) invocations.

**Sysmon Event 22 (DNSQuery):** `svchost.exe` queries `ACME-DC01.acme.local` for NTP synchronization — a legitimate side effect of the W32Time service restart.

**Security Event 4616 (System Time Changed):** The W32Time service restart caused a time adjustment of ~6ms, generating this event with `NT AUTHORITY\LOCAL SERVICE` as the subject.

**System log events:** Four time-service-specific events including Event 1 (system time change), Event 24 (timezone refresh), Event 37 (NtpClient receiving valid data from domain controller), and Event 132/135 (NtpClient duplicate peer error) — all authentic side effects of the W32Time stop/start cycle.

## What This Dataset Does Not Contain

- **No DLL load into W32Time.** The service was restarted but because `AtomicTest.dll` is a stub, there is no telemetry of it successfully initializing as a time provider. A real malicious DLL would generate Sysmon Event 7 (ImageLoad) in svchost.exe.
- **No T1547.003-specific Sysmon rule match.** The registry writes were captured by the catch-all rule, not a named time provider monitoring rule.
- **No Security 4657 registry auditing.** Object access auditing is disabled.

## Assessment

This is the most telemetry-rich dataset in the T1547.003 group, with authentic side-effects across four log sources including Security 4616 (time change) and System log events from the W32Time service restart. The technique completed successfully — the DLL was placed in `C:\Users\Public\` and the time provider keys were created. Windows Defender did not block the DLL placement (the stub is benign) or the registry writes.

The multi-source corroboration makes this dataset valuable for building cross-channel detection logic: the Sysmon 13 events confirm the registry writes, the System log events confirm the service was restarted, and the PowerShell logs provide the full command context.

## Detection Opportunities Present in This Data

- **Sysmon Event 13:** Writes to `HKLM\SYSTEM\CurrentControlSet\Services\W32Time\TimeProviders\` creating a new subkey or writing a `DllName` value are high-confidence indicators. Legitimate time provider changes are extremely rare on workstations.
- **Sysmon Event 29 (FileExecutableDetected):** DLL written to `C:\Users\Public\` — world-writable locations hosting PE files warrant investigation.
- **Sysmon Event 1:** `net.exe stop w32time` followed by `reg.exe` modifying W32Time provider keys followed by `net.exe start w32time` is a recognizable sequence.
- **Security 4616:** Unexpected time changes (especially by `svchost.exe` immediately after manual `net stop/start w32time`) combined with registry modification events corroborate the attack.
- **System Event 37 / 132 / 135:** Anomalous W32Time service restart during business hours, especially accompanied by duplicate NTP peer errors, can serve as a weak supporting indicator.
- **PowerShell 4104:** Script blocks containing `TimeProviders` and `DllName` in registry paths, combined with `net stop w32time`, are high-confidence.
