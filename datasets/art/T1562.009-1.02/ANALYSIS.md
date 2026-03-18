# T1562.009-1: Safe Mode Boot — Safe Mode Boot

## Technique Context

MITRE ATT&CK T1562.009 (Safe Mode Boot) covers adversaries configuring a system to boot into Safe Mode, where many third-party security products — endpoint detection and response agents, antivirus services, and enterprise management agents — do not start. Ransomware operators (REvil/Sodinokibi, BlackMatter, BlackCat/ALPHV) have used this technique immediately before triggering file encryption to ensure endpoint protection is inactive during the encryption run. The technique requires administrator or SYSTEM privileges and typically precedes a forced reboot.

The attack command is:
```
bcdedit /set safeboot network
```

`network` safe mode boots with networking enabled — essential for ransomware C2 communication during encryption. The `safeboot minimal` variant (network-less) is also used when C2 is not needed during the encryption phase.

## What This Dataset Contains

The dataset spans roughly five seconds and captures 124 events across PowerShell (107) and Security (17) channels.

**Security (EID 4688):** Six process creation events document the full execution chain. PowerShell (parent) spawns `whoami.exe` (test framework identity check), then spawns `cmd.exe`:

```
"cmd.exe" /c bcdedit /set safeboot network
```

`cmd.exe` spawns `bcdedit.exe`:

```
bcdedit  /set safeboot network
```

Both processes run as `NT AUTHORITY\SYSTEM` (S-1-5-18, ACME\ACME-WS06$) with `TokenElevationTypeDefault (1)` and System integrity label. The cleanup invocation is also captured:

```
"cmd.exe" /c bcdedit /deletevalue {current} safeboot
```

With `bcdedit.exe` spawned as:

```
bcdedit  /deletevalue {current} safeboot
```

This cleanup confirms the attack phase ran successfully — `{current}` refers to the active boot entry, and `deletevalue safeboot` removes the boot mode setting that `/set safeboot network` established.

**Security (EID 4689):** Ten process exit events for all processes above.

**Security (EID 4703):** One token right adjustment for `powershell.exe` enabling the full SYSTEM privilege set.

**PowerShell (EID 4103 + 4104):** 107 events. Three EID 4103 events record `Set-ExecutionPolicy Bypass -Scope Process -Force` and related test framework cmdlets. EID 4104 events are ART test framework boilerplate across multiple runspace startups.

## What This Dataset Does Not Contain

**No Sysmon events.** The defended variant captured 28 Sysmon events including EID 1 (process creates for `whoami.exe`, `cmd.exe`, `bcdedit.exe`, and PowerShell with full parent-chain annotations), EID 22 (DNS query for `ACME-DC01.acme.local`), EID 7 (image loads), EID 10 (process access), EID 11 (file creates), and EID 17 (named pipe). None of that is present here.

**No BCD store modification event.** The BCD (Boot Configuration Data) store is stored as a binary file (`\Boot\BCD`) accessed via a special device path (`\\.\BCD`), not through the Windows registry hive. Sysmon EID 13 (RegistryValue Set) does not cover it, and Sysmon EID 11 (file create) does not match the BCD device path. No event source in this dataset confirms the BCD write succeeded — you are relying on the process creation record alone.

**No reboot.** The test sets the safe boot configuration but does not initiate a restart. No System EID 6006 (event log stopped), Security EID 4609 (Windows shutdown), or System EID 1074 (user initiated shutdown/reboot) appear. In a real ransomware attack, a forced restart would immediately follow.

**No boot-time events.** If the system had rebooted into safe mode, you would see dramatically different startup telemetry — services that normally start would be absent, EDR agent would not appear, and the boot mode would be reflected in System events. That phase is not captured here.

## Assessment

The technique executed successfully. Security EID 4688 events capture the complete process chain through `bcdedit /set safeboot network`, and the cleanup `bcdedit /deletevalue {current} safeboot` confirms the setting was applied. Because Defender was disabled, there was no behavioral block on `bcdedit.exe` and no tamper protection on the BCD store.

Compared to the defended variant (28 Sysmon + 12 Security + 34 PowerShell = 74 total), the undefended run produced 107 PowerShell + 17 Security events (124 total). The Security channel is richer in the undefended run (17 vs. 12 events) because additional process exit and token adjustment events were captured. The primary difference is the absent Sysmon data, which in the defended variant provided parent-chain-annotated process creates that are absent here.

The `bcdedit /set safeboot` command is one of the highest-severity Windows commands an attacker can execute — combined with its near-zero legitimate administrative use, it should be treated as an immediate priority indicator in any environment.

## Detection Opportunities Present in This Data

- **Security EID 4688 (`bcdedit.exe` command line):** `bcdedit /set safeboot` or `bcdedit /set safeboot network` or `bcdedit /set safeboot minimal` — any invocation of bcdedit setting the safeboot value. This command has essentially no legitimate use in normal enterprise operations and should trigger an immediate high-severity alert.
- **Security EID 4688 (`cmd.exe` command line):** The parent `cmd.exe` contains the full `bcdedit /set safeboot network` command, providing a second record before `bcdedit.exe` itself is created.
- **Process ancestry:** `bcdedit.exe` spawned by `cmd.exe` spawned by `powershell.exe` under SYSTEM context is consistent with both scripted attack tooling and legitimate administration — but the command content disambiguates these cases unambiguously.
- **Cleanup as confirmation:** `bcdedit /deletevalue {current} safeboot` in the cleanup phase is itself a secondary indicator — an attacker who successfully set safe boot mode but was detected or changed their mind might also issue this command, and its presence confirms a prior safe boot configuration.
- **Temporal correlation:** Seeing `bcdedit /set safeboot` followed by a shutdown or restart command (e.g., `shutdown /r /f /t 0`) within seconds or minutes is a near-certain indicator of imminent ransomware execution.
