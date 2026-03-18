# T1562.009-1: Safe Mode Boot — Safe Mode Boot

## Technique Context

MITRE ATT&CK T1562.009 (Safe Mode Boot) covers adversaries configuring a system to boot into
Safe Mode, where many third-party security products — endpoint detection and response agents,
antivirus services, and enterprise management agents — do not start. Ransomware operators
(notably REvil/Sodinokibi, BlackMatter, and BlackCat/ALPHV) have used this technique
immediately before triggering file encryption to ensure endpoint protection is inactive during
the encryption run. The technique requires administrator or SYSTEM privileges and typically
precedes a forced reboot.

## What This Dataset Contains

The test uses `bcdedit` to set the safe boot mode:

```
cmd.exe /c bcdedit /set safeboot network
```

Security EID 4688 records the full process chain: `powershell.exe` spawns `cmd.exe` which
spawns `bcdedit.exe` with `/set safeboot network`. Sysmon EID 1 captures the same three
processes with parent image annotations, confirming the chain. Sysmon EID 22 (DnsQuery)
records a lookup for `ACME-DC01.acme.local` by `svchost.exe` — background domain controller
DNS activity unrelated to the technique.

The PowerShell Operational log contains ART test framework artifacts: EID 4103 records
`Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass -Force` (the standard ART
pre-execution step) and EID 4104 contains boilerplate error handler scriptblocks.

## What This Dataset Does Not Contain (and Why)

No BCD store modification event from `bcdedit.exe` appears in Sysmon's registry monitoring
(EID 13) because BCD is stored as a binary file (`\Boot\BCD`) accessed via a special device
path, not the Windows registry hive. No file modification event (Sysmon EID 11) for the BCD
file appears — the sysmon-modular file creation rules do not target the BCD path.

No reboot occurs and no system shutdown events (Security EID 4609 or System EID 6006) are
present because the test only sets the boot configuration and does not initiate a restart.
There are no Windows Defender block events; `bcdedit.exe` is a signed Microsoft binary and
the `/set safeboot` operation is not flagged.

## Assessment

The test executed successfully; `bcdedit /set safeboot network` ran to completion under
SYSTEM context. The Security and Sysmon process creation logs provide clean evidence of the
attempt. The absence of a reboot means the configuration change has been staged but not
activated — in a real attack this would be followed by a forced restart (`shutdown /r /t 0`
or similar). Detectors should treat `bcdedit /set safeboot` as an immediate high-severity
indicator regardless of whether a reboot follows.

## Detection Opportunities Present in This Data

- **Security EID 4688**: `bcdedit.exe` command line containing `/set safeboot` — this is a
  rare, high-confidence indicator with essentially no legitimate administrative use at scale.
- **Sysmon EID 1**: `bcdedit.exe` process create with parent `cmd.exe` and grandparent
  `powershell.exe`; the command line includes `/set safeboot network` or `/set safeboot
  minimal`.
- **Process ancestry anomaly**: `powershell.exe` → `cmd.exe` → `bcdedit.exe` with safeboot
  arguments warrants immediate investigation; `bcdedit` should almost never appear in a
  typical endpoint process tree.
- **Chained detection**: Correlating `bcdedit /set safeboot` with a subsequent
  shutdown/restart command (within minutes) indicates active ransomware pre-encryption
  activity and should trigger immediate isolation.
