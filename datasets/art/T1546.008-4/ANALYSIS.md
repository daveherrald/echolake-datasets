# T1546.008-4: Accessibility Features — Atbroker.exe (AT) Executes Arbitrary Command via Registry Key

## Technique Context

T1546.008 (Accessibility Features) covers the abuse of Windows accessibility infrastructure for persistence and privilege escalation. This test exercises a less-commonly documented sub-variant: the Assistive Technology Broker (`AtBroker.exe`) can be directed to launch an arbitrary executable by registering a custom "AT" entry under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\`. The `StartEXE` value in that key specifies what binary to run. When `atbroker /start <name>` is executed, Windows will launch the registered binary in the security context of the caller. From the lock screen, Winlogon can trigger AT binaries as SYSTEM. This persistence mechanism is stealthier than direct binary replacement and survives file integrity checks on the original accessibility executables. Detection focuses on registry writes to the `Accessibility\ATs\` key space, and on `AtBroker.exe` launching unexpected child processes.

## What This Dataset Contains

The test registers a malicious AT entry and then invokes AtBroker to trigger it. Sysmon EID 13 (RegistryValueSet) captures the write directly:

```
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware_test\StartEXE
Details: C:\WINDOWS\system32\cmd.exe
Image: C:\Windows\system32\reg.exe
```

Sysmon EID 1 (ProcessCreate) captures the full execution chain across seven events:
- `whoami.exe` (pre-exec context check, parent `powershell.exe`)
- `cmd.exe` invoking `reg add "HKLM\Software\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware_test..."` with three separate `reg.exe` invocations (AT key creation, `StartEXE` value, `ATExe` value — each triggering a separate rule match)
- `AtBroker.exe` with `CommandLine: atbroker /start malware_test` (matched on Sysmon rule `technique_id=T1218,technique_name=System Binary Proxy Execution`)
- `cmd.exe` launched as a child of `AtBroker.exe` with `CommandLine: "C:\WINDOWS\system32\cmd.exe"` (blank arguments, the spawned payload), matched on `technique_id=T1546.008`

Security EID 4688 records seven process creations, including all three `reg.exe` invocations, the `atbroker.exe` invocation, and the resulting `cmd.exe` spawn. Security EID 4689 provides termination records. One EID 4703 (token right adjustment) is present for the SYSTEM logon session.

The PowerShell channel contains only test framework boilerplate (`Set-ExecutionPolicy`, `Set-StrictMode` error handler fragments) — no technique-specific PowerShell content, as the AT registration is performed via `cmd.exe /c reg add`.

## What This Dataset Does Not Contain

The actual `reg add` command lines in the Sysmon EID 1 messages are truncated in the stored events at 400 characters, but the registry value write itself is fully captured in EID 13. There is no EID 12 (RegistryCreateKey) for the creation of the `malware_test` subkey — the sysmon-modular config does not include an EID 12 rule matching this key path. Object access auditing is disabled, so there are no EID 4657 (registry value modification via audit) events that would complement the Sysmon coverage.

## Assessment

This is an excellent dataset for AtBroker-via-registry persistence detection. It contains the three most important artifacts in combination: the `reg.exe` command line writing to the AT key space (EID 1), the Sysmon EID 13 registry value set showing the exact malicious `StartEXE` value pointing to `cmd.exe`, and the subsequent `AtBroker.exe` → `cmd.exe` process chain (EID 1 matched on the T1546.008 rule). The Sysmon rule tagging on the `AtBroker.exe` and spawned `cmd.exe` events is particularly valuable because it provides pre-labeled ground truth for the most alertable moment in the chain.

## Detection Opportunities Present in This Data

1. **Sysmon EID 13 — RegistryValueSet to `HKLM\...\Accessibility\ATs\*\StartEXE`** with a value pointing to a non-AT binary (`cmd.exe`) — directly observable, tagged `technique_id=T1546.008`.
2. **Sysmon EID 1 — `reg.exe` command line containing `Accessibility\ATs\` registry path** with a `StartEXE` value being set; parent `cmd.exe` running as SYSTEM.
3. **Sysmon EID 1 — `AtBroker.exe` with argument `/start <name>`** where `<name>` is not a known Windows built-in AT name, tagged `technique_id=T1218`.
4. **Sysmon EID 1 — `cmd.exe` (or other shell) spawned as a child of `AtBroker.exe`** — atypical parent-child relationship, tagged `technique_id=T1546.008`.
5. **Security EID 4688 — Process chain `powershell.exe` → `cmd.exe` → `reg.exe` modifying `Accessibility\ATs` key** under SYSTEM context corroborates the Sysmon registry write.
6. **Correlation: EID 13 registry write to `ATs\*\StartEXE` followed within seconds by EID 1 `atbroker.exe /start <same name>`** — confirms the registration-then-trigger pattern.
