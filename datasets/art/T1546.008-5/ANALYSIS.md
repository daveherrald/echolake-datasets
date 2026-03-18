# T1546.008-5: Accessibility Features — Auto-start Application on User Logon

## Technique Context

T1546.008 (Accessibility Features) encompasses multiple mechanisms by which the Windows accessibility infrastructure can be hijacked for persistence or privilege escalation. This test exercises the same AT broker registration vector as test 4 — writing a custom `StartEXE` value under `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\` — but frames it specifically as a user-logon auto-start mechanism. The AT framework is invoked at logon, making this a reliable persistence hook. When a user logs on and activates accessibility features, or when the Ease of Access shortcut is triggered at the lock screen, the registered command executes under SYSTEM. Detection focuses on unauthorized writes to the `Accessibility\ATs\` key space and on `AtBroker.exe` spawning unexpected children.

## What This Dataset Contains

Sysmon EID 13 (RegistryValueSet) captures the central persistence write:

```
TargetObject: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Accessibility\ATs\malware_test\StartEXE
Details: C:\WINDOWS\system32\cmd.exe
Image: C:\Windows\system32\reg.exe
```

Sysmon EID 1 (ProcessCreate) records six process-create events: `whoami.exe` (SYSTEM context check from PowerShell), `cmd.exe` wrapping the `reg add` commands, three `reg.exe` invocations writing the AT subkey entries, and `cmd.exe` spawned as the result of AtBroker dispatching the registered command (matched on `technique_id=T1059.003` and `technique_id=T1012`).

Security EID 4688 covers six process creations including all `reg.exe` invocations and the `cmd.exe` that runs the registered payload. EID 4689 records eleven process terminations for the full chain including `conhost.exe` and `whoami.exe`. One EID 4703 (token right adjustment) appears for the SYSTEM session.

The PowerShell channel contains only test framework boilerplate across 27 events (EID 4103: `Set-ExecutionPolicy`, EID 4104: `Set-StrictMode` error handler fragments). No technique-specific PowerShell content is present — the AT key is written via `cmd.exe /c reg add`.

## What This Dataset Does Not Contain

The dataset does not include an EID 1 for `AtBroker.exe` itself — Sysmon's include-mode ProcessCreate rules captured the payload `cmd.exe` child but appear not to have generated a separate event for the `atbroker.exe` launch in this test run (compare with test 4, where `AtBroker.exe` does appear). This limits the traceability of the AtBroker invocation to the registry write and the resulting child shell. There is no Sysmon EID 12 for the AT subkey creation, no EID 4657 (Security audit of registry change), and no object access events because those audit categories are disabled.

## Assessment

This dataset is functionally very similar to T1546.008-4 and the core detection artifacts are identical: the Sysmon EID 13 registry write to `Accessibility\ATs\*\StartEXE` and the Security EID 4688 chain showing `reg.exe` under SYSTEM. The absence of an EID 1 for `AtBroker.exe` in this run (compared with test 4) is a useful illustration of how the same technique can produce slightly different telemetry depending on timing and Sysmon rule matching conditions. The registry write alone is a sufficient and high-fidelity detection anchor.

## Detection Opportunities Present in This Data

1. **Sysmon EID 13 — RegistryValueSet to `HKLM\...\Accessibility\ATs\*\StartEXE`** pointing to a shell or non-AT binary (`cmd.exe`) — core persistence artifact, tagged by sysmon-modular as `T1547.001`.
2. **Sysmon EID 1 — `reg.exe` process with command line containing `Accessibility\ATs\`** and a `StartEXE` value referencing a command interpreter, under SYSTEM context.
3. **Sysmon EID 1 — `cmd.exe` spawned from a parent associated with AT dispatch**, with empty or unexpected command line arguments — payload execution indicator.
4. **Security EID 4688 — Three rapid consecutive `reg.exe` process creations** from the same SYSTEM session writing to an Accessibility key path.
5. **Correlation: EID 13 `StartEXE` registry write followed by `cmd.exe` process create within the same second** — tight temporal coupling of registration and execution.
