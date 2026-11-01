# T1546-6: Load Custom DLL on mstsc Execution

## Technique Context

Atomic Red Team T1546 test 6 attempts to set `ClxDllPath` under `HKLM\SOFTWARE\Microsoft\Terminal Server Client`. The configured DLL is intended to load when `mstsc.exe` runs.

## Packaged Telemetry

The four bundled files contain 1,724 events from `2026-03-13T23:34:26.216000Z` through `2026-03-13T23:34:32.997000Z`.

| Channel | Events |
|---|---:|
| Security | 69 |
| Application | 12 |
| PowerShell | 1,593 |
| Sysmon | 50 |

PowerShell EID 4104 records `Invoke-AtomicTest T1546 -TestNumbers 6` at `2026-03-13T23:34:29.924000Z`.

Security EID 4688 at `2026-03-13T23:34:30.753000Z` and Sysmon EID 1 at `2026-03-13T23:34:30.758000Z` record this command attempt:

```text
"cmd.exe" /c reg add "HKLM\SOFTWARE\Microsoft\Terminal Server Client" /v ClxDllPath /t REG_SZ /d "C:\Windows\System32\amsi.dll" /f
```

Sysmon EID 1 at `2026-03-13T23:34:30.782000Z` records the child `reg.exe` process with the same registry arguments.

## Scope Limitations

The payload contains no process-creation event for `mstsc.exe` and no image-load event that shows `mstsc.exe` loading `amsi.dll`. Its Sysmon event set has no EID 12 or 13 registry event. The command lines establish an attempted registry change, but the package does not prove that the value was written or that a DLL later loaded.

## Detection Use

The strongest evidence in this package is the `reg add` command line targeting `Terminal Server Client\ClxDllPath`. Detection logic can match that registry path and value name in Security EID 4688, Sysmon EID 1, or PowerShell logging. A claim of successful persistence requires separate registry-change or `mstsc.exe` image-load evidence.
