# T1574.012-2: COR_PROFILER — System Scope COR_PROFILER

## Technique Context

T1574.012 (COR_PROFILER) abuses the .NET Common Language Runtime profiling API to load an attacker-controlled DLL into every .NET process that starts on the system. The CLR checks environment variables — `COR_ENABLE_PROFILING`, `COR_PROFILER` (a CLSID), and `COR_PROFILER_PATH` (the DLL path) — and loads the nominated DLL before executing managed code. When set in the **system** environment (under `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Environment`), every .NET process launched on the host will load the profiler DLL, making this a powerful persistence and privilege escalation primitive. This test (number 2) sets system-scope variables using `New-ItemProperty` against the HKLM path.

## What This Dataset Contains

The dataset spans roughly 4 seconds of activity across three log sources (29 Sysmon events, 10 Security events, 37 PowerShell events).

**PowerShell script block logging** captures the full attack payload:

```
New-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment'
  -Name "COR_ENABLE_PROFILING" -PropertyType String -Value "1"
New-ItemProperty ... -Name "COR_PROFILER" -Value "{09108e71-974c-4010-89cb-acf471ae9e2c}"
New-ItemProperty ... -Name "COR_PROFILER_PATH" -Value "C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll"
```

The CLSID `{09108e71-974c-4010-89cb-acf471ae9e2c}` and profiler DLL path are logged verbatim in 4104 (script block) and 4103 (module logging) events.

**Sysmon Event 13** (RegistryValueSet) records all three registry writes with `RuleName: technique_id=T1546.008` (the sysmon-modular rule that fires on Session Manager environment key modifications):
- `HKLM\System\CurrentControlSet\Control\Session Manager\Environment\COR_ENABLE_PROFILING` = `1`
- `HKLM\System\CurrentControlSet\Control\Session Manager\Environment\COR_PROFILER` = `{09108e71-974c-4010-89cb-acf471ae9e2c}`
- `HKLM\System\CurrentControlSet\Control\Session Manager\Environment\COR_PROFILER_PATH` = `C:\AtomicRedTeam\atomics\T1574.012\bin\T1574.012x64.dll`

**Sysmon Event 1** (ProcessCreate) records `whoami.exe` spawned under the ART test framework (rule: `technique_id=T1033`) and a second PowerShell process launched to verify or clean up the registration.

**Sysmon Event 10** (ProcessAccess) fires on cross-process memory access from PowerShell to another PowerShell instance, tagged `technique_id=T1055.001`.

**Security Event 4688** records two new process creation events for `powershell.exe` (the test and cleanup stages), along with `whoami.exe`. Event 4703 (token right adjusted) and 4689 (process exit) round out the session lifecycle.

## What This Dataset Does Not Contain

The dataset does not contain evidence of the profiler DLL actually being loaded by a victim .NET process. The test sets the registry keys but the per-test cleanup removes them before a long-lived .NET process would restart and trigger a load. No Sysmon Event 7 (ImageLoad) for `T1574.012x64.dll` appears. Registry read events are not captured (object access auditing is disabled). The test also does not demonstrate a DLL with any payload — no network connection, no file drop by the profiler.

The Sysmon ProcessCreate filter is in include-mode; most routine process creations are suppressed. Security Event 4688 provides complementary full-coverage process telemetry.

## Assessment

This dataset successfully demonstrates the **write** half of the T1574.012 system-scope attack path: the three defining registry values are written and captured across both Sysmon (Event 13) and PowerShell script block logging. The CLSID and DLL path are present in clear text in multiple events. The dataset does not show the persistence effect (DLL injection into a victim process), but it provides high-fidelity write-phase telemetry. Execution is via QEMU guest agent as NT AUTHORITY\SYSTEM, with Windows Defender fully active; Defender did not block this test.

## Detection Opportunities Present in This Data

- **Sysmon Event 13**: Registry writes to `HKLM\...\Session Manager\Environment` for `COR_ENABLE_PROFILING`, `COR_PROFILER`, or `COR_PROFILER_PATH` by any process other than a known installer. The CLSID and path are present in the `Details` field.
- **PowerShell Event 4104**: Script blocks containing `COR_ENABLE_PROFILING`, `COR_PROFILER`, or `New-ItemProperty` targeting the Session Manager Environment key.
- **PowerShell Event 4103**: `New-ItemProperty` command binding with the HKLM Session Manager path as the target.
- **Security Event 4688**: PowerShell process creation with command line containing `New-ItemProperty` and the Session Manager key path (requires command-line auditing, which is enabled here).
- Correlation: three registry writes to the same parent key within milliseconds, all from the same PowerShell PID, is a high-fidelity pattern.
