# T1614.001-1: System Language Discovery — Discover System Language by Registry Query

## Technique Context

T1614.001 (System Language Discovery) covers adversary enumeration of the operating system's configured language, locale, and regional settings. Many malware families — particularly ransomware and nation-state tools — check system language to avoid attacking systems in certain regions or to tailor payload behavior. This test queries the registry key `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language` using `reg.exe` to retrieve the language identifier, and also uses `cmd.exe` to read the locale from the registry.

## What This Dataset Contains

The dataset spans roughly 6 seconds across three log sources (38 Sysmon events, 12 Security events, 36 PowerShell events).

**Sysmon Event 1** (ProcessCreate) records three technique-relevant processes:
- `whoami.exe` — ART test framework identity check (tagged `technique_id=T1033`)
- `cmd.exe` — command shell used to run the registry query (tagged `technique_id=T1083`)
- `reg.exe` — `reg query` against the NLS Language key (tagged `technique_id=T1083`)

The `cmd.exe` and `reg.exe` processes are captured because the sysmon-modular include rules match on `cmd.exe` as a known suspicious process launcher in certain contexts and on `reg.exe` as a file/directory discovery tool.

**Security Event 4688** records all process creations with full command lines, including:
- `reg.exe` with the specific registry query arguments targeting the NLS Language key
- `cmd.exe` with its argument string

**Sysmon Event 3** (NetworkConnect) appears in this dataset — tagged `technique_id=T1036` (Masquerading). This is a background event from `MpDefenderCoreService.exe` making a network connection (timestamped approximately 9 hours after the test), collected because the event fell within the dataset's time window. It is not related to the technique.

**Sysmon Event 10** (ProcessAccess) records the PowerShell test framework accessing child processes, tagged `technique_id=T1055.001`.

**Sysmon Event 7** (ImageLoad) captures .NET runtime and Windows Defender DLL loads into PowerShell instances.

**PowerShell Events 4103/4104** contain only the ART test framework (`Set-ExecutionPolicy Bypass`). The language discovery itself runs through `cmd.exe` and `reg.exe`, which are outside the PowerShell logging pipeline.

## What This Dataset Does Not Contain

Registry read events are not captured. The audit policy has object access auditing disabled, so there are no Security events for the registry key read. Sysmon does not log registry read operations (only Event 12/13/14 for create/set/delete). The actual value returned by `reg query` — the NLS language ID — is not captured in any log source.

No network connections to external services are expected or present (excluding the incidental Defender connection).

The PowerShell script block log contains only test framework boilerplate because the language query is delegated to `cmd.exe`/`reg.exe`, not executed within PowerShell.

## Assessment

The registry-based language discovery leaves a clear process execution trail: `reg.exe` queried by `cmd.exe` as a child of `powershell.exe`, all running as SYSTEM. Both Sysmon Event 1 and Security Event 4688 capture the `reg.exe` invocation with full command-line arguments including the NLS Language registry path. The query result is not logged, but the intent is unambiguous. This approach is historically used by malware to check `0x0419` (Russian), `0x0422` (Ukrainian), and similar language codes before executing payloads. Defender was active and did not block this test.

## Detection Opportunities Present in This Data

- **Sysmon Event 1 / Security Event 4688**: `reg.exe` with arguments querying `HKLM\SYSTEM\CurrentControlSet\Control\Nls\Language`, `HKCU\Control Panel\International`, or similar NLS/locale registry paths.
- **Process chain**: `powershell.exe` (or any scripting host) spawning `cmd.exe` which spawns `reg.exe` to query NLS language keys is an unusual pattern on a managed workstation.
- **Sysmon Event 1**: `cmd.exe` spawned from a non-interactive SYSTEM-context PowerShell, especially when followed immediately by `reg.exe`, warrants correlation.
- **Security Event 4688**: The full command line of `reg.exe` (available because command-line auditing is enabled) contains the specific registry key path — alert on any `reg query` targeting NLS, MUI, or language-related keys from non-admin user processes or automated tooling contexts.
