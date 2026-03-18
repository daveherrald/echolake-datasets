# T1546.015-3: Component Object Model Hijacking — COM Hijacking with RunDLL32 (Local Server Switch)

## Technique Context

T1546.015 (Component Object Model Hijacking) via RunDLL32 with the `-localserver` switch represents a specific execution variant. Rather than loading a DLL in-process, the `-localserver` flag causes `rundll32.exe` to register and activate a COM local server for the specified CLSID. Attackers use this to activate a COM object that has been hijacked in the user hive (HKCU), triggering their malicious DLL or out-of-process COM server under `rundll32.exe` as the host — a process that is legitimately used by Windows and may bypass application allowlisting. The persistence registration step writes a malicious `InprocServer32` path under `HKCU\Software\Classes\CLSID\<CLSID>`, which is loaded when any application activates that COM object.

## What This Dataset Contains

The test registers a COM hijack in `HKU\.DEFAULT` (the SYSTEM-context HKCU equivalent) then invokes it via `rundll32.exe -localserver`. Two Sysmon Event ID 13 (Registry Value Set) events carry the core persistence artifacts, tagged `technique_id=T1546.015,technique_name=Component Object Model Hijacking`:

- `HKU\.DEFAULT\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32\(Default)` = `C:\AtomicRedTeam\atomics\..\ExternalPayloads\T1546.015_calc.dll`
- `HKU\.DEFAULT\Software\Classes\CLSID\{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}\InprocServer32\ThreadingModel` = `Both`

The CLSID `{B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}` corresponds to `MSAA AccPropServices`.

Sysmon Event ID 1 captures the PowerShell process writing the keys (command line includes `New-Item -Path 'HKCU:\SOFTWARE\Classes\CLSID\{B5F8350B-...}'`) and the `rundll32.exe` invocation:
```
"C:\Windows\System32\RUNDLL32.EXE" -localserver {B5F8350B-0548-48B1-A6EE-88BD00B4A5E7}
```

`rundll32.exe` is captured by Sysmon Event ID 1 with `RuleName: technique_id=T1083` (File and Directory Discovery rule match on `rundll32.exe`), making it visible in the Sysmon process create stream.

Security 4688 shows the same PowerShell and `rundll32.exe` process creations with full command lines.

## What This Dataset Does Not Contain

- **No DLL load event for the payload DLL**: Sysmon Event ID 7 does not show `T1546.015_calc.dll` loading into `rundll32.exe`. This may indicate the payload DLL was not present at `C:\AtomicRedTeam\...\ExternalPayloads\T1546.015_calc.dll` at the time of test execution, or that the DLL loaded and unloaded before Sysmon could capture it. There is no evidence the COM object was actually instantiated successfully.
- **No child process from calc.dll**: if the DLL payload were functioning, a `calc.exe` or equivalent child would appear. It does not, suggesting Defender may have blocked the DLL load or the payload was absent.
- **Sysmon ProcessCreate filtering**: only LOLBin-matching processes (rundll32.exe, powershell.exe) appear in Sysmon Event ID 1.

## Assessment

The registry side of this dataset is strong: the two Sysmon 13 events with accurate T1546.015 tagging, pointing to a HKCU InprocServer32 path containing an attacker payload DLL, are exactly what detection rules should target. The `rundll32.exe -localserver` invocation in Sysmon Event ID 1 provides the execution-phase artifact. The absence of a confirmed DLL load or payload execution slightly weakens the end-to-end narrative, but the setup and invocation phases are well-represented. This dataset is well-suited for testing both HKCU COM registration detections and `rundll32.exe -localserver` command line alerting.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 13 — writes to `HKCU\Software\Classes\CLSID\*\InprocServer32`**: Any process registering a new COM InprocServer32 path in the user hive, especially pointing to a non-system-directory DLL, is a high-fidelity indicator for COM hijacking setup.
2. **Sysmon Event ID 1 — `rundll32.exe` with `-localserver` argument**: The `-localserver` switch is rarely used by legitimate software. Any `rundll32.exe -localserver <CLSID>` invocation warrants investigation.
3. **PowerShell Event ID 4104 — `New-Item` creating CLSID subkeys under `HKCU:\Software\Classes\CLSID`**: Script block logging surfaces the PowerShell-based registry key creation, which is the setup phase of this technique.
4. **Sysmon Event ID 13 — `ThreadingModel` value set alongside `InprocServer32` default**: The pairing of these two values is the canonical COM server registration fingerprint. Alerting on both appearing together under a new CLSID path is a compound indicator.
5. **Sysmon Event ID 7 — unexpected DLL path loading into `rundll32.exe`**: If the payload DLL is present and loads, an image load event for a DLL in a writable or non-standard path under `rundll32.exe` would confirm exploitation.
6. **CLSID path comparison — HKCU overrides HKLM**: Detection logic that identifies CLSIDs registered in both `HKCU` and `HKLM` where the `HKCU` version points to a non-system path detects the core hijacking condition regardless of the activation mechanism used.
