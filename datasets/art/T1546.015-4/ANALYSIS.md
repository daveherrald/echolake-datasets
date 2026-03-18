# T1546.015-4: Component Object Model Hijacking — COM Hijacking via TreatAs

## Technique Context

T1546.015 via the `TreatAs` registry key is a less commonly detected variant of COM hijacking. The `TreatAs` key redirects all COM activations for a given CLSID to a different CLSID — effectively a CLSID alias. An attacker creates a new "decoy" CLSID with a malicious `InprocServer32`, then sets `TreatAs` on a legitimate, frequently-activated CLSID to point to the decoy. The OS then loads the attacker's DLL whenever any application activates the targeted legitimate CLSID. This approach is more indirect than direct InprocServer32 replacement and can affect high-frequency system CLSIDs without modifying their registration directly. Many detection rules focus on InprocServer32 writes and may miss the `TreatAs` path entirely.

## What This Dataset Contains

Three Sysmon Event ID 13 (Registry Value Set) events, all tagged `technique_id=T1546.015,technique_name=Component Object Model Hijacking`, capture the full registration:

1. Decoy CLSID InprocServer32 registration:
   - `HKU\.DEFAULT\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32\(Default)` = `C:\WINDOWS\system32\scrobj.dll`
2. Decoy CLSID threading model:
   - `HKU\.DEFAULT\Software\Classes\CLSID\{00000001-0000-0000-0000-0000FEEDACDC}\InprocServer32\ThreadingModel` = `Apartment`
3. TreatAs redirect on a real CLSID:
   - `HKU\.DEFAULT\Software\Classes\CLSID\{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}\TreatAs\(Default)` = `{00000001-0000-0000-0000-0000FEEDACDC}`

The decoy CLSID `{00000001-0000-0000-0000-0000FEEDACDC}` points to `scrobj.dll` (Windows Script Runtime), while the victim CLSID `{97D47D56-3777-49FB-8E8F-90D7E30E1A1E}` is redirected to it via `TreatAs`. All three writes are performed by `reg.exe` instances, captured in both Sysmon Event ID 1 and Security 4688.

Sysmon Event ID 1 shows multiple `reg.exe` instances (tagged T1012/Query Registry by the include-mode config) alongside the usual `whoami.exe` and test framework `powershell.exe`. A final set of `reg.exe` processes appears in the Security channel representing cleanup.

## What This Dataset Does Not Contain

- **No trigger execution**: no application activates the targeted CLSID `{97D47D56-...}` during the test window, so the `TreatAs` redirect is never exercised. There is no `scrobj.dll` load event.
- **No Sysmon Event ID 12 (key creation)**: only SetValue events appear; the key creation events for the new CLSID subkeys are not captured.
- **Defender action unclear**: `scrobj.dll` is a legitimate Windows DLL, so Defender does not block the registration. However, whether the redirect would be allowed to activate is unknown from this dataset alone.
- The PowerShell channel is test framework boilerplate only. All meaningful execution is via `reg.exe`.

## Assessment

This dataset is notable for capturing the `TreatAs` registry key write, which is absent from most detection rule libraries. The three Sysmon 13 events clearly show the two-stage structure: first, a new CLSID with a DLL payload is registered, then a `TreatAs` value on a different CLSID points to the decoy. Detection rules that look only at InprocServer32 modifications would catch the first write but miss the significance of the `TreatAs` redirect. Writing a compound rule that looks for `TreatAs` creation under a CLSID in the user hive is the key detection opportunity this dataset validates. The use of `reg.exe` for all writes provides clean, visible process execution telemetry.

## Detection Opportunities Present in This Data

1. **Sysmon Event ID 13 — writes to `HKCU\Software\Classes\CLSID\*\TreatAs`**: The `TreatAs` key under a user-hive CLSID is highly anomalous. Writes here by any non-system process should be treated as a high-severity signal.
2. **Sysmon Event ID 13 — CLSID with suspicious GUID pattern in user hive**: The decoy CLSID `{00000001-0000-0000-0000-0000FEEDACDC}` contains a recognizable placeholder pattern. While real attacks would use more convincing GUIDs, a rule detecting CLSID registrations with sequential or patterned GUIDs in HKCU is a useful heuristic.
3. **Sysmon Event ID 13 — `InprocServer32` + `TreatAs` writes within the same process session**: Correlating an InprocServer32 registration with a TreatAs write to a different CLSID in the same time window is a compound indicator for this specific attack variant.
4. **Sysmon Event ID 1 / Security 4688 — multiple `reg.exe` instances with CLSID-targeting arguments in rapid succession**: The burst of `reg.exe` calls writing to `HKCU\Software\Classes\CLSID` paths is behaviorally distinctive.
5. **Baseline HKCU CLSID enumeration**: Any CLSID appearing in `HKCU\Software\Classes\CLSID` that does not exist in `HKLM\SOFTWARE\Classes\CLSID` and points to a non-system DLL path is a persistent detection opportunity, independent of the installation method.
