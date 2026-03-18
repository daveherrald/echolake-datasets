# T1553.003-1: SIP and Trust Provider Hijacking — SIP (Subject Interface Package) Hijacking via Custom DLL

## Technique Context

T1553.003 (Subvert Trust Controls: SIP and Trust Provider Hijacking) covers modification of
the Windows cryptographic trust chain to bypass Authenticode signature verification. Subject
Interface Packages (SIPs) are the COM-based pluggable components that Windows uses to compute
and verify digital signatures for different file types (PE binaries, scripts, CAB files, etc.).
Each SIP is registered in the registry under `HKLM\SOFTWARE\Microsoft\Cryptography\OID\` keyed
by a GUID representing the file type. An attacker who registers a malicious DLL as a SIP
provider for a new or existing GUID can intercept signature verification calls, allowing
unsigned or maliciously-modified files to appear validly signed to WinVerifyTrust. This
technique was documented by Matt Graeber (SpecterOps) and is used in sophisticated defense
evasion scenarios.

## What This Dataset Contains

The dataset captures a complete, successful SIP provider registration via `regsvr32.exe` followed
by a reboot-triggered verification sequence.

**Sysmon EID 1 (Process Create) records the full attack chain:**

```
"cmd.exe" /c regsvr32.exe C:\AtomicRedTeam\atomics\T1553.003\bin\GTSIPProvider.dll
```
Tagged `technique_id=T1059.003`.

```
regsvr32.exe C:\AtomicRedTeam\atomics\T1553.003\bin\GTSIPProvider.dll
```
Tagged `technique_id=T1218.010,technique_name=Regsvr32`.

**Sysmon EID 13 (Registry Value Set) records all SIP function registrations** — 10 separate
registry writes under the GUID `{00000000-DEAD-BEEF-DEAD-DEADBABECAFE}`:

Key paths include:
- `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllGetSignedDataMsg\{...}\Dll`
  → `C:\AtomicRedTeam\atomics\T1553.003\bin\GTSIPProvider.dll`
- `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDllVerifyIndirectData\{...}\FuncName`
  → `GtSipVerify`
- `CryptSIPDllCreateIndirectData`, `CryptSIPDllRemoveSignedDataMsg`, `CryptSIPDllPutSignedDataMsg`,
  `CryptSIPDllIsMyFileType2`, `CryptSIPDllGetCaps` — all registered to the malicious DLL

The GUID `DEAD-BEEF-DEAD-DEADBABECAFE` is the test payload's identifier; in a real attack this
would be a genuine GUID matching an existing file type.

**Security EID 4624/4672** record a SYSTEM logon associated with the test execution.

**PowerShell EID 4104** records the test framework wrapper, but the SIP registration is performed by
`regsvr32.exe` rather than PowerShell — no SIP-specific script content appears in PS logs.

The timestamp range spans ~61 seconds (00:32:37 to 00:33:38), reflecting the cleanup/verification
phase the test performs after registration.

The dataset contains 32 Sysmon events, 17 Security events, and 30 PowerShell events.

## What This Dataset Does Not Contain (and Why)

**No DLL content analysis.** The dataset records the DLL path and hash (from Sysmon EID 7 image
loads) but does not contain the DLL binary itself. A full analysis of the SIP provider's behavior
would require examination of `GTSIPProvider.dll`.

**No Sysmon EID 7 (Image Load) for GTSIPProvider.dll.** `regsvr32.exe` calls `DllRegisterServer`
on the DLL to write the registry entries, but the Sysmon image load events captured are for the
PowerShell process's DLL loads, not for the `regsvr32.exe` invocation itself in this filtered
dataset.

**No WinVerifyTrust invocation events.** The test registers the SIP provider but does not
demonstrate a signature bypass verification event within this dataset window. The actual
trust subversion would only appear when another process verifies the signature of a file
associated with the hijacked GUID.

**No Security registry audit events (EID 4657).** Object access auditing is disabled; registry
changes are only visible through Sysmon EID 13.

The Sysmon config's include-mode Process Create filter captured `regsvr32.exe` via the
`technique_id=T1218.010` rule, not a generic process rule.

## Assessment

This dataset is notable for the richness of the registry telemetry. The 10 Sysmon EID 13 events
comprehensively document the SIP registration: every function entry point (`Get`, `Put`, `Create`,
`Verify`, `Remove`, `IsMyFileType2`, `GetCaps`) and its corresponding DLL path is recorded. This
provides a complete fingerprint of the SIP hijack in the registry. Combined with the `regsvr32.exe`
process creation events, the dataset supports detection at both the execution and persistence layers.

## Detection Opportunities Present in This Data

- **Sysmon EID 13 with T1553.003 rule tag**: Writes to
  `HKLM\SOFTWARE\Microsoft\Cryptography\OID\EncodingType 0\CryptSIPDll*` by any process other
  than a legitimate PKI setup tool are highly suspicious. Multiple writes in rapid succession to
  the same GUID constitute a SIP registration event.
- **Sysmon EID 1**: `regsvr32.exe` loading a DLL from `C:\AtomicRedTeam\` or any non-system
  directory via `cmd.exe` is anomalous. The T1218.010 rule tag directly identifies the LOLBin
  usage.
- **GUID pattern**: The test uses a synthetic GUID (`DEAD-BEEF`), which is immediately obvious.
  Real attacks would use a valid GUID, but the registry path pattern
  (`CryptSIPDll*\{<GUID>}\Dll`) remains the detection anchor.
- **Registry value content**: Any `Dll` value under `CryptSIPDll*` registry keys pointing to
  non-system paths (outside `C:\Windows\System32\`) should alert.
- **Process chain**: `powershell.exe` → `cmd.exe` → `regsvr32.exe` [non-system DLL] as SYSTEM
  from `C:\Windows\TEMP\` is a high-confidence pattern.
