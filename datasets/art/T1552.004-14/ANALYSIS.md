# T1552.004-14: Private Keys — Export Certificates with Mimikatz

## Technique Context

T1552.004 (Unsecured Credentials: Private Keys) includes adversary use of credential dumping
tools to extract certificate material. Test 14 uses Mimikatz's `crypto::certificates` module to
enumerate and export certificates from the Windows certificate store. Mimikatz can export
certificates with their private keys even when the keys are marked as non-exportable, by accessing
the key material directly from the CryptoAPI/CNG key containers on disk rather than through normal
API export paths. This makes it significantly more powerful than PowerShell Export-PfxCertificate
for targeting certificates whose private keys are export-protected.

## What This Dataset Contains

The dataset records a Mimikatz certificate export attempt that proceeds through process creation
but is blocked by Windows Defender before the tool can execute.

**Security EID 4688 and Sysmon EID 1 both capture the cmd.exe invocation with the full command:**

```
"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\x64\mimikatz.exe"
  "crypto::certificates /systemstore:local_machine /store:my /export" exit
```

**Sysmon EID 10 (Process Access)** records PowerShell accessing `whoami.exe` with
`GrantedAccess: 0x1FFFFF` — the ART test framework pre-check. A second EID 10 shows PowerShell
accessing `cmd.exe` with the same access mask before launching Mimikatz.

**Sysmon EID 1** also records the `cmd.exe` subprocess (tagged `technique_id=T1059.003`) and
the `whoami.exe` pre-check (tagged `technique_id=T1033`).

**PowerShell EID 4104** records the outer ART invocation but contains no Mimikatz-specific
script block content — the Mimikatz binary is launched via `cmd.exe /c`, not through PowerShell
directly.

The dataset spans 17 Sysmon events, 11 Security events, and 34 PowerShell events over 4 seconds.
The Sysmon event mix (EID 7: 9, EID 10: 2, EID 11: 3, EID 1: 2, EID 17: 1) shows two
PowerShell sessions and no image loads for mimikatz.exe itself, which confirms Defender
terminated the process before it could be observed by Sysmon's ImageLoad monitoring.

## What This Dataset Does Not Contain (and Why)

**No Mimikatz process image load events (Sysmon EID 7).** Windows Defender terminated the
Mimikatz process before Sysmon could record its DLL loads. This is consistent with Defender's
real-time protection blocking known malicious executables by hash.

**No certificate files on disk.** Mimikatz did not run long enough to export any `.pfx` or
`.cer` files. There are no Sysmon EID 11 events with certificate file paths from the Mimikatz
working directory.

**No registry modifications.** No EID 13 events appear. Mimikatz's `crypto::certificates`
operates on in-memory CryptoAPI state and disk key containers rather than registry certificate
blobs.

**No Mimikatz output or LSASS interaction.** The dataset does not include any LSASS process
access events (Sysmon EID 10 targeting `lsass.exe`), which would appear if Mimikatz had
privilege escalation enabled and could interact with LSASS.

**No `0xC0000022` (Access Denied) exit codes.** The block happens before execution rather than
via an access denial during the crypto operations. Defender's behavior monitoring terminates the
process at launch rather than letting it fail on a permission check.

## Assessment

This dataset captures the attack at the command-execution stage with the actual certificate export
blocked. It is representative of what defenders observe when Mimikatz is detected by an active
endpoint protection product: clear process creation telemetry (including the full command with
arguments) but no completion evidence. The dataset demonstrates that process creation logging
alone is sufficient to detect this variant even when the tool is blocked before it produces output.

## Detection Opportunities Present in This Data

- **EID 4688 / Sysmon EID 1 command line**: The string `mimikatz.exe` with `crypto::certificates`
  arguments is directly observable in Security and Sysmon process creation events. This is the
  primary detection path regardless of whether Defender blocks execution.
- **Sysmon EID 1 rule tag**: The `cmd.exe` process is tagged `technique_id=T1059.003`, providing
  an additional classification signal.
- **Process chain**: `powershell.exe` (as SYSTEM) spawning `cmd.exe` which would spawn
  `mimikatz.exe` from `C:\AtomicRedTeam\ExternalPayloads\` is a high-confidence pattern.
- **Path anomaly**: Execution of binaries from `C:\AtomicRedTeam\` or similar staging directories
  under `C:\Windows\TEMP\` as the working directory is suspicious regardless of the binary name.
- **Absence of process termination for mimikatz.exe**: If monitoring for the Mimikatz command
  in EID 4688 but not seeing a corresponding EID 4689, Defender killed the process — the attempt
  still occurred and should be investigated.
