# T1649-1: Steal or Forge Authentication Certificates — Staging Local Certificates via Export-Certificate

## Technique Context

T1649 (Steal or Forge Authentication Certificates) covers adversary access to certificate material that can be used for authentication, code signing bypass, or as a stepping stone to more advanced certificate-based attacks such as ADCS abuse. This test uses the built-in `Export-Certificate` cmdlet to enumerate and export certificates from the current user's personal certificate store (`Cert:\CurrentUser\My`), staging them for potential exfiltration.

## What This Dataset Contains

This dataset captures a PowerShell-based certificate export operation that iterates over all certificates in `Cert:\CurrentUser\My`, exports each as a `.cer` file, then compresses the results into a ZIP archive. Executed as NT AUTHORITY\SYSTEM on ACME-WS02 (Windows 11 Enterprise, acme.local domain member).

The core payload script block logged in PowerShell EID 4104:
```
$archive="$env:PUBLIC\T1649\atomic_certs.zip"
$exfilpath="$env:PUBLIC\T1649\certs"
Add-Type -assembly "system.io.compression.filesystem"
Remove-Item $(split-path $exfilpath) -Recurse -Force -ErrorAction Ignore
mkdir $exfilpath | Out-Null
foreach ($cert in (gci Cert:\CurrentUser\My)) { Export-Certificate -Cert $cert -FilePath $exfilpath\$($cert.FriendlyName).cer}
[io.compression.zipfile]::CreateFromDirectory($exfilpath, $archive)
```

**Sysmon (41 events)** — EID 7 (image load) for PowerShell startup DLLs; EID 17 (named pipe) for multiple PSHost pipes; EID 10 (process access) for the PowerShell SYSTEM process tagged T1055.001; EID 1 (process create) events:
  - `whoami.exe` tagged `technique_id=T1033`
  - `powershell.exe` (test execution) tagged `technique_id=T1083` (File and Directory Discovery) — unusual tagging, reflecting the `Get-ChildItem` certificate enumeration
- EID 11 (file create): `C:\Users\Public\T1649\certs` directory and `.cer` files — the staging path for exported certificates. A file create event with `RuleName: technique_id=T1047` appears, which is a labeling artifact from the sysmon-modular config matching on file write behavior.

**Security log (11 events)** — EID 4688/4689 process lifecycle events for `whoami.exe` and the test PowerShell process; EID 4703 token right adjustments showing standard SYSTEM privileges.

**PowerShell log (44 events)** — Beyond the key script block above, EID 4103 module logging records `Add-Type` with `system.io.compression.filesystem`, `Get-ChildItem` against `Cert:\CurrentUser\My`, `Export-Certificate` (with `Cert` and `FilePath` parameter values), `mkdir`, `Remove-Item`, and `Split-Path`. Standard test framework boilerplate stubs appear in quantity.

## What This Dataset Does Not Contain (and Why)

- **Certificate file content** — The actual certificate data written to `.cer` files is not captured in Windows event logs. Object access auditing is disabled.
- **ZIP archive creation events** — The `[io.compression.zipfile]::CreateFromDirectory` call creates `atomic_certs.zip` in `C:\Users\Public\T1649\`, but Sysmon EID 11 does not appear to capture this specific file creation (it may not have been collected within the time window or the file path was not matched by the Sysmon config's file creation rules).
- **Private key access** — `Export-Certificate` exports only the public certificate (`.cer` format), not the private key. Private key export would require `Export-PfxCertificate` and would likely trigger additional Security events; no such events appear.
- **CryptoAPI or CAPI2 events** — The Microsoft-Windows-CAPI2/Operational channel was not included in the collection scope.

## Assessment

This test completed successfully. The PowerShell module logging (EID 4103) provides granular visibility into every cmdlet called, including the certificate store path and export file path. The Sysmon EID 11 file creation events for the staging directory and `.cer` files are present. The test exports only public certificate files (not private keys), which limits the immediate credential theft impact but still provides an attacker with certificate fingerprints and subject information useful for ADCS abuse planning.

## Detection Opportunities Present in This Data

- **PowerShell EID 4103**: `Export-Certificate` invocation with `Cert:\CurrentUser\My` path and a staging directory in `C:\Users\Public\` is a high-confidence indicator of certificate staging.
- **PowerShell EID 4103**: `Get-ChildItem` on `Cert:\` (the certificate store provider) is unusual for automated processes running as SYSTEM and warrants investigation.
- **PowerShell EID 4104**: The script block contains both certificate enumeration and ZIP archive creation in a single block — a characteristic staging-for-exfiltration pattern.
- **Sysmon EID 11**: `.cer` file creation events in a public or temp directory by a SYSTEM PowerShell process, particularly in a directory named after an adversary staging convention, correlate with certificate theft.
- **Sysmon EID 1, RuleName T1083**: The sysmon-modular config's tagging of the test PowerShell process as File and Directory Discovery reflects the `Get-ChildItem` behavior and provides an alert-ready label.
