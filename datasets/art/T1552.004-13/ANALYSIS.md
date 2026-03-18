# T1552.004-13: Private Keys — Export Root Certificate with Export-Certificate

## Technique Context

T1552.004 (Unsecured Credentials: Private Keys) covers adversary theft of certificate material
and private keys. Test 13 uses the PowerShell `Export-Certificate` cmdlet to export a certificate
in DER-encoded `.cer` format. Unlike test 12 (which exports a PFX with the private key),
`Export-Certificate` exports only the public certificate — the private key is not included. This
technique is used by attackers to steal the public certificate component for subsequent use in
certificate cloning attacks or to establish trusted identities for HTTPS interception.

## What This Dataset Contains

The dataset captures a complete, successful DER certificate export executed as SYSTEM.

**PowerShell EID 4104 (Script Block Logging) records the exact payload:**

```
$cert = New-SelfSignedCertificate -DnsName atomicredteam.com -CertStoreLocation cert:\LocalMachine\My
Set-Location Cert:\LocalMachine\My
Export-Certificate -Type CERT -Cert Cert:\LocalMachine\My\$($cert.Thumbprint) -FilePath $env:Temp\AtomicRedTeam.cer
```

**Sysmon EID 13 (Registry Value Set)** captures the certificate being installed into the
certificate store prior to export, tagged with `technique_id=T1553.004`:

```
TargetObject: HKLM\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\944B60BC3135E4A68176340D3CD92187D7A96E3E\Blob
```

**Sysmon EID 11 (File Create)** confirms the `.cer` file was written to disk:

```
TargetFilename: C:\Windows\Temp\AtomicRedTeam.cer
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Sysmon EID 1 (Process Create)** records the PowerShell invocation with the full command line
containing the `Export-Certificate` script, tagged with `technique_id=T1059.001`. A `whoami.exe`
process is also present — the ART test framework identity pre-check.

**Security EID 4688/4689** confirm process creation and termination of `powershell.exe` and
`whoami.exe` as SYSTEM. Security EID 4703 (Token Right Adjusted) appears for privilege
manipulation during execution.

The dataset spans 30 Sysmon events, 16 Security events, and 37 PowerShell events over 5 seconds.

## What This Dataset Does Not Contain (and Why)

**No private key export.** `Export-Certificate -Type CERT` exports only the public portion.
The `.cer` file created does not contain a private key. An attacker seeking private key material
for impersonation would need to follow this with a `Export-PfxCertificate` call (as in test 12).

**No logon events.** Unlike test 12, this dataset does not include EID 4624/4627/4672 logon
records. The test ran within an existing SYSTEM session without triggering a new service logon.

**No network telemetry.** The operation is entirely local.

**No object access audit events.** The audit policy has object access auditing disabled; file
and registry access appears only through Sysmon, not Security log EID 4663/4657.

**Boilerplate PowerShell script blocks.** The majority of the 37 PowerShell EID 4104 events
are internal error-handling closures emitted at PowerShell session startup
(`$_.PSMessageDetails`, `$_.ErrorCategory_Message`, etc.). These are engine boilerplate, not
attacker activity.

The Sysmon configuration uses include-mode filtering for Process Create events.

## Assessment

This is a clean, successful certificate export with all key stages observable in the telemetry.
The dataset is complementary to test 12: together they show the difference between public-only
certificate export (`.cer`) and full private-key export (`.pfx`). Both produce similar Sysmon
registry and file events, making them useful for building detection rules that cover both cases.
The EID 13 registry write with Sysmon's built-in T1553.004 tag is a particularly direct signal.

## Detection Opportunities Present in This Data

- **EID 4104 script block**: `Export-Certificate` used in conjunction with `New-SelfSignedCertificate`
  or any `cert:\` provider reference warrants review. The `-FilePath` parameter pointing to a
  temp directory is particularly notable.
- **Sysmon EID 13 with T1553.004 tag**: Certificate store modifications (`HKLM\SOFTWARE\Microsoft\
  SystemCertificates\`) made by `powershell.exe` rather than system certificate management tools
  are anomalous.
- **Sysmon EID 11**: `powershell.exe` creating a `.cer` file in `C:\Windows\Temp\` is suspicious.
  Legitimate certificate exports from PowerShell are rare and typically go to user-controlled paths.
- **EID 4688 command line**: The `Export-Certificate` command is fully visible in the process
  command line, providing a detection path independent of script block logging.
- **File extension**: Monitoring for `.cer` or `.pfx` files created by PowerShell processes in
  world-writable temp directories covers both tests 12 and 13.
