# T1552.004-12: Private Keys — Export Root Certificate with Export-PfxCertificate

## Technique Context

T1552.004 (Unsecured Credentials: Private Keys) encompasses adversary actions to locate and
steal private key material. Test 12 exercises the PowerShell `Export-PfxCertificate` cmdlet to
export a self-signed certificate with its private key as a PFX (PKCS#12) file. While this test
creates and immediately exports a certificate it generated itself, the technique is identical to
what an attacker would use against pre-existing certificates in a compromised machine's certificate
store, including code-signing certificates, encryption keys, or VPN client certificates.

## What This Dataset Contains

The dataset captures a complete, successful PFX certificate export operation executed as SYSTEM
via the ART PowerShell test framework.

**PowerShell EID 4104 (Script Block Logging) records the full attack payload twice** — once with
the ART test framework wrapper and once as the inner script block:

```
$mypwd = ConvertTo-SecureString -String "AtomicRedTeam" -Force -AsPlainText
$cert = New-SelfSignedCertificate -DnsName atomicredteam.com -CertStoreLocation cert:\LocalMachine\My
Set-Location Cert:\LocalMachine\My
Get-ChildItem -Path $cert.Thumbprint | Export-PfxCertificate -FilePath $env:Temp\atomicredteam.pfx -Password $mypwd
```

**Sysmon EID 13 (Registry Value Set)** records the self-signed certificate being written to
the certificate store before export:

```
TargetObject: HKLM\SOFTWARE\Microsoft\SystemCertificates\CA\Certificates\20B91C68D379142E7546CA11AFB661B69CE5C037\Blob
```

The rule tag `technique_id=T1553.004` on this event reflects Sysmon's correct identification of
certificate store modification.

**Sysmon EID 11 (File Create)** confirms the PFX was written to disk:

```
TargetFilename: C:\Windows\Temp\atomicredteam.pfx
Image: C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
```

**Sysmon EID 1 (Process Create)** captures two PowerShell invocations and a `whoami.exe`
pre-check. The PowerShell command line includes the full `Export-PfxCertificate` script.

**Sysmon EID 10 (Process Access)** shows the PowerShell process accessing `whoami.exe` with
`GrantedAccess: 0x1FFFFF` — this is the ART test framework performing its identity verification step.

**Security EID 4624/4627/4672** record a Logon Type 5 (service) event for SYSTEM, reflecting
the QEMU guest agent spawning the test. EID 4703 (Token Right Adjusted) appears multiple times
as PowerShell adjusts its token privileges.

The dataset spans 39 Sysmon events, 20 Security events, and 37 PowerShell events over 6 seconds.

## What This Dataset Does Not Contain (and Why)

**No network telemetry.** The operation is entirely local — the PFX is written to disk and not
transmitted. There are no Sysmon EID 3 network connection events.

**No file read events.** Windows audit policy has object access auditing disabled, so no EID
4663 (file access) events are generated when the certificate store or the output PFX is accessed.

**No Security EID 4657 (registry value modified).** Object access auditing is off; registry
changes appear only in Sysmon EID 13, not the Security log.

**Partial PowerShell module logging.** Many of the 37 PowerShell events are boilerplate EID 4104
script blocks for internal error-handling closures (`$_.PSMessageDetails`,
`$_.ErrorCategory_Message`, etc.) emitted every time a new PowerShell session starts. These are
PowerShell engine internals, not attacker content.

The Sysmon configuration is include-mode for Process Create. The `powershell.exe` invocation is
captured because the parent process (ART test framework) triggered a T1059.001 rule match.

## Assessment

This is a clean, successful execution with full observability. All three phases — certificate
creation (registry write), temporary store placement, and PFX export (file write) — are
represented in the telemetry. The combination of script block logging and Sysmon file/registry
events provides multiple independent detection paths. The dataset is directly applicable to
detection engineering for certificate theft scenarios.

## Detection Opportunities Present in This Data

- **EID 4104 script block**: `Export-PfxCertificate` combined with `New-SelfSignedCertificate`
  or any reference to `cert:\` provider paths is unusual outside of PKI administration workflows.
- **Sysmon EID 13 rule tag**: `technique_id=T1553.004` on certificate store registry writes
  is directly actionable. The key path `HKLM\SOFTWARE\Microsoft\SystemCertificates\` written by
  `powershell.exe` rather than `certutil.exe` or an MMC snap-in is anomalous.
- **Sysmon EID 11 file path**: `powershell.exe` writing a `.pfx` file to `C:\Windows\Temp\` is
  a high-confidence indicator. Legitimate PFX operations rarely write to system temp directories.
- **EID 4688 command line**: The full script is embedded in the PowerShell command line and is
  visible without any script block logging configured.
- **Process chain**: `whoami.exe` spawned by `powershell.exe` as SYSTEM immediately followed by
  a certificate-related PowerShell invocation is a recognizable ART test framework pattern, but the
  underlying certificate commands remain malicious regardless of their parent.
