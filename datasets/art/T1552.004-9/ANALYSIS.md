# T1552.004-9: Private Keys — ADFS Token Signing and Encryption Certificates Theft - Local

## Technique Context

T1552.004 (Unsecured Credentials: Private Keys) covers adversary attempts to find and exfiltrate
private keys and certificate material from compromised systems. Test 9 specifically targets Active
Directory Federation Services (ADFS) token signing and encryption certificates using the
AADInternals PowerShell module. ADFS certificate theft is a high-value objective in identity-based
attacks — the token signing certificate allows an attacker to forge authentication tokens for any
federated identity, and the encryption certificate allows decryption of SAML assertions. This
capability was famously abused in the Solorigate/SUNBURST campaign (Golden SAML attacks).

## What This Dataset Contains

The dataset captures a PowerShell-driven attempt to import the AADInternals module and invoke
`Export-AADIntADFSCertificates` on a domain-joined Windows 11 workstation running as SYSTEM.

**PowerShell script block logging (EID 4104) captures the full attack payload:**

```
& {Import-Module AADInternals -Force
Export-AADIntADFSCertificates
Get-ChildItem | Where-Object {$_ -like "ADFS*"}
Write-Host "`nCertificates retrieved successfully"}
```

**Sysmon EID 1 (Process Create) records the PowerShell invocation with full command line:**
- `powershell.exe` spawned by the ART test framework with the AADInternals command embedded in
  command-line arguments
- The test framework `whoami.exe` pre-check process also visible (technique_id=T1033 rule tag)

**Sysmon EID 7 (Image Load)** shows 35 DLL loads into the PowerShell process, including
`System.Management.Automation.ni.dll` and the Defender AMSI/IOAV modules (`MpOAV.dll`,
`MpClient.dll`), which reflect normal PowerShell startup and AMSI integration.

**Sysmon EID 17 (Pipe Create)** captures the PSHost named pipe, confirming the PowerShell
session was created under the ART test framework parent.

**Security EID 4688** provides an independent process creation record with command line.

The dataset contains 48 Sysmon events, 10 Security events, and 52 PowerShell events across
a 6-second window.

## What This Dataset Does Not Contain (and Why)

**No ADFS certificate files on disk.** This is a domain workstation, not an ADFS server.
The `Export-AADIntADFSCertificates` function requires access to the AD FS configuration
database (WID or SQL) and DKM decryption keys stored in Active Directory, none of which exist
on a standard domain workstation. The function fails silently or with an error, and no `.pfx`
or `.cer` files are created.

**No registry writes related to certificate stores.** Unlike tests 12 and 13 (which create and
export self-signed certificates), no Sysmon EID 13 events appear. No certificate material was
installed or modified.

**No Sysmon EID 11 output files.** The absence of file-creation events confirms the export
operation produced no output on this machine.

**No network connections.** AADInternals in local mode reads from local ADFS service state
rather than connecting to Azure AD or a remote endpoint.

**No ADFS-specific event logs.** ADFS diagnostic and security logs would only appear on the
ADFS server itself, not collected here.

The Sysmon configuration uses include-mode filtering for EID 1 (Process Create). The PowerShell
process was captured because the parent/command matched a known-suspicious pattern rule
(T1059.001 tag). Not all process creations on the host are recorded.

## Assessment

This dataset represents a credential-access attempt against ADFS certificate material that fails
because the target machine is not an ADFS server. The telemetry records the attempt with high
fidelity — the exact PowerShell commands are visible in both script block logs and process
command lines. However, there is no completion evidence (no exported files, no registry changes).
The dataset is most useful for detecting the reconnaissance and tooling phase of a Golden SAML
attack: an adversary who has already identified a target but has not yet pivoted to the correct
host.

## Detection Opportunities Present in This Data

- **EID 4104 script block content**: `Import-Module AADInternals` and `Export-AADIntADFSCertificates`
  are rare in legitimate environments. Either string in a script block should alert.
- **EID 4688 / Sysmon EID 1 command line**: `powershell.exe` with `AADInternals` in the command
  line argument is directly observable.
- **Module import pattern**: Any PowerShell session importing AADInternals as SYSTEM warrants
  investigation regardless of whether the export succeeds.
- **Execution context**: The test runs as `NT AUTHORITY\SYSTEM`, which is an unusual context
  for certificate-related PowerShell operations outside of scheduled tasks or service accounts
  with documented purpose.
