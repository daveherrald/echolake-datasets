# T1552.004-10: Private Keys — ADFS Token Signing and Encryption Certificates Theft - Remote

## Technique Context

MITRE ATT&CK T1552.004 (Private Keys) includes the theft of ADFS (Active Directory Federation Services) token signing and encryption certificates, a high-value target enabling Golden SAML attacks. Adversaries who compromise these certificates can forge SAML assertions to impersonate any user to any federated application, including cloud services. Test 10 uses the AADInternals PowerShell module to remotely extract ADFS certificates from a domain controller via DCSync (fetching the ADFS service account's NTLM hash) and then extracting the certificate material. This is a sophisticated, targeted technique associated with nation-state actors and the SolarWinds attack campaign. Execution on this workstation-class host fails because the required modules and ADFS infrastructure are not present.

## What This Dataset Contains

The dataset spans approximately six seconds (00:30:26–00:30:32 UTC) and contains 139 events across three log sources.

**The attack script and its partial execution are captured.** PowerShell EID 4104 script block logging preserves the complete attack script:

```
& {Import-Module ActiveDirectory -Force
Import-Module AADInternals -Force | Out-Null
#Get Configuration
$dcServerName = (Get-ADDomainController).HostName
$svc = Get-ADObject -filter * -Properties objectguid,objectsid | Where-Object name -eq "adfs_svc"
$PWord = ConvertTo-SecureString -String "ReallyStrongPassword" -AsPlainText -Force
$Credential = New-Object -TypeName System.Management.Automation.PSCredential -ArgumentList Administrator, $PWord
# use DCSync to fetch the ADFS service account's NT hash
$hash = Get-AADIntADFSEncryptionCertificates ...
```

EID 4103 module log records:
- `Import-Module ActiveDirectory` → `NonTerminatingError: The specified module 'ActiveDirectory' was not loaded because no valid module file was found in any module directory`
- `Import-Module AADInternals` → same error
- `ConvertTo-SecureString -String "ReallyStrongPassword" -AsPlainText -Force` — the hardcoded credential executed before the error was caught
- `New-Object System.Management.Automation.PSCredential -ArgumentList Administrator, $PWord`
- Multiple `Out-Null` calls as execution continued past the failed module imports
- `Write-Host "Certificates retrieved successfully"` — the script completed its output line despite the failures

A final EID 4104 script block `{$_ -like "ADFS*"}` represents a Where-Object filter that ran as part of the script execution.

Security EID 4688/4689 records confirm the PowerShell process launch and exit.

## What This Dataset Does Not Contain (and Why)

**No actual certificate extraction occurred.** AADInternals is not installed on this workstation, and the `ActiveDirectory` module is not available. The DCSync operation never ran. No ADFS certificates were retrieved despite the script printing "Certificates retrieved successfully" (which executes unconditionally regardless of prior failures).

**No DCSync telemetry.** A successful DCSync would generate domain controller Security event 4662 (object access with GUID for replication) and potentially LDAP query events. These are absent because the module that performs DCSync was never loaded.

**No network connections to the DC.** Without AADInternals loaded, no LDAP, SMB, or RPC connections were initiated.

**The hardcoded credential `ReallyStrongPassword`** in the script block log is the ART test placeholder, not a real credential.

## Assessment

This dataset captures a sophisticated but failed attack attempt. The value lies in the comprehensive script block logging, which exposes the full TTPs of the ADFS certificate theft technique even though execution failed. The module logging records individual cmdlets and their errors, providing rich behavioral context. The pattern of `Import-Module` failures followed by continued execution (because PowerShell's non-terminating error handling allows the script to proceed) is common in real attacks where the operator's toolset may be partially unavailable. The "Certificates retrieved successfully" output despite failure is an artifact of the ART test's unconditional success message and is not a reliable indicator of technique success or failure in real deployments.

## Detection Opportunities Present in This Data

- **PowerShell EID 4104**: Script block containing `AADInternals`, `Get-AADIntADFSEncryptionCertificates`, `Get-ADDomainController`, combined with `ConvertTo-SecureString` and `PSCredential` construction is a highly specific ADFS theft indicator.
- **PowerShell EID 4103**: `Import-Module AADInternals` — this module has no legitimate administrative use on workstations and is specifically a post-exploitation tool. Any attempt to load it should generate an alert regardless of success.
- **PowerShell EID 4103**: `ConvertTo-SecureString -AsPlainText -Force` with a hardcoded string is a credential-handling anti-pattern indicating scripted attacks.
- **PowerShell EID 4104**: The `$_ -like "ADFS*"` filter block is a low-noise indicator specific to this certificate enumeration pattern.
- **Module import failures**: `NonTerminatingError` on `Import-Module` for post-exploitation modules (AADInternals, PowerSploit, etc.) still indicates malicious intent — the attacker attempted to use the tool even if it wasn't available.
- **Threat intelligence context**: This technique maps directly to the Golden SAML attack pattern. Any detection of AADInternals usage on non-ADFS-server systems warrants immediate escalation given its association with high-severity intrusion campaigns.
