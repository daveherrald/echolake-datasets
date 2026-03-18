# T1552.006-1: Group Policy Preferences — findstr

## Technique Context

T1552.006 (Unsecured Credentials: Group Policy Preferences) covers a well-known Windows domain
misconfiguration. Prior to MS14-025, Group Policy Preferences (GPP) XML files stored in the
SYSVOL share could contain encrypted passwords for local administrator accounts, service accounts,
and scheduled task credentials. The encryption key was published by Microsoft in MSDN
documentation, allowing any domain user to decrypt any GPP-stored password. While MS14-025
prevents new GPP passwords from being set, many environments retain legacy GPP files in SYSVOL
containing historical credentials. Test 1 uses `findstr` to search SYSVOL for the `cpassword`
attribute in GPP XML files.

## What This Dataset Contains

The dataset captures a `findstr`-based SYSVOL search for GPP credentials executed as SYSTEM on
a domain-joined workstation.

**Sysmon EID 1 (Process Create) records the full attack chain:**

The `cmd.exe` invocation (tagged `technique_id=T1059.003`):
```
"cmd.exe" /c findstr /S cpassword %%logonserver%%\sysvol\*.xml
```

The `findstr.exe` process (tagged `technique_id=T1083,technique_name=File and Directory Discovery`):
```
findstr /S cpassword %%logonserver%%\sysvol\*.xml
```

Both processes ran as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`.

**Security EID 4688** provides independent confirmation of both process creations with command
lines. A `whoami.exe` event also appears — the ART test framework pre-check.

**PowerShell EID 4104** records the ART test framework wrapper that launched the `cmd.exe` command,
though the actual credential search is a native command rather than PowerShell script content.

The dataset spans 27 Sysmon events, 12 Security events, and 35 PowerShell events over 4 seconds.

## What This Dataset Does Not Contain (and Why)

**No SYSVOL file access events.** Object access auditing is disabled; there are no EID 4663
events for the XML files that `findstr` reads across the network share.

**No network connection events.** Although the `%%logonserver%%` variable resolves to a UNC
path on the domain controller (`\\ACME-DC01\sysvol\`), network connections to SMB are not
captured by this Sysmon configuration. Sysmon network events (EID 3) are configured for
outbound connections, and SMB to the DC may be filtered by the Sysmon config rules. The actual
SMB traffic is not represented.

**No findstr output.** Process output (stdout) is not captured by Windows event logging. Whether
any `cpassword` attributes were found in SYSVOL XML files is not determinable from this dataset.
The ACME domain was freshly provisioned and likely contains no legacy GPP password files.

**No GPP decryption activity.** This test only searches for the `cpassword` attribute; it does
not decrypt it. A complete GPP attack would follow this with AES decryption (trivial — the key
is public) or use a tool like `Get-GPPPassword` (see test 2).

The Sysmon configuration captures `findstr.exe` under the T1083 rule (File and Directory
Discovery), not through a T1552.006-specific rule — the detection is based on the search
behavior pattern.

## Assessment

This dataset captures the reconnaissance phase of a GPP credential attack: scanning SYSVOL for
legacy credential files. The `findstr /S cpassword` pattern targeting `*.xml` on the SYSVOL
share is a well-known indicator with high specificity. The cmd.exe and findstr.exe process
creation events are visible in both Sysmon and the Security log, providing redundant detection
coverage. Whether any credentials were discovered is not determinable, but the search itself is
the detectable event of interest.

## Detection Opportunities Present in This Data

- **EID 4688 / Sysmon EID 1 command line**: The string `findstr` combined with `cpassword` and
  `sysvol` (or `\sysvol\`) in any combination is a very specific indicator with negligible false
  positive rate in most environments.
- **Sysmon EID 1 rule tag**: `findstr.exe` captured under the T1083 (File and Directory
  Discovery) rule; pairing this with UNC path arguments or the `cpassword` keyword tightens the
  detection.
- **Process chain**: `powershell.exe` spawning `cmd.exe` spawning `findstr.exe` as SYSTEM from
  `C:\Windows\TEMP\` is unusual. Any user-space process launching `findstr` against `sysvol`
  should be reviewed.
- **Broader pattern**: Monitoring for any process accessing `\\*\sysvol\**\*.xml` at the file
  system level (via object access auditing if enabled) would catch this independent of the
  specific search term used.
