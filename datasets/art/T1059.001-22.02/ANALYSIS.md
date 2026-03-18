# T1059.001-22: PowerShell — SOAPHound Build Cache

## Technique Context

T1059.001 (PowerShell) wraps the execution of SOAPHound in its cache-building mode. Where test 21 performed a full BloodHound data dump (`--bhdump`), this test uses `--buildcache`, which queries Active Directory via ADWS to construct a local cache file that subsequent SOAPHound operations can use without re-querying the DC. Building a cache is often the first step in a two-phase SOAPHound workflow: cache first, then dump from cache — reducing the query volume visible to the domain controller.

The tool syntax differs slightly between the two tests, illustrating a real-world operational nuance: test 21 used `--user $env:USERNAME --domain $env:USERDOMAIN` while test 22 uses `--user $($env:USERNAME)@$($env:USERDOMAIN)` — the UPN format (`user@domain`) rather than the separate user/domain arguments. Detection rules that key on one format may miss the other.

The full command:
```
C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe --user $($env:USERNAME)@$($env:USERDOMAIN)
--password P@ssword1 --dc 10.0.1.14 --buildcache --cachefilename c:\temp\cache.txt
```

ADWS runs on TCP 9389. Network monitoring rules for BloodHound/SharpHound focused on LDAP (389/636) would miss this traffic entirely.

## What This Dataset Contains

Security EID 4688 records four process creates. The primary one is the PowerShell child (PID 0x1640) with the full SOAPHound command line including credentials and DC target. A cleanup step `"powershell.exe" & {}` appears as an empty block — the test framework running a no-op cleanup since `--buildcache` doesn't create output files that need deletion. Two `whoami.exe` processes are also captured.

The PowerShell channel has 104 EID 4104 events, the same count as test 21. The script blocks cover the test framework and SOAPHound invocation.

Sysmon provides 24 events across EIDs 7, 1, 10, 2, 17, and 11. The notable addition compared to test 21 is the EID 2 (FileCreationTimeChanged) event:

```
Image: C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.26010.5-0\MsMpEng.exe
TargetFilename: C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe
CreationUtcTime: 2026-03-14 22:38:25.145
PreviousCreationUtcTime: 2026-03-14 22:38:25.145
RuleName: technique_id=T1099,technique_name=Timestomp
```

Windows Defender's `MsMpEng.exe` touched the creation timestamp on `SOAPHound.exe` — or rather, Sysmon detected no actual timestamp change (both times are identical) but the event was recorded because MsMpEng accessed the file's metadata. This is Defender scanning the binary before execution, which even with real-time protection disabled, Defender may still scan newly-executed files. The EID 2 event here is evidence of Defender scanning SOAPHound.exe, tagged as Timestomp because the Sysmon rule fires on any file-time change event from a suspicious source.

Sysmon EID 1 shows `whoami.exe` (PID 6464) and the PowerShell process (PID 5696, CommandLine: `"powershell.exe" & {C:\AtomicRedTeam\atomics\T1059.001\bin\SOAPHound.exe --user $($env:USERNAME)@$($env:USERDOMAIN) --password P@ssword1 --dc 10.0.1.14 --buildcache --cachefilename c:\temp\cache.txt}`). EID 10 shows three full-access handle opens (0x1FFFFF) from the parent PowerShell (PID 1552) to `whoami.exe`, to the SOAPHound-executing PowerShell (PID 5696), and to a second `whoami.exe` (PID 6304). EID 11 is the PowerShell startup profile write.

Compared to the defended version (which similarly lacked SOAPHound.exe process creation and network events), this undefended version adds the EID 2 Defender scan artifact and the complete credential-bearing command line in EID 4688.

## What This Dataset Does Not Contain

Like test 21, there are no Sysmon EID 3 network events and no EID 22 DNS queries. The `c:\temp\cache.txt` cache file creation is not recorded via EID 11 — either the Sysmon configuration does not capture writes to `c:\temp\` or SOAPHound did not successfully connect to the DC and create the file.

No direct process-creation event for `SOAPHound.exe` appears as a Sysmon EID 1 — the tool's execution is only documented through the parent PowerShell's command line. The UPN format for credentials (`user@domain`) versus the separate-field format in test 21 is present here, which is a useful variant for detection rule coverage testing.

## Assessment

This dataset pairs usefully with test 21 to illustrate SOAPHound's two-phase operational pattern. The cache-build phase generates its own artifacts distinct from the dump phase. The EID 2 artifact from `MsMpEng.exe` scanning `SOAPHound.exe` is an interesting side-channel: even with real-time protection disabled, Defender's engine touches file timestamps when scanning, and that scan is recorded by Sysmon. This suggests that `MsMpEng.exe`-sourced EID 2 events on executable files in unusual paths may be worth monitoring even in environments where AV is believed to be disabled.

## Detection Opportunities Present in This Data

1. EID 4688 `CommandLine` containing `SOAPHound.exe` with `--buildcache` and `--cachefilename c:\temp\` — cache-building mode of SOAPHound with a staging path.
2. EID 4688 `CommandLine` with UPN-format credential argument `--user username@domain --password plaintext` — a different credential format from test 21, covering both SOAPHound invocation styles.
3. Sysmon EID 2 with `Image: MsMpEng.exe` and `TargetFilename` containing an executable in an unusual path — Defender scanning a tool binary, indicating file access even when real-time protection is nominally disabled.
4. EID 4688 with `--dc 10.0.1.14` — direct IP reference to a domain controller as a recon tool target.
5. Sysmon EID 1 on PowerShell tagged `technique_id=T1059.001` with SOAPHound arguments in the command line — Sysmon rule correlation with process creation.
6. EID 4688 showing `--buildcache` mode — the presence of this flag indicates a staged operation where cache-building precedes actual data collection, potentially allowing defenders to detect the setup phase before the dump occurs.
7. Sysmon EID 10 `GrantedAccess: 0x1FFFFF` from parent PowerShell to child PowerShell running a credential-bearing tool command.
