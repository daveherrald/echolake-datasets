# T1482-5: Domain Trust Discovery — Adfind - Enumerate Active Directory Trusts

## Technique Context

T1482 (Domain Trust Discovery) via AdFind.exe is particularly common in pre-ransomware attack
chains. This test uses AdFind's built-in trust dump shortcut: `-gcb -sc trustdmp`, which queries
the global catalog and runs the "trustdmp" script to enumerate all domain trust relationships.
This is the AdFind invocation pattern most associated with ransomware operators such as Maze,
Conti, and their affiliates.

## What This Dataset Contains

This dataset captures telemetry from an AdFind.exe trust dump execution attempt on ACME-WS02.

**Security channel (4688/4689)** is the primary evidence source. A 4688 event records the full
command: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -gcb -sc trustdmp`.
The cmd.exe wrapper exits with `0x1` — AdFind failed to retrieve trust data, consistent with the
same failure seen in T1482-4. The exit code `0x1` indicates a tool error, not a Defender block
(`0xC0000022`).

**Sysmon channel** (36 events, IDs 1, 7, 10, 11, 17) documents the process execution. The
include-mode ProcessCreate rules captured the cmd.exe invocation. Sysmon ID 7 (ImageLoad) events
record DLL loading activity for the process chain. Sysmon ID 10 (ProcessAccess) and ID 17
(PipeCreate) capture ART test framework process interaction.

**PowerShell channel** (40 events, IDs 4103/4104) contains exclusively ART test framework boilerplate.
No technique-relevant content.

## What This Dataset Does Not Contain

- Successful trust enumeration — AdFind returned an error
- Global catalog LDAP queries or network connections to a DC
- AdFind.exe output file artifacts (the command does not redirect to a file in this test variant)
- The contents of AdFind's trust data if the query had succeeded

## Assessment

This dataset captures a **failed AdFind trust dump attempt** with the full command preserved in
the Security log. The `-gcb -sc trustdmp` argument combination is one of the most threat-intel-rich
AdFind invocation patterns available — it appears directly in public reporting on Maze, Conti, and
related ransomware intrusion chains. Even in failure, this telemetry provides a complete detection
opportunity. Compared to T1482-4 (OU enumeration), this test is more targeted: the `-gcb` flag
queries the global catalog, which requires DC connectivity that was unavailable from this workstation.

## Detection Opportunities Present in This Data

- **Security 4688**: `AdFind.exe` with `-gcb -sc trustdmp` arguments is a high-fidelity indicator
  directly correlated with ransomware pre-deployment reconnaissance in threat intelligence reporting
- **Security 4688**: The `-sc trustdmp` built-in script identifier is a specific string that can
  anchor a detection rule regardless of how AdFind is renamed or relocated
- **Sysmon ID 1**: cmd.exe → AdFind.exe execution chain with global catalog query arguments; the
  SHA256 hash of AdFind.exe can be used to detect the binary regardless of filename
- **Combined**: AdFind invocations across T1482-4 and T1482-5 together with other AD enumeration
  tests form a behavioral sequence characteristic of active intrusion reconnaissance
