# T1482-4: Domain Trust Discovery — Adfind - Enumerate Active Directory OUs

## Technique Context

T1482 (Domain Trust Discovery) is frequently executed using third-party AD enumeration tools.
AdFind.exe is a free, standalone AD query tool that has been widely abused by ransomware operators,
APT groups, and red teams to enumerate AD objects without requiring RSAT or PowerShell modules.
This test uses AdFind with the `-f (objectcategory=organizationalUnit)` filter to enumerate all
Organizational Units in the directory — a common first step in mapping AD structure.

## What This Dataset Contains

This dataset captures telemetry from an attempt to run AdFind.exe against the acme.local domain
from ACME-WS02.

**Security channel (4688/4689)** is the primary evidence source. A 4688 event records the full
command: `"cmd.exe" /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\AdFind.exe" -f
(objectcategory=organizationalUnit)`. The cmd.exe wrapper exits with `0x1`, indicating AdFind
failed. This is a tool execution failure (likely inability to contact the DC or a missing
dependency), not a Defender termination — exit `0x1` is a standard error return, not the
`0xC0000022` (STATUS_ACCESS_DENIED) that Defender produces when it kills a process.

**Sysmon channel** (26 events, IDs 1, 7, 10, 11, 17) captures process execution. The include-mode
ProcessCreate configuration picked up the cmd.exe wrapper. Sysmon ID 7 (ImageLoad) documents DLL
loading for cmd.exe and any AdFind.exe process activity. Sysmon ID 10 (ProcessAccess) captures
test framework cross-process access.

**PowerShell channel** (34 events, IDs 4103/4104) contains exclusively ART test framework boilerplate.
No technique-relevant PowerShell content is present.

## What This Dataset Does Not Contain

- Successful OU enumeration output — AdFind.exe returned an error
- LDAP network traffic to the domain controller
- AdFind.exe Sysmon ProcessCreate event if the child process was not captured by the include rules
  (the Security 4688 for the cmd.exe wrapper confirms the invocation path)
- Domain controller logs of any LDAP bind attempt by AdFind

## Assessment

This dataset captures a **failed AdFind execution attempt** with the tool invocation command line
fully preserved in the Security log. The presence of AdFind.exe in the `ExternalPayloads` directory
path is itself a detection indicator — the path is characteristic of ART test infrastructure and
real-world staging directories. The exit code `0x1` distinguishes this from Defender intervention.
The command-line evidence is sufficient for detection rule development even without a successful
execution outcome.

## Detection Opportunities Present in This Data

- **Security 4688**: The filename `AdFind.exe` in any command line is a high-confidence indicator —
  AdFind is a legitimate tool with no native Windows analog, making it an effective detection target
- **Security 4688**: The LDAP filter string `(objectcategory=organizationalUnit)` in a command line
  argument identifies this as AD OU enumeration specifically
- **Sysmon ID 1**: cmd.exe executing AdFind.exe from a non-standard path (`ExternalPayloads`
  subdirectory) is detectable by parent-child relationship and command-line content
- **File path**: The presence of AdFind.exe in the `C:\AtomicRedTeam\atomics\..\ExternalPayloads\`
  path is observable via Sysmon ID 11 (FileCreate) if AdFind was downloaded or written during setup
