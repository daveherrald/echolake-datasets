# T1482-8: Domain Trust Discovery — TruffleSnout - Listing AD Infrastructure

## Technique Context

T1482 (Domain Trust Discovery) can be performed with specialized tooling beyond built-in utilities.
TruffleSnout is an open-source .NET tool designed for iterative AD and Azure AD infrastructure
discovery. This test exercises two TruffleSnout invocations: `forest -n %userdomain%` to enumerate
the forest and `domain -n %userdomain%` to enumerate the domain. Using `%userdomain%` as the target
argument means the tool targets the workstation's own domain (acme.local) dynamically.

## What This Dataset Contains

This dataset captures telemetry from two consecutive TruffleSnout execution attempts on ACME-WS02.

**Security channel (4688/4689)** provides the primary evidence. A 4688 event records the full
compound command: `"C:\AtomicRedTeam\atomics\..\ExternalPayloads\TruffleSnout.exe" forest -n
%userdomain% & "...TruffleSnout.exe" domain -n %userdomain%` wrapped in a cmd.exe invocation.
The cmd.exe exits with `0x1`, indicating TruffleSnout failed. Like the AdFind tests (T1482-4,
T1482-5), the exit code is `0x1` (tool error) rather than `0xC0000022` (Defender termination),
suggesting the .NET binary either failed to load properly or could not contact a DC.

**Sysmon channel** (36 events, IDs 1, 7, 10, 11, 17) captures process execution. The include-mode
ProcessCreate configuration captured the cmd.exe wrapper. Sysmon ID 7 (ImageLoad) events document
the DLL loading sequence. Sysmon ID 10 (ProcessAccess) captures test framework cross-process access, and
ID 17 (PipeCreate) records pipe activity.

**PowerShell channel** (34 events, IDs 4103/4104) contains exclusively ART test framework boilerplate.
No TruffleSnout-related PowerShell content is present.

## What This Dataset Does Not Contain

- Successful forest or domain enumeration output from TruffleSnout
- .NET runtime assembly load events that would indicate TruffleSnout's managed code executed
  successfully (Sysmon ID 7 focuses on cmd.exe, not TruffleSnout's own DLL loads)
- LDAP or DNS traffic to the domain controller
- TruffleSnout-specific named pipe activity (no pipes matching TruffleSnout patterns)

## Assessment

This dataset captures a **failed TruffleSnout enumeration attempt** with the tool invocation
command line preserved in Security 4688. TruffleSnout is less commonly seen in the wild than
AdFind or nltest, making its filename and command-line arguments relatively high-confidence
indicators when they appear. The use of `%userdomain%` as the argument value is notable — in
actual log events, this expands to the real domain name (acme), providing an additional artifact.
The dual-command structure (forest followed by domain) is a recognizable reconnaissance sequence.

## Detection Opportunities Present in This Data

- **Security 4688**: `TruffleSnout.exe` in any command line is a low-prevalence indicator; the
  tool is not present on standard enterprise systems
- **Security 4688**: The argument pattern `forest -n <domain>` or `domain -n <domain>` alongside
  TruffleSnout.exe identifies the specific discovery mode being used
- **Security 4688**: The `ExternalPayloads` staging path in the command line is consistent with
  tooling dropped during an intrusion and can be generalized to any non-standard binary path
- **Sysmon ID 1**: cmd.exe executing a .NET binary from a non-standard path with AD enumeration
  arguments; SHA256 hash of TruffleSnout.exe available for IOC matching
- **Compound command**: `& ` chaining of two TruffleSnout invocations in a single cmd.exe
  command line reveals scripted sequential enumeration
