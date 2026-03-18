# T1087.002-12: Domain Account — Enumerate Active Directory Users with ADSISearcher

## Technique Context

T1087.002 (Account Discovery: Domain Account) includes numerous methods to query Active Directory for domain user accounts. The `[adsisearcher]` PowerShell type accelerator provides direct access to Active Directory Services Interface (ADSI) without importing any additional modules or downloading external tools. By issuing `([adsisearcher]"objectcategory=user").FindAll()`, an attacker retrieves all user objects from the domain using the same LDAP infrastructure that Windows itself uses for normal AD operations.

This technique is particularly significant because it requires zero external dependencies — no PowerView, no AD module, no net.exe — making it harder to detect through tool-specific signatures. The ADSI search uses the domain controller the workstation is already authenticated to, generating LDAP queries indistinguishable from normal Windows authentication traffic. Defender does not flag this technique; both defended and undefended datasets capture the same technique-relevant telemetry.

## What This Dataset Contains

This dataset covers a 5-second window (2026-03-14T23:34:14Z–23:34:19Z).

**Process execution chain**: Sysmon EID 1 captures two events. The first is `whoami.exe` (PID 6756) at 23:34:15 as a pre-execution identity check. The second is the main PowerShell process (PID 6496) at 23:34:17 with the explicit command line:

```
"powershell.exe" & {([adsisearcher]"objectcategory=user").FindAll(); ([adsisearcher]"objectcategory=user").FindOne()}
```

Tagged `technique_id=T1059.001,technique_name=PowerShell` by sysmon-modular. The process runs as `NT AUTHORITY\SYSTEM` from `C:\Windows\TEMP\`.

The command issues both `.FindAll()` (returns all matching users) and `.FindOne()` (returns the first matching user), demonstrating both bulk enumeration and targeted single-object lookup.

**Network activity (Sysmon EID 3 and EID 22)**: The dataset includes 2 EID 3 (network connection) events and 1 EID 22 (DNS query) event in the total count, though these fall outside the 20-sample set. These represent the LDAP connections to ACME-DC01 made by `powershell.exe` executing the ADSI queries. This is the key behavioral distinction from other domain account tests in this batch — the ADSI query generates observable network connections to the domain controller that appear in the dataset, even though domain-side events are outside scope.

**Sysmon EID 11 (file creation)**: The defended analysis mentions creation of an `acme.local.sch` file in the Active Directory schema cache directory. This file appears as a Sysmon EID 11 event (2 total in the dataset). Windows caches AD schema information locally when ADSI queries are first executed — this cache file is a persistent artifact of the domain enumeration that persists after the process exits.

**Security events**: Four EID 4688 events. The additional process creation (compared to simpler tests) reflects the ADSI search spawning or accessing additional system components during LDAP query execution.

**PowerShell script block logging**: 95 EID 4104 events were captured. The available samples include the test framework module import and cleanup invocation. The actual `[adsisearcher]"objectcategory=user"` commands are logged in the full 95-event set.

**DLL loading**: 24 Sysmon EID 7 events reflect .NET runtime, ADSI, and LDAP client DLLs loading. The ADSI subsystem requires loading `adsldp.dll`, `activeds.dll`, and related Active Directory client libraries — a distinct DLL loading fingerprint compared to simpler PowerShell tests.

**Application channel**: A single EID 15 event indicating Defender status returned to `SECURITY_PRODUCT_STATE_ON` — the test framework re-enables Defender after the test completes.

Comparing to the defended dataset (42 sysmon, 14 security, 37 powershell): the undefended run has 40 sysmon, 4 security, and 95 powershell events. The sysmon counts are nearly identical, confirming Defender does not significantly alter this technique's event generation. The powershell count increase (95 vs 37) reflects execution proceeding further and logging more script blocks.

## What This Dataset Does Not Contain

The results of the ADSI search — the list of domain user accounts discovered in `acme.local` — do not appear in any event. The `.FindAll()` and `.FindOne()` returns are in-memory PowerShell objects visible only to the executing process. No event captures which users were found, their attributes, or how many user objects exist in the domain.

The LDAP connections to the domain controller (Sysmon EID 3 events) contain connection metadata but not query content or response data.

## Assessment

This dataset is forensically interesting because it shows a technique that leaves multiple independent evidence streams: the explicit `[adsisearcher]` command line (process creation), network connections to the domain controller (Sysmon EID 3), AD schema cache file creation (Sysmon EID 11), and ADSI DLL loading (Sysmon EID 7). The schema cache file in particular is a persistent on-disk artifact that survives process termination — an investigator examining the system later could find `acme.local.sch` in the schema cache directory as evidence that ADSI queries were executed.

The `[adsisearcher]` technique is notable for its stealth: no external tools, no unusual DLL loading, and LDAP traffic that resembles normal Windows authentication activity. Yet it leaves the same process creation and schema cache artifacts as more obvious tools.

## Detection Opportunities Present in This Data

**Sysmon EID 1 / Security EID 4688**: The command line `([adsisearcher]"objectcategory=user").FindAll()` is fully visible. The ADSI type accelerator with broad `objectcategory=user` filter is a reliable indicator of bulk user enumeration. Legitimate administrative scripts may use ADSI, but `.FindAll()` across all users from a SYSTEM-level PowerShell process in `C:\Windows\TEMP\` is anomalous.

**Sysmon EID 3 (Network Connection)**: PowerShell connecting to ACME-DC01 on LDAP port (389) or Global Catalog (3268) — events present in the full dataset — provide corroborating evidence of domain controller communication during the enumeration.

**Sysmon EID 11 (File Created)**: Creation of `acme.local.sch` in the AD schema cache directory by PowerShell is a persistent artifact of ADSI query execution. This file creation is a reliable indicator that an ADSI search was performed, detectable even after the process exits.

**Sysmon EID 7 (DLL Loading)**: ADSI client libraries (`adsldp.dll`, `activeds.dll`) loading into `powershell.exe` signals LDAP-based directory queries. These DLLs are not typically loaded by legitimate PowerShell scripts.

**PowerShell EID 4104**: The `[adsisearcher]"objectcategory=user"` script block will appear in the 95 EID 4104 events, providing a second source confirming the query string.
