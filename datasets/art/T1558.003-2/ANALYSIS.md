# T1558.003-2: Kerberoasting — Rubeus kerberoast

## Technique Context

Kerberoasting (T1558.003) exploits the fact that any authenticated domain user can request Kerberos TGS tickets for accounts with registered SPNs. The resulting tickets are encrypted with the service account's NTLM password hash and can be cracked offline. This test uses Rubeus, a C# Kerberos toolset widely used by attackers and red teams, pre-staged at `C:\AtomicRedTeam\ExternalPayloads\rubeus.exe`. The test first purges existing Kerberos tickets with `klist purge`, then executes Rubeus in kerberoast mode, writing output to a file.

## What This Dataset Contains

The dataset spans approximately 5 seconds on 2026-03-14 from ACME-WS02 (acme.local domain) and contains 82 events across Sysmon, Security, and PowerShell channels.

**The attack command**, captured in Security 4688 and PowerShell 4104:
```
powershell.exe & {klist purge
cmd.exe /c "C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus.exe" kerberoast /outfile:"C:\AtomicRedTeam\atomics\..\ExternalPayloads\rubeus_output.txt"}
```

**Rubeus.exe was blocked.** The `cmd.exe` process exits with status `0x1` (failure). Rubeus.exe itself never appears as a process creation event in either Security 4688 or Sysmon 1 — Defender prevented the binary from launching, consistent with its detection of Rubeus by reputation/hash.

**Process chain** (Security 4688 and Sysmon 1):
1. `whoami.exe` — ART test framework identity pre-check
2. `powershell.exe` — carrying the full `klist purge` + rubeus command
3. `klist.exe purge` — successfully purged the Kerberos ticket cache
4. `cmd.exe` — spawned to execute rubeus.exe, exits 0x1

**Sysmon events include:**
- Event 1: `whoami.exe` (T1033), `powershell.exe` (T1059.001), `klist.exe` (T1087/Account Discovery), `cmd.exe` (T1059.003)
- Event 7: .NET CLR image loads into `powershell.exe`
- Event 10: PowerShell accessing child processes (T1055.001 rule match in sysmon-modular)
- Event 11: PowerShell profile startup data file creation
- Event 17: `\PSHost.*` named pipes for PowerShell host initialization

**PowerShell 4104** records the full script block (both the outer `& { ... }` wrapper and the inner body), plus standard module boilerplate.

## What This Dataset Does Not Contain (and Why)

**No Rubeus execution telemetry.** Defender blocked rubeus.exe before it could run. There is no Sysmon 1 or Security 4688 for the binary itself, no kerberoast output file, and no Kerberos TGS ticket requests (Security 4769) visible in this dataset.

**No DC-side Kerberos events.** Even if Rubeus had run, the 4769 events would appear on the domain controller's Security log, not the workstation. This dataset covers only the workstation endpoint.

**No Defender error in PowerShell log.** Unlike test 1 (which used `iex`), this invocation passes through `cmd.exe`, so the AMSI block on rubeus.exe does not produce a PowerShell 4100 error — it manifests only as `cmd.exe` exiting with error code 0x1.

## Assessment

Defender blocked Rubeus.exe before execution. The dataset captures the complete attack setup: `klist purge` to clean the ticket cache (itself a notable pre-attack behavior), the full command line for the rubeus kerberoast invocation, and the failure of `cmd.exe` with exit code 0x1. The `klist.exe purge` step is particularly meaningful as it represents intentional cache clearing before ticket harvesting, and is not typical of legitimate use. Despite the block, the command line evidence is sufficient for high-confidence detection.

## Detection Opportunities Present in This Data

- **Security 4688 / Sysmon 1**: `powershell.exe` spawning `klist.exe purge` followed by `cmd.exe` referencing `rubeus.exe kerberoast` — the sequence and arguments are highly anomalous
- **Security 4688 / Sysmon 1**: `klist.exe` with `purge` argument run immediately before a kerberoasting attempt — `klist purge` is a documented pre-attack step to ensure fresh ticket requests
- **PowerShell 4104**: Script block containing the full rubeus command line including `/outfile:` argument
- **Security 4689**: `cmd.exe` exits with status `0x1` immediately after being passed a rubeus.exe path — failure exit code corroborates Defender block
- **Sysmon 1**: `klist.exe` tagged with `T1087/Account Discovery` rule — the sysmon-modular config treats klist as account discovery tooling
