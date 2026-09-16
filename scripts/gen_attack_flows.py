#!/usr/bin/env python3
"""Generate MITRE Attack Flow v2.0.0 STIX 2.1 bundles for the scenario datasets.

Each scenario is defined below as an ordered list of stages (name, ATT&CK
technique id, description). This emits, per scenario, a STIX 2.1 bundle with:

  - the canonical Attack Flow extension-definition,
  - an identity (created_by_ref),
  - an attack-flow root SDO (start_refs -> first action),
  - one attack-action per stage, chained via effect_refs,
  - one attack-pattern per distinct technique (external_references -> ATT&CK).

Deterministic: object ids are uuid5 over a per-scenario namespace so re-running
produces byte-stable output. Written to datasets/<name>/attack_flow.json.

Grounded strictly in each dataset's own mitre_attack block plus the recorded
kill-chain order; no techniques are invented here.
"""

import json
import uuid
from pathlib import Path

# Canonical Attack Flow extension-definition id (fixed by the CTID spec).
AF_EXT_ID = "extension-definition--fb9c968a-745b-4ade-9b25-c324172197f4"
AF_EXT = {AF_EXT_ID: {"extension_type": "new-sdo"}}

# Stable timestamps so output is byte-reproducible.
CREATED = "2026-09-08T00:00:00.000Z"

DATASETS_DIR = Path(__file__).resolve().parent.parent / "datasets"

# ns for deterministic ids, one per scenario keeps ids scoped and stable.
BASE_NS = uuid.UUID("6ba7b810-9dad-11d1-80b4-00c04fd430c8")


# Each scenario: dataset dir name -> (flow name, flow description, [stages]).
# A stage is (action_name, technique_id, description). Order is the chain order.
SCENARIOS = {
    "thebiggerinterview": (
        "TheBiggerInterview: CI/CD to Kubernetes to AWS compromise",
        "A GitHub Actions workflow vulnerability leads to CI/CD supply-chain "
        "compromise, a Kubernetes tenant foothold, node and cluster compromise, "
        "and durable AWS persistence with database exfiltration. Seven phases "
        "correlated across GitHub audit, EKS audit, CrowdStrike EDR, and AWS "
        "CloudTrail. Chain order per the unsecure.sh scenario writeup.",
        [
            ("P1 CI/CD compromise via GitHub Actions cache poisoning", "T1195.002",
             "Unauthorized PR triggers a workflow on the dev ref that writes a backdoored artifact into the Actions cache."),
            ("P2 Supply-chain poisoning of the container image", "T1525",
             "The trusted release job restores the poisoned cache entry and bakes the backdoored entrypoint into the production image."),
            ("P2 Backdoored host software binary shipped", "T1554",
             "The compromised application binary is distributed in the pushed image."),
            ("P3 Tenant foothold via backdoored app", "T1610",
             "app-1 pulls the backdoored image; an in-memory beacon executes in an unprivileged namespace."),
            ("P3 Container and resource discovery", "T1613",
             "The beacon reads env and files to discover the monitoring service and cluster resources."),
            ("P3 Steal monitoring service-account token", "T1528",
             "Arbitrary file read yields the monitoring-sa projected token (get pods cluster-wide, nodes/proxy)."),
            ("P4 Exec into node debug pod (escape to host)", "T1611",
             "The beacon reaches the kubelet and execs into an operator's node debug pod, whose host mount gives root via chroot."),
            ("P4 Kernel rootkit installed as static pod", "T1547.006",
             "An LKM plus eBPF rootkit is written as a static pod manifest and loaded by restarting the kubelet, with no API-server record."),
            ("P4 Rootkit conceals node activity", "T1014",
             "The kernel rootkit hides the implant's processes and network activity on the node."),
            ("P5 Harvest CI runner credentials from files", "T1552.001",
             "The rootkit harvests AWS credentials present on the node filesystem."),
            ("P5 Cross-tenant escalation to cluster-admin", "T1078.004",
             "A backdoored orchestrator image is pulled by the privileged tenant; the cluster-admin orchestrator-sa token is stolen, and the ack-lambda-controller IRSA token with it."),
            ("P6 Account manipulation, cross-account IAM into aws-auth", "T1098",
             "orchestrator-sa patches aws-auth to add a cross-account IAM user for durable cluster access."),
            ("P6 Serverless persistence via ephemeral Lambdas", "T1648",
             "Lambdas (save-logging, iac-*) are created via PassRole onto a privileged role, plus a durable save-logging-info implant and an hourly EventBridge rule; iac-* peer VPCs and open RDS/EKS security groups."),
            ("P7 Collect application databases", "T1530",
             "The peered link is used to reach and dump the application databases."),
            ("P7 Exfiltration over web service", "T1567",
             "save-logging-info exfiltrates harvested AWS admin credentials on every hourly run; database contents are exfiltrated over the peered path."),
        ],
    ),
    "currentis-operation-black-start": (
        "Operation Black Start: agentic prompt-injection to IT-to-OT pre-positioning",
        "A fictional ICS/OT intrusion at Currentis Energy. Prompt injection of an "
        "agentic assistant leads to LOTL recon, an HTTP C2 beacon, LSASS credential "
        "theft, an IT-to-OT pivot on a stolen vendor account, OT reconnaissance, "
        "low-and-slow exfiltration, and a log clear, ending in staged (not fired) "
        "OT manipulation. Chain order per the Black Start kill-chain.",
        [
            ("Prompt-injection initial access", "T1566",
             "A poisoned NERC CIP document from a trusted sender is auto-processed by the rchen OpenClaw assistant."),
            ("User execution of the stager", "T1204",
             "The assistant executes an embedded instruction as the rchen user."),
            ("PowerShell stager", "T1059.001",
             "A base64 PowerShell stager runs; the on-host attack descends from the agent."),
            ("Deobfuscate staged payload", "T1140",
             "The obfuscated stager content is decoded on host."),
            ("Domain account discovery", "T1087.002",
             "net user/group /domain and AD queries enumerate the domain."),
            ("Masqueraded C2 beacon with Run-key persistence", "T1071.001",
             "kb5041234-v3.exe beacons to the C2 (~60s) with a registry Run-key; the C2 IP is a documented Cobalt Strike indicator."),
            ("LSASS credential dumping", "T1003.001",
             "An LSASS read harvests the cached turbine-vendor credential and a dormant service account."),
            ("IT-to-OT pivot on stolen vendor account (RDP)", "T1021.001",
             "RDP from WS-RACHEL to the SCADA jump host using the stolen helixgrid-svc account. Enterprise T1021.001 / ICS T0859."),
            ("OT reconnaissance / control-loop mapping", "T1083",
             "Enumerate engineering software and pull Unit 3 turbine config and alarm/setpoint data. ICS T0888."),
            ("Collect operational information", "T1005",
             "Turbine config and alarm data are staged from the local system. ICS T0882."),
            ("Low-and-slow exfiltration over C2", "T1041",
             "Turbine config and alarm data trickle out the C2 channel, staged small."),
            ("Stage OT manipulation, then clear logs", "T1070.001",
             "A Unit 3 setpoint-modification capability is staged but not fired; the Security log is cleared and staging artifacts deleted. ICS T0831 (staged)."),
        ],
    ),
    "paws-operation-yarn-ball": (
        "Operation Yarn Ball: Sliver C2 attack chain",
        "A multi-stage intrusion on the PAWS lab: discovery, DNS-tunneled C2, "
        "LOLBin proxy execution, scheduled-task and Run-key persistence, credential "
        "access, lateral movement over WinRM/SMB, ransomware impact, and a log clear.",
        [
            ("System and network discovery", "T1082",
             "Host, network, and user discovery on the initial workstation."),
            ("DNS-tunneled C2", "T1071.004",
             "A Sliver beacon communicates over DNS."),
            ("LOLBin proxy execution", "T1218",
             "A signed system binary proxies attacker code (defense evasion)."),
            ("Scheduled task and Run-key persistence", "T1053",
             "A scheduled task and a registry Run-key establish persistence."),
            ("Harvest unsecured credentials", "T1552",
             "Credentials are recovered from files and configuration."),
            ("Lateral movement over WinRM/SMB", "T1021.006",
             "The actor moves to additional hosts via Windows Remote Management and admin shares (T1021.002)."),
            ("Remote service execution", "T1569.002",
             "A service is created and started on a remote host to execute payload."),
            ("Exfiltration over C2", "T1041",
             "Collected data is exfiltrated over the Sliver channel."),
            ("Ransomware impact and log clear", "T1486",
             "Data is encrypted for impact; the Security event log is cleared (T1070.001)."),
        ],
    ),
    "ctid-process_injection": (
        "CTID micro-emulation: Process Injection (PE injection)",
        "A CTID micro-emulation of process injection via portable-executable "
        "injection.",
        [
            ("Portable executable injection", "T1055.002",
             "Attacker code is injected into a target process via PE injection (T1055 Process Injection)."),
        ],
    ),
    "ctid-named_pipes": (
        "CTID micro-emulation: Named Pipes (inter-process communication)",
        "A CTID micro-emulation exercising inter-process communication over named "
        "pipes.",
        [
            ("Inter-process communication over named pipes", "T1559",
             "Named-pipe IPC is used for local coordination/execution."),
        ],
    ),
    "ctid-reflective_loading": (
        "CTID micro-emulation: Reflective Code Loading",
        "A CTID micro-emulation of reflective code loading followed by light "
        "discovery.",
        [
            ("Reflective code loading", "T1620",
             "Code is loaded reflectively into memory, avoiding the on-disk image (defense evasion)."),
            ("System information discovery", "T1082",
             "Host information is enumerated after load."),
            ("System network connections discovery", "T1049",
             "Active network connections are enumerated."),
        ],
    ),
    "ctid-log_clearing": (
        "CTID micro-emulation: Clear Windows Event Logs",
        "A CTID micro-emulation of Windows event-log clearing.",
        [
            ("Clear Windows event logs", "T1070.001",
             "Windows event logs are cleared to remove indicators (defense evasion)."),
        ],
    ),
    "ctid-log_clearing_full": (
        "CTID micro-emulation: Clear Windows Event Logs (full)",
        "A CTID micro-emulation of Windows event-log clearing (full-capture "
        "variant).",
        [
            ("Clear Windows event logs", "T1070.001",
             "Windows event logs are cleared to remove indicators (defense evasion)."),
        ],
    ),
}


def det_id(ns: uuid.UUID, stix_type: str, key: str) -> str:
    return f"{stix_type}--{uuid.uuid5(ns, stix_type + ':' + key)}"


def build_bundle(dir_name: str, flow_name: str, flow_desc: str, stages):
    ns = uuid.uuid5(BASE_NS, dir_name)
    identity_id = det_id(ns, "identity", "echolake")
    flow_id = det_id(ns, "attack-flow", dir_name)

    objects = []

    # extension-definition (canonical Attack Flow)
    objects.append({
        "type": "extension-definition",
        "spec_version": "2.1",
        "id": AF_EXT_ID,
        "created_by_ref": identity_id,
        "created": "2022-08-02T19:34:35.143Z",
        "modified": "2022-08-02T19:34:35.143Z",
        "name": "Attack Flow",
        "description": "Extends STIX 2.1 with features to create Attack Flows.",
        "schema": "https://center-for-threat-informed-defense.github.io/attack-flow/stix/attack-flow-schema-2.0.0.json",
        "version": "2.0.0",
        "extension_types": ["new-sdo"],
    })

    # identity (author)
    objects.append({
        "type": "identity",
        "spec_version": "2.1",
        "id": identity_id,
        "created": CREATED,
        "modified": CREATED,
        "name": "EchoLake Project",
        "identity_class": "organization",
    })

    # attack-pattern per distinct technique
    tech_ids = []
    for _, tid, _ in stages:
        if tid not in tech_ids:
            tech_ids.append(tid)
    ap_ref = {}
    for tid in tech_ids:
        apid = det_id(ns, "attack-pattern", tid)
        ap_ref[tid] = apid
        objects.append({
            "type": "attack-pattern",
            "spec_version": "2.1",
            "id": apid,
            "created": CREATED,
            "modified": CREATED,
            "name": tid,
            "external_references": [
                {"source_name": "mitre-attack", "external_id": tid}
            ],
        })

    # attack-action per stage, chained
    action_ids = [det_id(ns, "attack-action", f"{i}:{name}") for i, (name, _, _) in enumerate(stages)]
    for i, (name, tid, desc) in enumerate(stages):
        action = {
            "type": "attack-action",
            "spec_version": "2.1",
            "id": action_ids[i],
            "created": CREATED,
            "modified": CREATED,
            "name": name,
            "technique_id": tid,
            "technique_ref": ap_ref[tid],
            "description": desc,
            "extensions": AF_EXT,
        }
        if i + 1 < len(stages):
            action["effect_refs"] = [action_ids[i + 1]]
        objects.append(action)

    # attack-flow root SDO
    flow = {
        "type": "attack-flow",
        "spec_version": "2.1",
        "id": flow_id,
        "created_by_ref": identity_id,
        "created": CREATED,
        "modified": CREATED,
        "name": flow_name,
        "description": flow_desc,
        "scope": "incident",
        "start_refs": [action_ids[0]],
        "extensions": AF_EXT,
    }
    # attack-flow object goes at the front of the objects list per convention.
    objects.insert(2, flow)

    bundle_id = det_id(ns, "bundle", dir_name)
    return {
        "type": "bundle",
        "id": bundle_id,
        "objects": objects,
    }


def main():
    for dir_name, (name, desc, stages) in SCENARIOS.items():
        out_dir = DATASETS_DIR / dir_name
        if not out_dir.is_dir():
            print(f"SKIP (dir missing): {dir_name}")
            continue
        bundle = build_bundle(dir_name, name, desc, stages)
        out_path = out_dir / "attack_flow.json"
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(bundle, f, indent=2)
            f.write("\n")
        print(f"wrote {out_path}  ({len(stages)} actions, {len(bundle['objects'])} objects)")


if __name__ == "__main__":
    main()
