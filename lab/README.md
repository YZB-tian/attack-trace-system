# Course lab: scripts, runbooks and evidence index

This directory publishes the isolated laboratory material behind the runs
described in `docs/`. It contains three things:

| Path | Content |
| --- | --- |
| `guest-services/` | The scripts that build and drive the lab (guest setup, the two exploitation runs, the covert-channel rig, the Windows memory-injection test, and the Zeek/export helpers). |
| `*.md`, `*.txt` | The laboratory runbook, node plan, network log, requirement-fit notes and the static-IP commands used for the original Metasploitable2 prototype. |
| `evidence-index/` | A sanitized, publishable index of the collected evidence: per-run derived analysis output, run manifests with SHA-256 hashes, live Zeek logs from the second run, and the combined store. |
| `images-and-datasets.md` | Sources, sizes and SHA-256 for the material that is deliberately **not** in this repository (VM disks, ISOs, public datasets). |

## Credentials are placeholders

The scripts in `guest-services/` were exported from a working lab, so every
password was replaced by a placeholder before publication:

| Placeholder | Original use |
| --- | --- |
| `__KALI_PASSWORD__` | Kali guest account (vmrun `-gp`, `sudo -S`) |
| `__LAB_PASSWORD__` | Windows lab administrator account |
| `__FORENSICS_PASSWORD__` | Dedicated evidence-collection account on the Linux targets |
| `__TRAINING_PASSWORD__` | The one valid login in the web exercise |
| `__TARGET_PASSWORD__` | Credential cracked from the target's shadow file and reused for lateral movement |

Set the real values locally before running anything, or keep the passwords in
your own environment/secret store. The collected `/etc/shadow` hashes are also
removed: `guest-services/exploit-chain/07-crack-hashes.sh` now expects you to
paste the dump gathered during the exercise.

Metasploitable2 is an intentionally vulnerable image whose default account is
printed on its own console banner; that default is the only credential the
repository still names, and it exists to explain the lateral-movement step.

## What is not published, and why

| Excluded | Reason |
| --- | --- |
| VM disks, ISOs, memory images (`*.vmdk`, `*.vmx`, `*.vmem`, `*.iso`) | Single files are 1.9 GB - 20 GB; GitHub rejects anything over 100 MB. See `images-and-datasets.md` for sources and hashes. |
| Raw captures and host exports (`*.pcap`, `*.pcapng`, `*.evtx`) | Contain plaintext lab credentials (the configuration telnet sessions), password hashes and internal host data. Kept local. |
| Third-party datasets (`APT29` Mordor collection, official ATT&CK STIX bundle, Zeek package) | Large third-party downloads with their own licences and update cadence; the exact URLs and hashes are recorded instead. |
| Derived graphs larger than 10 MB (`covert-positive`, `kernel-monitor2`) | Reproducible from the published normalized events with one command; see `evidence-index/README.md`. |

## Reproducing a run

1. Build the lab per `COURSE-LAB-RUNBOOK.md` and `lab-node-plan.md`, restoring
   the real passwords in the scripts.
2. Run the exercise scripts under `guest-services/exploit-chain/`,
   `guest-services/covert-channel/` or `guest-services/memory-injection/`.
3. Import the collected evidence with the importers in the repository's
   `scripts/` directory; each `docs/*-verification.md` file lists the exact
   commands and the expected numbers.
