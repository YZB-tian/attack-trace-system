# Images and datasets that are not stored in this repository

The lab runs on virtual machines and public data whose files are far larger than
GitHub's 100 MB per-file limit, and one of them (the Mordor dataset) is a
third-party research collection. This page records where each file came from,
how large it is, and the SHA-256 measured on the copy actually used, so the
environment can be rebuilt and verified without publishing gigabytes.

## Virtual machine images

| File | Role | Size | SHA-256 |
| --- | --- | ---: | --- |
| `kali-linux-2026.2-installer-amd64.iso` | Attacker node (official Kali release) | 4580.1 MB | `6dbefacc95e3b556c19c48e8bae39b8b505e2d3a1aba0bfb7ab62b036c3d2ba3` |
| `Metasploitable.vmdk` (Metasploitable2-Linux) | Intentionally vulnerable Linux targets | 1836.4 MB | `d75afaf67149fb64c1330bc7ffc6654de13e485fdce0ac922c4315ef7382b684` |
| `ubuntu-24.04.4-live-server-amd64.iso` | Ubuntu web, C2 simulator, mail and sensor nodes | 3247.7 MB | `e907d92eeec9df64163a7e454cbc8d7755e8ddc7ed42f99dbc80c40f1a138433` |
| Windows 11 Enterprise / Windows Server 2025 evaluation ISOs | Office and core-server nodes | 7.0 GB / 8.0 GB | Official Microsoft evaluation downloads; hash on demand |

The two working Metasploitable2 copies (`03-Metasploitable2` and
`06-Metasploitable2-Clone`) are converted growable disks derived from the
`Metasploitable.vmdk` above; their hashes were not computed because the running
virtual machines hold the files open.

Obtain Kali from <https://www.kali.org/get-kali/>, Ubuntu from
<https://releases.ubuntu.com/24.04/>, Metasploitable2 from
<https://sourceforge.net/projects/metasploitable/>, and the Windows evaluation
images from the Microsoft Evaluation Center.

## Public datasets and packages

| File | Use | Size | SHA-256 |
| --- | --- | ---: | --- |
| `apt29_evals_day1_manual_2020-05-01225525.json` (OTRF Mordor, APT29 day 1) | Public enterprise dataset used in `docs/public-dataset-validation.md` | 367.5 MB | `dce651806007a20f6f4bac806dd6054e3361e0dd57a74ddd2f7cb5665d98c954` |
| `enterprise-attack.json` (MITRE ATT&CK STIX) | Official technique/tactic naming for the ATT&CK mapping | 51.3 MB | `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4` |
| `zeek-core.deb` (Zeek 7.0.11) | Offline and live packet-to-log parsing | 8.7 MB | `481f8a8fe66503ad0622a1df585ccddb4371c1e54d998f3f339eb101bb5b8c45` |

Sources:

- APT29 day 1 host collection:
  `https://raw.githubusercontent.com/OTRF/Security-Datasets/master/datasets/compound/apt29/day1/apt29_evals_day1_manual.zip`
  (the JSON above is the single file inside that archive)
- Official ATT&CK bundle:
  `https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json`
- Zeek package: the `zeek-core` package distributed with the project's Zeek
  version; unpack it and point `ZEEKPATH` at the extracted `opt/zeek` tree, as
  `guest-services/exploit-chain/52-sensor-zeek-start.sh` does.

## Reproducing without the original files

- Network evidence can be re-derived from any capture of the same exercise; the
  importers only need Zeek `conn.log`/`dns.log`/`http.log`/`irc.log`.
- The public-dataset evaluation only needs the APT29 JSON and the STIX bundle;
  `scripts/validate_public_apt29.py` reports the same eight candidate alerts on
  the file with the hash above.
- The ATT&CK names in the trace output come from the STIX bundle; without it the
  run still works and leaves the technique name unresolved instead of inventing
  one.
