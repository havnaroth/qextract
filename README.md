<img src="quarantine-extractor.png" width="128" align="left" alt="qextract logo">

### qextract

[![](https://img.shields.io/badge/Category-DFIR%20%2F%20Incident%20Response-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-Python%203.11-E5A505?style=flat-square&logo=python&logoColor=white)]() [![](https://img.shields.io/badge/Build%20script-PowerShell-E5A505?style=flat-square&logo=powershell&logoColor=white)]() [![](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Version-0.1.42-E5A505?style=flat-square&color=green)]() [![](https://img.shields.io/badge/License-All%20rights%20reserved-E5A505?style=flat-square&color=lightgrey)]()

<br clear="left">

qextract pulls antivirus quarantine files and AV logs out of disk images, drives and
folders, decodes the quarantined files and builds one detection timeline. One Windows exe,
nothing to install.

## Installation

Copy `qextract.exe` (Windows 10/11 x64, no Python needed) to a folder only administrators
can write, e.g. `C:\Program Files\qextract`, together with `THIRD-PARTY-NOTICES.md`.

To build it yourself:

```
git clone https://github.com/havnaroth/qextract
cd qextract
powershell -ExecutionPolicy Bypass -File build.ps1      # checks (ruff, bandit), then dist\qextract.exe
```

The location database is not in the repository: an exe built from it knows only the
products you give it (see [Adding a product](#adding-a-product)); the release exe has them all.

## Supported

**Input** (recognised by its content, not by the file extension):
- E01 / Ex01 (EnCase), split segments found automatically
- L01 / Lx01 (EnCase logical evidence)
- VHD / VHDX and Hyper-V checkpoints (AVHDX)
- VMDK (VMware: sparse, flat, split, stream-optimized, snapshots)
- raw dd / img and split raw (.000, .001, ...)
- physical disks: `\\.\PhysicalDriveN`
- drive letters (`C:`, or a mounted image): read as a raw volume when run as administrator,
  so locked and protected files are included
- folders (KAPE output, mounted shares, copied ProgramData)
- ZIP triage collections (Velociraptor, KAPE, CyLR), read in place; `--zip-password` for an
  encrypted one

**The input is only ever read.** Images are opened read-only; mount images read-only too
(qextract warns about a writable one). The output folder may not be inside a scanned
folder or on a mounted image or evidence drive. A live system (its Windows drive) may keep
its own results, e.g. `-i C: -o C:\cases\host01`; that folder is left out of the scan.

**Products:**
- *Sample collected*: the quarantine folder is copied into the zip;
- *Sample decoded*: the quarantined file is restored to the original, with the detection,
  original path and date. The date is when it was last checked on a real quarantine of the
  then current product (vendors change their formats); "untested": synthetic samples only;
- *Logs*: the product's logs (and event logs, where it writes them) are collected.

| Product | Sample collected | Sample decoded | Logs |
|---|:-:|:-:|:-:|
| Avast | ✅ | ✅ 2026-11-01 | ✅ |
| AVG | ✅ | ✅ 2026-11-01 | ✅ |
| Avira | ✅ | ✅ 2026-11-01 | ✅ |
| Bitdefender | ✅ | ✅ 2026-11-02 | ✅ |
| ComboFix | ✅ | | ✅ |
| Comodo | ✅ | | |
| CrowdStrike Falcon | ✅ | | |
| Cybereason | | | ✅ |
| Cylance / Arctic Wolf | ✅ | | ✅ |
| Elastic Defend | ✅ | | ✅ |
| Emsisoft | ✅ | ✅ 2026-11-02 | ✅ |
| ESET | ✅ | ✅ 2026-11-02 | ✅ |
| F-Secure / WithSecure | ✅ | | ✅ |
| Fortect | | | ✅ |
| FortiClient Endpoint Protection | ✅ | ✅ untested | |
| G DATA | ✅ | ✅ untested | |
| HitmanPro | ✅ | | ✅ |
| Kaspersky | ✅ | ✅ 2026-11-02 | ✅ + event log |
| Malwarebytes | ✅ | ✅ 2026-11-02 | ✅ |
| McAfee / Trellix | ✅ | ✅ untested | ✅ |
| Microsoft Defender (also SCEP, Security Essentials) | ✅ | ✅ 2026-11-02 | ✅ + event logs |
| Microsoft Safety Scanner | | | ✅ |
| Norton | ✅ | | ✅ |
| Palo Alto Cortex XDR / Traps | | | ✅ |
| Panda / WatchGuard | ✅ | | ✅ |
| RogueKiller | | | ✅ |
| SecureAge | | | ✅ |
| SentinelOne | ✅ | | ✅ |
| Sophos | ✅ | | ✅ |
| SUPERAntiSpyware | | | ✅ |
| Symantec Endpoint Protection | ✅ | ✅ untested | ✅ + event logs |
| TotalAV | | | ✅ |
| Trend Micro | ✅ | | ✅ |
| VIPRE | ✅ | | ✅ |
| VMware Carbon Black | | | ✅ |
| Webroot | | | ✅ |

Plus the AV-related Windows event logs. `qextract.exe --list-sources` shows everything a build knows.

**Logs in the timeline:** Defender `Operational.evtx`, MPLog and MPDetection logs,
`Application.evtx` (AV products, Security Center), Symantec event logs.

## Usage

```
qextract.exe -i <image, drive or folder> -o <new output folder> [options]
```

```
qextract.exe -i C: -o D:\cases\host01 --only defender      live system (asks to restart as admin)
qextract.exe -i D:\cases\disk.E01 -o D:\cases\host01        disk image
qextract.exe -i D:\cases\disk.E01                           result next to the image
qextract.exe -i F: -o D:\cases\host01                       mounted image
qextract.exe -i C: -o D:\out --event-logs copy --no-elevate in a script, no questions
```

| Option | Meaning |
|---|---|
| `--only ID[,ID]` | only these products (ids from `--list-sources`) |
| `--event-logs ask\|copy\|skip` | also copy the `.evtx` files (asks by default, showing their size) |
| `--mode auto\|raw\|files` | drive letters: raw volume when possible (default), only raw, only files |
| `--include-deleted` | also collect deleted files still listed in the file system |
| `--no-elevate` | do not offer to restart as administrator |
| `--no-update-check` | do not ask GitHub for a newer version (see below) |
| `--force` | allow an output folder that is not empty |
| `--password PASSWORD` | your own password for the archive instead of `infected` |
| `-s DIR` | extra product definitions (JSON) |

**Output:** one zip, `qextract_recovered_<UTC start time>.zip` (e.g.
`qextract_recovered_20261101_093000.zip`). Nothing else is written. For an image or ZIP file
`-o` may be left out: the zip is then `<image name>_qextract_<UTC start time>.zip` next to the
image (a new file; the image files themselves are never touched).

**Update check:** when the machine has internet access, qextract asks GitHub (in the
background, 3 s at most) which version is the newest and, at the end, prints
`NEW VERSION AVAILABLE` with the download link. It never downloads anything. Where any
network traffic matters (e.g. on a suspect machine), use `--no-update-check`.

**The password to the archive is `infected`** (or your own, given with `--password`).

| In the zip | Content |
|---|---|
| `malware\<product>\` | the recovered files as `.infected` and, for Defender, a `.metadata.txt` next to each |
| `info\quarantine.csv` | decoded items: detection, original path, dates, hashes; for Defender also the original file's times, owner and download URL |
| `info\detections.csv` | one timeline from all AV logs, times in UTC |
| `info\mplog_processes.csv` | Defender per-process scan lines (evidence of execution) |
| `info\collected_files.csv`, `info\files\` | every collected file with its hash, and the copies |
| `info\summary.json`, `info\qextract.log` | what was searched, found and skipped |

The evidence and the machine are both treated as hostile (crafted files, planted links
while running as administrator).

## Adding a product

A product is one JSON file. Put it in a folder and pass the folder with `-s`, or put it in a
`sources` folder next to `qextract.exe`.

```json
{
  "id": "exampleav",
  "name": "Example Antivirus",
  "artifacts": [
    {"name": "Quarantine", "kind": "quarantine", "paths": ["ProgramData/ExampleAV/Quarantine/**"]},
    {"name": "Logs", "kind": "log", "paths": ["ProgramData/ExampleAV/Logs/*.log",
                                             "Users/*/AppData/Roaming/ExampleAV/*.txt"]}
  ]
}
```

- `paths`: relative to the root of each volume, `/` or `\`; `*` matches within one folder,
  `**` any depth. Names are matched without regard to case.
- `kind`: `quarantine`, `log`, `eventlog` or anything else (only a label in the report).
- `decoder` / `parser` (optional): one of the built-in ones (`qextract.exe --list-sources`
  shows which product uses which), e.g. `"decoder": "defender"`.
- A definition with the `id` of a built-in product replaces it.

Run as administrator, qextract does not read the `sources` folder next to the exe (anyone who
can write there could make it copy files of their choice); pass such a folder with `-s` if
you trust it.

## License

All rights reserved by the author. Bundled components: [THIRD-PARTY-NOTICES.md](THIRD-PARTY-NOTICES.md).

## About the icon

The icon borrows the style of the Semiotic Standard, the pictogram system made for the
spaceship signage of Ridley Scott's *Alien* (1979). In that spirit, the red frame is a
container that warns of danger, and the black sample inside it stands for death - malicious
samples inside quarantine.
