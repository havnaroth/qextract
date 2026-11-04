<img src="quarantine-extractor.png" width="128" align="left" alt="qextract logo">

### qextract

[![](https://img.shields.io/badge/Category-DFIR%20%2F%20Incident%20Response-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Language-Python%203.11-E5A505?style=flat-square&logo=python&logoColor=white)]() [![](https://img.shields.io/badge/Build%20script-PowerShell-E5A505?style=flat-square&logo=powershell&logoColor=white)]() [![](https://img.shields.io/badge/Platform-Windows%2010%20%7C%2011-E5A505?style=flat-square)]() [![](https://img.shields.io/badge/Version-0.3.2-E5A505?style=flat-square&color=green)]() [![](https://img.shields.io/badge/License-All%20rights%20reserved-E5A505?style=flat-square&color=lightgrey)]()

<br clear="left">

## Description

qextract pulls antivirus quarantine files and AV logs out of disk images, drives and
folders, decodes the quarantined files and builds one detection timeline. One Windows exe,
nothing to install.

It also scans the NTFS `$MFT` and `$UsnJrnl:$J` for every file a product detected or put in
quarantine. It looks for other locations of the same file:
- the record of a deleted file, until the record is reused;
- copies of the file's entry kept in the folder index;
- the moves and renames the file went through on the drive, as far back as the journal reaches.

It also looks for where the file came from: the download URL, the page that linked to it and
the security zone, read from the `Zone.Identifier` alternate data stream ("Mark of the Web").
That stream is kept with the quarantined file or in the file's `$MFT` record, even after the
file was deleted. Each incident then shows when the file arrived on the disk, how long it sat
there before the first detection, and where it came from (see "File history" under [Usage](#usage)).

## Installation

Copy `qextract.exe` (Windows 10/11 x64, no Python needed) to a folder only administrators
can write, e.g. `C:\Program Files\qextract`, together with `THIRD-PARTY-NOTICES.md`.

To build it yourself:

```
git clone https://github.com/havnaroth/qextract
cd qextract
powershell -ExecutionPolicy Bypass -File build.ps1      # builds dist\qextract.exe
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
Any other drive or folder takes its own results only with `--force` (e.g. `-i D: -o D:\cases\host01`,
qextract run from that drive): the output folder is left out of the scan, `summary.json` records
`output_on_input`, but writing changes the input - not for evidence that must stay untouched.

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
| F-Secure (consumer) | ✅ | | ✅ |
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
| RogueKiller / Adlice Protect (incl. portable) | ✅ | ✅ 2026-11-03 | ✅ + scan reports |
| SecureAge | | | ✅ |
| SentinelOne | ✅ | | ✅ |
| Sophos | ✅ | | ✅ |
| SUPERAntiSpyware | ✅ | ✅ 2026-11-02 | ✅ |
| Symantec Endpoint Protection | ✅ | ✅ untested | ✅ + event logs |
| TotalAV | | | ✅ |
| Trend Micro | ✅ | | ✅ |
| VIPRE | ✅ | | ✅ |
| VMware Carbon Black | | | ✅ |
| Webroot | | | ✅ |
| WithSecure Elements EPP (business, ex F-Secure Business) | ✅ | ✅ 2026-11-02 | ✅ + event log |

Plus the AV-related Windows event logs. `qextract.exe --list-sources` shows everything a build knows.

**Logs in the timeline:** Defender `Operational.evtx`, MPLog and MPDetection logs,
`Application.evtx` (AV products, Security Center), Symantec event logs, WithSecure EDR store
(`ATP\pstor\state.db`) and `FSecureUltralightSDK.evtx`: detections, including scripts blocked by AMSI.
RogueKiller scan and removal reports: every scan, and detections the user left in place.
Avast / AVG: `Log.db` (detections, scan sessions), the shield reports in `report\*.txt` (local
time, converted to UTC with the time zone from the registry) and the notifications shown to the
user (`NCcache.dat`, with whether the user opened them).
SUPERAntiSpyware: the scan logs and the application logs (`AppLogs\*.SDB`, decoded): scans,
detections with the rule number, and every quarantined file with its MD5.
Emsisoft: `logs.db3` (scans, detections with SHA1, quarantine, settings changes, protection
problems) and the scan reports in `Reports\scan_*.txt`, which are the only record of files
quarantined at the end of a scan.
Kaspersky: `Data\reports.db` with its `-wal` file (most of the data is only there): every
detection with the process that touched the file, MD5, quarantine and deletion; protection
components started and stopped; sign-ins to the My Kaspersky portal.

The portable RogueKiller keeps its data in a `RogueKiller` folder next to the exe. qextract looks
for it at the drive root, one folder deep (e.g. `C:\Tools`), under the users' Desktop, Downloads,
Documents and Temp, and in ProgramData. For another place, pass a definition with that path
(see Adding a product, `"decoder": "roguekiller"`).

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
qextract.exe -i D: -o D:\cases\host01 --force               results on the scanned drive
```

| Option | Meaning |
|---|---|
| `--only ID[,ID]` | only these products (ids from `--list-sources`) |
| `--event-logs ask\|copy\|skip` | also copy the `.evtx` files (asks by default, showing their size) |
| `--mode auto\|raw\|files` | drive letters: raw volume when possible (default), only raw, only files |
| `--include-deleted` | also collect deleted files still listed in the file system |
| `--no-elevate` | do not offer to restart as administrator |
| `--no-update-check` | do not ask GitHub for a newer version (see below) |
| `--no-file-history` | skip the `$MFT` / `$UsnJrnl` history of the detected files (see `mft\` below) |
| `--force` | override the safety checks that are your call: an output folder that is not empty, and the output on the scanned drive or inside the scanned folder (left out of the scan; changes the input, recorded as `output_on_input`). The protection against crafted evidence stays on |
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
| `info\summary.txt` | **start here**: the host (computer, Windows, time zone), what each product left, the incidents, recovered files, warnings |
| `info\incidents.csv` | one row per threat on one file (or AMSI scan, registry key): every log's events and the quarantine item joined, first / last seen, each action with its time (`action_times`), recovered file, and the user context: the account the detection happened for (`user_context`, a person before SYSTEM), the profile the file was in, the owner of the quarantined file (SID resolved through the registry) and the process that touched it |
| `malware\<product>\` | the recovered files as `.infected` and, for Defender, a `.metadata.txt` next to each |
| `info\quarantine.csv` | decoded items: detection, original path, dates, hashes; for Defender also the original file's times, owner and download URL |
| `info\detections.csv` | one timeline from all AV logs, times in UTC; `category` (detection, response, tamper, config, scan, health, telemetry) separates detections from noise |
| `info\mplog_processes.csv` | Defender per-process scan lines (evidence of execution) |
| `info\collected_files.csv`, `info\files\` | every collected file with its hash, and the copies |
| `info\decoded\` | readable forms of obfuscated logs and settings (e.g. RogueKiller `config.ini.json`) |
| `info\summary.json`, `info\qextract.log` | the summary for programs (`schema_version`), and the run |
| `mft\file_records.csv`, `mft\usn_events.csv` | the NTFS history of the files the products named: their `$MFT` records (also deleted ones) with both time sets and the download origin (`Zone.Identifier`), and their `$UsnJrnl:$J` events |
| `mft\file_moves.csv` | each file's way on the volume from the journal: created, moved / renamed (from, to), deleted |

The CSVs keep their columns; normalized ones are appended for every product alike (report schema 2):
`action_norm` (quarantined, deleted, blocked, cleaned, allowed, restored, failed, detected, none -
language independent), `path_norm` (`\Device\HarddiskVolumeN`, `%SystemDrive%`, `\\?\` and `amsi:_` resolved)
with `path_type`, `log`, `sha256` / `md5` / `threat_family` / `severity` from the details, `details_json` and
`incident`; quarantine.csv adds `quarantined_utc` (local times converted with the host's time zone rules
from the registry), `recovery`, `verified_by` and `warning`.

**File history:** not every host has real-time protection and not every sample is detected on
arrival. For every file a product named, qextract reads the whole `$MFT` once (also records of
deleted files, until they are reused) and the `$UsnJrnl:$J`. The incident then shows
`on_disk_since` (when the file arrived there: `$FILE_NAME` created or the journal's file create;
modified times are the age of the content - an unpacked or copied file keeps them - and are not
used), the evidence for it and the `dwell` time before the first detection of that path;
`summary.txt` lists the files that were on the disk a minute or more before their detection.
`$STANDARD_INFORMATION` is easy to change (timestomping, but also restore and unpack tools),
`$FILE_NAME` is set by the system: both are reported.
The incident also shows where a downloaded file came from (`origin`: download URL, the page that
linked to it, the zone - from the `Zone.Identifier` stream kept with the quarantined file or in the
file's `$MFT` record, also of a deleted file) and the way it took on the drive (`journey`, e.g.
created in Temp, moved to Downloads, moved to `C:\`), as far back as the journal reaches; a copy or
a move from another drive starts a new file and is not followed. It needs an NTFS image, a raw drive
(administrator) or a collection that holds `$MFT` / `$J`; it takes seconds on a workstation
(2 million records about 10 s) and is turned off with `--no-file-history`. The journal is small:
on a busy machine it covers hours or days.

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
- `markers` (optional): files only this product has, e.g.
  `"markers": ["Program Files*/F-Secure/PSB/SecurityProductInformation.ini"]`. A file belongs to
  one product only: when several products match it (they share folders), it goes to the one
  whose markers are on that disk, then to the one with the more specific path; otherwise to the
  first, with a warning.
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
