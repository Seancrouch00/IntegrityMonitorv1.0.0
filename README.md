# Integrity Monitor Final

Integrity Monitor Final is a terminal-based file integrity and monitoring tool for recursive hashing, manifests, baselines, drift detection, duplicate triage, saved profiles, watch mode, and report generation.

It is designed to work well as a practical TUI application for repeated integrity checking and monitoring workflows without requiring a GUI.

---

## Features

- Recursive file hashing
- Multiple hash algorithms
- Algorithm presets
- Saved UI settings
- Saved profiles/jobs
- Baselines
- Manifests
- Baseline drift comparison
- Manifest verification
- Single-file verification
- Duplicate detection
- Duplicate triage
- Search and sort of results
- Extension filtering
- Include file patterns
- Exclude file patterns
- Excluded folders
- Incremental cache for faster rescans
- Watch mode
- Watch history logs
- Report generation
- Bookmark export
- Maintenance tools
- App log preview

---

## Supported Algorithms

Direct algorithms:

- `md5`
- `sha1`
- `sha256`
- `sha512`
- `blake2b`
- `blake2s`

Algorithm presets:

- `fast` → `md5`
- `balanced` → `sha256`
- `strong` → `sha512`
- `blake_fast` → `blake2s`
- `blake_strong` → `blake2b`

---

## Main Purpose

Integrity Monitor is intended to help you:

- record the state of a folder
- detect when files change
- compare current state with older saved states
- build trusted baselines
- verify manifests
- review duplicates
- repeatedly monitor important folders through reusable profiles

---

## Requirements

- Python 3.8 or newer
- `rich`

Install dependency:

```bash
pip install rich
```

---

## Running the Program

```bash
python integrity_monitor_final.py
```

---

## Directory Structure Created by the Program

The application creates and uses the following directories and files:

```text
hash_exports/
hash_cache/
watch_logs/
baselines/
bookmarks/
reports/
manifests/
scan_profiles.json
ui_settings.json
integrity_monitor.log
```

### Purpose of each

#### `hash_exports/`
Stores exported scan results in JSON, CSV, and TXT format.

#### `hash_cache/`
Stores incremental scan cache files to speed up rescans.

#### `watch_logs/`
Stores JSONL watch history logs for watched profiles.

#### `baselines/`
Stores saved trusted baseline files.

#### `bookmarks/`
Stores saved bookmark files for flagged results.

#### `reports/`
Stores generated comparison and drift reports.

#### `manifests/`
Stores saved manifest files.

#### `scan_profiles.json`
Stores saved profiles/jobs.

#### `ui_settings.json`
Stores saved interface settings.

#### `integrity_monitor.log`
Stores internal application logging.

---

## Core Workflows

### 1. Manual Scan
Run a scan directly against a chosen folder with optional filters and pattern rules.

### 2. Baseline Workflow
Create a trusted baseline from a scan and compare later scans against it to detect drift.

### 3. Manifest Workflow
Save a manifest from a scan and verify later scans or single files against it.

### 4. Profile Workflow
Save reusable scan jobs with filters, presets, tags, exclusions, and thresholds.

### 5. Watch Workflow
Continuously re-run a profile on a timer and monitor changes over time.

### 6. Duplicate Review Workflow
Detect matching hashes, estimate wasted size, and bookmark duplicate groups for review.

---

## Main Menu Overview

### Quick Actions
Common shortcuts for:
- running scans
- exporting last scan
- saving baseline
- saving manifest
- reviewing duplicates
- showing dashboard

### Run New Scan
Performs a manual recursive scan with:
- folder path
- algorithm/preset
- extension filter
- excluded folders
- include file patterns
- exclude file patterns
- incremental cache option

### Results Tools
Includes:
- show displayed results
- paged results
- search
- sort
- reset filtered view
- show largest files

### Integrity Tools
Includes:
- compare against previous JSON scan
- compare against baseline
- verify against manifest
- verify single file against manifest

### Review Tools
Includes:
- duplicate review
- extension summary
- folder summary
- errors
- session dashboard

### Profile Management
Includes:
- add profile
- edit profile
- clone profile
- delete profile
- run profile
- watch profile
- filter profiles by tag
- view watch history

### Maintenance
Includes:
- list export files
- list cache files
- clear cache
- list reports
- list bookmarks
- back up profile file
- preview app log

---

## Profiles

Profiles allow repeated use without re-entering settings every time.

A profile can store:

- path
- algorithm/preset
- extensions
- excluded folders
- include file patterns
- exclude file patterns
- tags
- incremental cache setting
- auto export setting
- watch logging setting
- report mode
- baseline path
- thresholds
- last run metadata

### Good profile examples

- `documents_main`
- `photos_archive`
- `project_source`
- `backup_validation`
- `evidence_store`

### Suggested tags

- `work`
- `media`
- `archive`
- `backup`
- `source`
- `evidence`

---

## Baselines

A baseline represents a trusted folder state.

Use baselines when you want to detect:

- added files
- removed files
- changed files
- unchanged files

Best used for:
- important folders
- release folders
- archives
- evidence sets
- long-term monitoring

---

## Manifests

A manifest is a saved record of file hashes and metadata for later verification.

Use manifests when you want to:

- verify a folder later
- verify one file later
- confirm integrity against a known saved result

---

## Watch Mode

Watch mode reruns a saved profile repeatedly.

It can compare:

- current cycle vs previous cycle
- current cycle vs baseline

Watch mode supports:

- verbose mode
- quiet mode
- per-cycle export
- report-on-change-only behavior
- watch history log creation

Stop watch mode with:

```text
Ctrl+C
```

---

## Reports

Reports are saved JSON files describing drift or comparison results.

A report can include:

- report metadata
- added files
- removed files
- changed files
- unchanged sample

Report modes:

- `full`
- `changed_only`

---

## Bookmarks

Bookmarks allow you to save interesting findings for later review.

You can bookmark:

- drift findings
- changed files
- duplicates
- top duplicate groups

---

## Duplicate Triage

Duplicate triage groups files by identical hash and shows:

- duplicate count
- total duplicate group size
- estimated wasted size

This helps prioritize duplicate cleanup or review.

---

## UI Settings

Saved UI settings include:

- clear screen on menu/view open
- pause after views
- page size
- default algorithm
- default result display limit

---

## Example Usage

### Run a scan
```bash
python integrity_monitor_final.py
```

Then choose:

```text
2. Run new scan
```

### Save a baseline
1. Run scan
2. Go to baselines menu
3. Save current scan as baseline

### Compare to a baseline
1. Run scan again later
2. Choose compare last scan to baseline
3. Enter baseline path

### Save and use a profile
1. Go to profiles menu
2. Add profile
3. Run profile
4. Optionally watch profile

---

## Safety Notes

Integrity Monitor is meant for integrity checking, review, and monitoring.

It does not automatically delete or modify scanned files during its main workflows.

That is intentional, to reduce accidental destructive behavior.

---

## Limitations

- File identity is path-based
- Renamed files appear as remove + add
- Watch mode is interactive, not a system service
- No built-in scheduler
- No cryptographic signing of manifests or baselines
- No database backend; storage is file-based

---

## Recommended Project Files

For a complete release, keep these alongside the program:

- `README.md`
- `TESTING_GUIDE.md`
- `CHANGELOG.md`
- `requirements.txt`

Example `requirements.txt`:

```text
rich
```

---

## Version

This project file is intended for:

**Integrity Monitor Final**
