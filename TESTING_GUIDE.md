# Integrity Monitor Final - Testing Guide

This guide explains how to test the main workflows of Integrity Monitor Final step by step.

---

## Test Environment Setup

Create a test folder structure similar to this:

```text
test_data/
├── docs/
│   ├── a.txt
│   ├── b.txt
│   └── c.md
├── duplicates/
│   ├── file1.txt
│   ├── file1_copy.txt
│   └── file1_copy2.txt
├── temp/
│   ├── debug.log
│   └── cache.tmp
└── media/
    ├── image.jpg
    └── report.pdf
```

Also make sure at least two files in `duplicates/` have identical content.

---

## 1. Basic Manual Scan Test

### Goal
Confirm recursive hashing works.

### Steps
1. Start the program:
   ```bash
   python integrity_monitor_final.py
   ```

2. Select:
   ```text
   2. Run new scan
   ```

3. Enter your test folder path.

4. Choose:
   ```text
   balanced
   ```

5. Leave extension filter blank.

6. Leave excluded folders blank.

7. Leave include patterns blank.

8. Leave exclude patterns blank.

9. Enable incremental cache.

### Expected result
- Files are found and hashed
- Dashboard appears
- Results display cleanly
- File count matches expected test files

---

## 2. Incremental Cache Test

### Goal
Confirm rescans reuse cache entries.

### Steps
1. Run the same scan again immediately.
2. Compare cache hit count from first vs second run.

### Expected result
- Second run shows more cache hits
- Fewer files are freshly hashed

---

## 3. Extension Filter Test

### Goal
Confirm extension filtering works.

### Steps
1. Run scan again.
2. Set extension filter to:
   ```text
   .txt,.md
   ```

### Expected result
- Only `.txt` and `.md` files appear
- `.jpg`, `.pdf`, `.log`, `.tmp` do not appear

---

## 4. Excluded Folder Test

### Goal
Confirm excluded folders are skipped.

### Steps
1. Run scan again.
2. Set excluded folder to the `temp` folder path.

### Expected result
- Files from `temp/` are not scanned
- Other folders still appear

---

## 5. Include Pattern Test

### Goal
Confirm include file-name patterns work.

### Steps
1. Run scan again.
2. Leave extensions blank.
3. Set include patterns:
   ```text
   *.txt
   ```

### Expected result
- Only `.txt` files appear

---

## 6. Exclude Pattern Test

### Goal
Confirm exclude file-name patterns work.

### Steps
1. Run scan again.
2. Leave extensions blank.
3. Set exclude patterns:
   ```text
   *.log,*.tmp
   ```

### Expected result
- `.log` and `.tmp` files are omitted

---

## 7. Search and Sort Test

### Goal
Confirm result navigation works.

### Steps
1. Run a scan.
2. Search for:
   ```text
   file1
   ```
3. Sort results by:
   - name
   - size
   - path

### Expected result
- Search narrows results
- Sorting changes order
- Reset view restores full list

---

## 8. Export Test

### Goal
Confirm scan exports work.

### Steps
1. Run a scan.
2. Export displayed results.

### Expected result
Files are created in `hash_exports/`:
- `.json`
- `.csv`
- `.txt`

Open them and confirm contents look correct.

---

## 9. Baseline Workflow Test

### Goal
Confirm baseline creation and drift comparison work.

### Steps
1. Run scan on test folder.
2. Save current scan as baseline.
3. Modify one file.
4. Add one file.
5. Delete one file.
6. Run scan again.
7. Compare last scan to baseline.

### Expected result
Comparison correctly shows:
- 1 added
- 1 removed
- 1 changed

---

## 10. Manifest Workflow Test

### Goal
Confirm manifest save and verification work.

### Steps
1. Run a scan.
2. Save current scan as manifest.
3. Change a file.
4. Run scan again.
5. Verify last scan against manifest.

### Expected result
Verification shows:
- verified files
- mismatched files
- missing files
- unexpected files

---

## 11. Single File Verification Test

### Goal
Confirm single-file verification works.

### Steps
1. Save a manifest.
2. Choose single-file verification.
3. Select one file from the manifest.
4. Verify once unchanged.
5. Modify it and verify again.

### Expected result
- First verification passes
- Second verification fails

---

## 12. Duplicate Triage Test

### Goal
Confirm duplicate grouping works.

### Steps
1. Ensure duplicate files exist.
2. Run scan.
3. Open duplicate review.

### Expected result
- Duplicate groups appear
- File counts are correct
- Wasted size is shown
- Bookmarking duplicates works

---

## 13. Profile Creation Test

### Goal
Confirm reusable profiles work.

### Steps
1. Go to profiles menu.
2. Add profile with:
   - path
   - algorithm preset
   - extension filter
   - excluded folders
   - include/exclude patterns
   - tags

3. Save profile.
4. Run profile.

### Expected result
- Profile is stored
- Running the profile works
- Results match stored settings

---

## 14. Profile Clone Test

### Goal
Confirm profile cloning works.

### Steps
1. Clone an existing profile.
2. Edit cloned profile.
3. Change path or filters.
4. Run cloned profile.

### Expected result
- Clone exists separately
- Changes only affect cloned profile

---

## 15. Filter Profiles by Tag Test

### Goal
Confirm tag filtering works.

### Steps
1. Create multiple tagged profiles.
2. Use filter-by-tag feature.

### Expected result
- Only matching tagged profiles are shown

---

## 16. Watch Mode Test

### Goal
Confirm watch mode works.

### Steps
1. Create or use a profile.
2. Start watch mode.
3. Use short interval, e.g. 15 seconds.
4. During watch mode:
   - add a file
   - change a file
   - remove a file

5. Stop with `Ctrl+C`.

### Expected result
- Cycle output appears
- Changes are detected
- Watch mode stops cleanly

---

## 17. Watch History Test

### Goal
Confirm watch logs are saved and viewable.

### Steps
1. Run watch mode with watch logging enabled.
2. Stop watch mode.
3. Open watch history for that profile.

### Expected result
- History records exist
- Cycle stats appear correctly

---

## 18. Report Generation Test

### Goal
Confirm reports export correctly.

### Steps
1. Run baseline comparison or watch mode with drift.
2. Export report.
3. Preview report from reports menu.

### Expected result
- JSON report exists
- Metadata and findings are correct
- Preview works

---

## 19. UI Settings Persistence Test

### Goal
Confirm settings persist after restart.

### Steps
1. Change:
   - page size
   - default algorithm
   - screen clear setting
   - pause after views

2. Exit program.
3. Restart program.

### Expected result
- Settings are preserved

---

## 20. Maintenance Test

### Goal
Confirm maintenance tools work.

### Steps
1. Open maintenance menu.
2. List exports
3. List cache
4. Back up profile file
5. Preview app log

### Expected result
- Files are listed properly
- Backup file is created
- Log preview works if log exists

---

## Suggested Full Test Order

For a full validation pass, test in this order:

1. Manual scan
2. Incremental cache
3. Extension filter
4. Excluded folders
5. Include patterns
6. Exclude patterns
7. Search and sort
8. Export
9. Baseline workflow
10. Manifest workflow
11. Single-file verification
12. Duplicate review
13. Profile create/run
14. Profile clone
15. Filter by tag
16. Watch mode
17. Watch history
18. Report export and preview
19. UI settings persistence
20. Maintenance menu

---

## Pass Criteria

The application can be considered working correctly if:

- scans complete without crashing
- results match folder contents
- cache speeds up repeat scans
- filters work as intended
- comparisons detect changes accurately
- manifests verify correctly
- duplicates are detected correctly
- profiles save and reload properly
- watch mode logs correctly
- reports export correctly
- settings persist across restarts
