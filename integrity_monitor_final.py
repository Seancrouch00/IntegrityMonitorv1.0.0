#!/usr/bin/env python3
"""
Integrity Monitor - Final TUI Version
Single-file terminal application for:
- recursive hashing
- manifests
- baselines
- drift detection
- duplicate triage
- saved scan jobs / profiles
- watch mode
- reports
- UI settings
"""

from __future__ import annotations

import csv
import fnmatch
import hashlib
import json
import os
import shutil
import sys
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich.prompt import Confirm, IntPrompt, Prompt
from rich.table import Table

# =========================
# Constants / Globals
# =========================

APP_TITLE = "Integrity Monitor"
APP_VERSION = "Final"
APP_TAGLINE = "Terminal-based file integrity, baseline, manifest, drift, and duplicate monitoring tool"

console = Console()

SUPPORTED_ALGOS = {
    "md5": hashlib.md5,
    "sha1": hashlib.sha1,
    "sha256": hashlib.sha256,
    "sha512": hashlib.sha512,
    "blake2b": hashlib.blake2b,
    "blake2s": hashlib.blake2s,
}

ALGO_PRESETS = {
    "fast": "md5",
    "balanced": "sha256",
    "strong": "sha512",
    "blake_fast": "blake2s",
    "blake_strong": "blake2b",
}

BASE_DIR = Path.cwd()
EXPORT_DIR = BASE_DIR / "hash_exports"
CACHE_DIR = BASE_DIR / "hash_cache"
PROFILE_FILE = BASE_DIR / "scan_profiles.json"
WATCH_LOG_DIR = BASE_DIR / "watch_logs"
BASELINE_DIR = BASE_DIR / "baselines"
BOOKMARK_DIR = BASE_DIR / "bookmarks"
REPORT_DIR = BASE_DIR / "reports"
MANIFEST_DIR = BASE_DIR / "manifests"
UI_SETTINGS_FILE = BASE_DIR / "ui_settings.json"
APP_LOG_FILE = BASE_DIR / "integrity_monitor.log"

DEFAULT_UI_SETTINGS = {
    "page_size": 50,
    "clear_screen": True,
    "pause_after_views": True,
    "default_algorithm": "sha256",
    "result_limit": 200,
}

for d in [EXPORT_DIR, CACHE_DIR, WATCH_LOG_DIR, BASELINE_DIR, BOOKMARK_DIR, REPORT_DIR, MANIFEST_DIR]:
    d.mkdir(exist_ok=True, parents=True)

last_scan_results: List[Dict[str, Any]] = []
last_scan_metadata: Dict[str, Any] = {}
last_duplicates: Dict[str, List[Dict[str, Any]]] = {}
last_errors: List[Tuple[str, str]] = []
last_filtered_results: List[Dict[str, Any]] = []
last_baseline_comparison: Optional[Dict[str, Any]] = None
last_manifest_comparison: Optional[Dict[str, Any]] = None
last_diff_result: Optional[Dict[str, Any]] = None


# =========================
# Utility / safety helpers
# =========================

def log_app(message: str) -> None:
    stamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    try:
        with open(APP_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(f"[{stamp}] {message}\n")
    except Exception:
        pass


def safe_read_json(path: Path, default: Any) -> Any:
    try:
        if not path.exists():
            return default
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        log_app(f"safe_read_json failed for {path}: {e}")
        return default


def safe_write_json(path: Path, data: Any) -> bool:
    try:
        tmp_path = path.with_suffix(path.suffix + ".tmp")
        with open(tmp_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=4)
        tmp_path.replace(path)
        return True
    except Exception as e:
        log_app(f"safe_write_json failed for {path}: {e}")
        return False


def sanitize_name(value: str) -> str:
    safe = "".join(c if c.isalnum() or c in ("-", "_") else "_" for c in value)
    return safe[:180] or "unnamed"


def now_str() -> str:
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def pretty_dt() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")
def human_size(size_bytes: int) -> str:
    units = ["B", "KB", "MB", "GB", "TB"]
    size = float(size_bytes)
    for unit in units:
        if size < 1024 or unit == units[-1]:
            return f"{size:.2f} {unit}"
        size /= 1024
    return f"{size_bytes} B"


def parse_csv_list(text: str) -> List[str]:
    if not text.strip():
        return []
    return [item.strip() for item in text.split(",") if item.strip()]


def parse_extensions(ext_input: str) -> set[str]:
    if not ext_input.strip():
        return set()

    exts = set()
    for ext in ext_input.split(","):
        ext = ext.strip().lower()
        if not ext:
            continue
        if not ext.startswith("."):
            ext = "." + ext
        exts.add(ext)
    return exts


def resolve_algorithm(value: str) -> str:
    value = value.strip().lower()
    if value in SUPPORTED_ALGOS:
        return value
    if value in ALGO_PRESETS:
        return ALGO_PRESETS[value]
    return UI_SETTINGS.get("default_algorithm", "sha256")


def should_clear() -> bool:
    return bool(UI_SETTINGS.get("clear_screen", True))


def should_pause() -> bool:
    return bool(UI_SETTINGS.get("pause_after_views", True))


def clear_screen() -> None:
    if should_clear():
        os.system("cls" if os.name == "nt" else "clear")


def wait_for_enter(message: str = "Press Enter to continue") -> None:
    if should_pause():
        input(f"\n{message}...")


def show_header(title: Optional[str] = None) -> None:
    clear_screen()
    header_title = title or APP_TITLE
    console.print(Panel.fit(f"[bold green]{header_title}[/bold green]", border_style="green"))


def path_is_excluded(path_obj: Path, excluded_dirs: Optional[List[str]]) -> bool:
    if not excluded_dirs:
        return False
    path_str = str(path_obj.resolve())
    for excluded in excluded_dirs:
        try:
            ex = str(Path(excluded).expanduser().resolve())
            if path_str == ex or path_str.startswith(ex + os.sep):
                return True
        except Exception:
            continue
    return False


def filename_matches_patterns(path_obj: Path, include_patterns=None, exclude_patterns=None) -> bool:
    name = path_obj.name
    if include_patterns:
        if not any(fnmatch.fnmatch(name, pat) for pat in include_patterns):
            return False
    if exclude_patterns:
        if any(fnmatch.fnmatch(name, pat) for pat in exclude_patterns):
            return False
    return True


# =========================
# UI settings
# =========================

def load_ui_settings() -> Dict[str, Any]:
    if not UI_SETTINGS_FILE.exists():
        safe_write_json(UI_SETTINGS_FILE, DEFAULT_UI_SETTINGS)
        return dict(DEFAULT_UI_SETTINGS)

    data = safe_read_json(UI_SETTINGS_FILE, dict(DEFAULT_UI_SETTINGS))
    merged = dict(DEFAULT_UI_SETTINGS)
    if isinstance(data, dict):
        merged.update(data)
    return merged


def save_ui_settings(settings: Dict[str, Any]) -> None:
    safe_write_json(UI_SETTINGS_FILE, settings)


UI_SETTINGS = load_ui_settings()


# =========================
# Core scan logic
# =========================

def get_cache_path(root_path: Path, algo_name: str) -> Path:
    raw = f"{str(root_path.resolve())}_{algo_name}"
    digest = hashlib.sha256(raw.encode("utf-8")).hexdigest()
    return CACHE_DIR / f"cache_{digest}.json"


def load_cache(cache_path: Path) -> Dict[str, Any]:
    data = safe_read_json(cache_path, {})
    return data if isinstance(data, dict) else {}


def save_cache(cache_path: Path, cache_data: Dict[str, Any]) -> None:
    safe_write_json(cache_path, cache_data)


def build_cache_entry(size: int, mtime: float, digest: str) -> Dict[str, Any]:
    return {"size": size, "mtime": mtime, "hash": digest}


def hash_file(file_path: Path, algo_name: str, chunk_size: int = 65536) -> str:
    hasher = SUPPORTED_ALGOS[algo_name]()
    with open(file_path, "rb") as f:
        while True:
            chunk = f.read(chunk_size)
            if not chunk:
                break
            hasher.update(chunk)
    return hasher.hexdigest()
def collect_files(
    root: Path,
    extensions=None,
    excluded_dirs=None,
    include_patterns=None,
    exclude_patterns=None,
) -> Tuple[List[Path], List[Tuple[str, str]]]:
    file_list: List[Path] = []
    errors: List[Tuple[str, str]] = []

    for current_root, dirs, files in os.walk(root):
        current_root_path = Path(current_root)

        if path_is_excluded(current_root_path, excluded_dirs):
            dirs[:] = []
            continue

        dirs[:] = [d for d in dirs if not path_is_excluded(current_root_path / d, excluded_dirs)]

        for name in files:
            full_path = current_root_path / name
            try:
                if not full_path.is_file():
                    continue
                if extensions and full_path.suffix.lower() not in extensions:
                    continue
                if path_is_excluded(full_path, excluded_dirs):
                    continue
                if not filename_matches_patterns(full_path, include_patterns, exclude_patterns):
                    continue
                file_list.append(full_path)
            except Exception as e:
                errors.append((str(full_path), str(e)))

    return file_list, errors


def run_scan_config(
    root_path: Path,
    algo_name: str,
    extensions=None,
    use_incremental=True,
    show_output=True,
    excluded_dirs=None,
    include_patterns=None,
    exclude_patterns=None,
) -> Optional[Dict[str, Any]]:
    global last_scan_results, last_scan_metadata, last_duplicates, last_errors, last_filtered_results

    files, collection_errors = collect_files(
        root_path,
        extensions=extensions,
        excluded_dirs=excluded_dirs,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )

    if not files:
        if show_output:
            console.print("[yellow]No matching files found.[/yellow]")
            display_errors(collection_errors)
        return None

    start_time = time.time()
    cache_hits = 0
    fresh_hashed = 0
    results: List[Dict[str, Any]] = []
    hash_errors: List[Tuple[str, str]] = []

    cache_path = get_cache_path(root_path, algo_name)
    cache_data = load_cache(cache_path) if use_incremental else {}
    new_cache = {}

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
        transient=not show_output,
    ) as progress:
        task = progress.add_task("Hashing files...", total=len(files))

        for file_path in files:
            try:
                stat = file_path.stat()
                size = stat.st_size
                mtime = stat.st_mtime
                key = str(file_path)

                cached = cache_data.get(key)
                if (
                    use_incremental
                    and cached
                    and cached.get("size") == size
                    and cached.get("mtime") == mtime
                    and cached.get("hash")
                ):
                    digest = cached["hash"]
                    cache_hits += 1
                else:
                    digest = hash_file(file_path, algo_name)
                    fresh_hashed += 1

                item = {"path": key, "size": size, "mtime": mtime, "hash": digest}
                results.append(item)
                new_cache[key] = build_cache_entry(size, mtime, digest)

            except Exception as e:
                hash_errors.append((str(file_path), str(e)))

            progress.advance(task)

    if use_incremental:
        save_cache(cache_path, new_cache)

    results = sort_results(results, "path", False)
    duplicates = find_duplicates(results)
    all_errors = collection_errors + hash_errors
    total_size = sum(item["size"] for item in results)
    elapsed = time.time() - start_time
    metadata = {
        "scanned_path": str(root_path),
        "algorithm": algo_name,
        "timestamp": now_str(),
        "file_count": len(results),
        "total_size_bytes": total_size,
        "extensions": sorted(list(extensions)) if extensions else [],
        "incremental_cache": use_incremental,
        "cache_file": str(cache_path),
        "cache_hits": cache_hits,
        "fresh_hashed": fresh_hashed,
        "elapsed_seconds": elapsed,
        "excluded_dirs": excluded_dirs or [],
        "include_patterns": include_patterns or [],
        "exclude_patterns": exclude_patterns or [],
    }

    last_scan_results = results
    last_filtered_results = list(results)
    last_scan_metadata = metadata
    last_duplicates = duplicates
    last_errors = all_errors

    if show_output:
        show_header("Scan Results")
        print_dashboard()
        console.print()
        display_results(results, title=f"Scan Results - {algo_name.upper()}")

    return {
        "results": results,
        "metadata": metadata,
        "duplicates": duplicates,
        "errors": all_errors,
    }


# =========================
# Compare / verify / export
# =========================

def find_duplicates(results: List[Dict[str, Any]]) -> Dict[str, List[Dict[str, Any]]]:
    hash_map: Dict[str, List[Dict[str, Any]]] = {}
    for item in results:
        hash_map.setdefault(item["hash"], []).append(item)
    return {h: items for h, items in hash_map.items() if len(items) > 1}


def duplicate_group_stats(duplicates: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    rows = []
    for hash_value, items in duplicates.items():
        total_size = sum(i["size"] for i in items)
        wasted = total_size - max((i["size"] for i in items), default=0)
        rows.append({
            "hash": hash_value,
            "count": len(items),
            "total_size": total_size,
            "wasted_size": wasted,
            "items": items,
        })
    rows.sort(key=lambda x: (-x["count"], -x["wasted_size"], x["hash"]))
    return rows


def export_json(results: List[Dict[str, Any]], output_path: Path, metadata: Dict[str, Any]) -> None:
    safe_write_json(output_path, {"metadata": metadata, "results": results})


def export_csv(results: List[Dict[str, Any]], output_path: Path) -> None:
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["path", "name", "size_bytes", "size_human", "hash", "modified_time"])
        for item in results:
            writer.writerow([
                item["path"],
                Path(item["path"]).name,
                item["size"],
                human_size(item["size"]),
                item["hash"],
                item.get("mtime", 0),
            ])


def export_txt(results: List[Dict[str, Any]], output_path: Path, algo_name: str) -> None:
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(f"{APP_TITLE} Results - {algo_name.upper()}\n")
        f.write("=" * 100 + "\n")
        for i, item in enumerate(results, start=1):
            f.write(f"{i}. {item['path']}\n")
            f.write(f"   Size: {human_size(item['size'])} ({item['size']} bytes)\n")
            f.write(f"   MTime: {item.get('mtime', 0)}\n")
            f.write(f"   Hash: {item['hash']}\n")
            f.write("-" * 100 + "\n")


def export_scan_bundle(
    results: List[Dict[str, Any]],
    metadata: Dict[str, Any],
    label: str = "",
    target_dir: Optional[Path] = None,
) -> Tuple[Path, Path, Path]:
    target_dir = target_dir or EXPORT_DIR
    target_dir.mkdir(exist_ok=True, parents=True)

    algo_name = metadata.get("algorithm", "sha256")
    timestamp = metadata.get("timestamp", now_str())
    label_suffix = f"_{sanitize_name(label)}" if label else ""
    base_name = f"scan_{timestamp}{label_suffix}"

    json_path = target_dir / f"{base_name}.json"
    csv_path = target_dir / f"{base_name}.csv"
    txt_path = target_dir / f"{base_name}.txt"
    export_json(results, json_path, metadata)
    export_csv(results, csv_path)
    export_txt(results, txt_path, algo_name)

    return json_path, csv_path, txt_path


def load_json_results(json_path: Path) -> Tuple[Dict[str, Any], List[Dict[str, Any]]]:
    data = safe_read_json(json_path, None)
    if isinstance(data, dict) and "results" in data:
        return data.get("metadata", {}), data["results"]
    if isinstance(data, list):
        return {}, data
    raise ValueError("Unsupported JSON format.")


def compare_scans(
    old_results: List[Dict[str, Any]],
    new_results: List[Dict[str, Any]]
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]], List[Dict[str, Any]]]:
    old_map = {item["path"]: item for item in old_results}
    new_map = {item["path"]: item for item in new_results}

    added = []
    removed = []
    changed = []
    unchanged = []

    for path, item in new_map.items():
        if path not in old_map:
            added.append(item)
        else:
            old_item = old_map[path]
            if old_item["hash"] != item["hash"] or old_item["size"] != item["size"]:
                changed.append({
                    "path": path,
                    "old_hash": old_item["hash"],
                    "new_hash": item["hash"],
                    "old_size": old_item["size"],
                    "new_size": item["size"],
                })
            else:
                unchanged.append(item)

    for path, item in old_map.items():
        if path not in new_map:
            removed.append(item)

    return added, removed, changed, unchanged


def build_diff_summary(added, removed, changed, unchanged) -> Dict[str, Any]:
    return {
        "added_count": len(added),
        "removed_count": len(removed),
        "changed_count": len(changed),
        "unchanged_count": len(unchanged),
        "added_sample": added[:10],
        "removed_sample": removed[:10],
        "changed_sample": changed[:10],
    }


def verify_against_manifest(manifest_results, current_results):
    manifest_map = {item["path"]: item for item in manifest_results}
    current_map = {item["path"]: item for item in current_results}

    verified = []
    mismatched = []
    missing = []
    unexpected = []

    for path, m_item in manifest_map.items():
        if path not in current_map:
            missing.append(m_item)
        else:
            c_item = current_map[path]
            if m_item["hash"] == c_item["hash"] and m_item["size"] == c_item["size"]:
                verified.append(c_item)
            else:
                mismatched.append({
                    "path": path,
                    "manifest_hash": m_item["hash"],
                    "current_hash": c_item["hash"],
                    "manifest_size": m_item["size"],
                    "current_size": c_item["size"],
                })

    for path, c_item in current_map.items():
        if path not in manifest_map:
            unexpected.append(c_item)

    return verified, mismatched, missing, unexpected


# =========================
# Sorting / filtering / summaries
# =========================

def sort_results(results: List[Dict[str, Any]], sort_key="path", reverse=False) -> List[Dict[str, Any]]:
    valid_keys = {"path", "name", "size", "hash", "mtime"}
    if sort_key not in valid_keys:
        sort_key = "path"

    def key_func(item):
        if sort_key == "name":
            return Path(item["path"]).name.lower()
        return item.get(sort_key, "")

    return sorted(results, key=key_func, reverse=reverse)


def filter_results(results: List[Dict[str, Any]], query: str) -> List[Dict[str, Any]]:
    q = query.lower().strip()
    if not q:
        return list(results)

    filtered = []
    for item in results:
        file_name = Path(item["path"]).name.lower()
        file_path = item["path"].lower()
        file_hash = item["hash"].lower()
        if q in file_name or q in file_path or q in file_hash:
            filtered.append(item)
    return filtered
def summarize_extensions(results: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    stats = defaultdict(lambda: {"count": 0, "size": 0})
    for item in results:
        ext = Path(item["path"]).suffix.lower() or "[no_ext]"
        stats[ext]["count"] += 1
        stats[ext]["size"] += item["size"]
    rows = [{"extension": ext, "count": data["count"], "size": data["size"]} for ext, data in stats.items()]
    rows.sort(key=lambda x: (-x["count"], x["extension"]))
    return rows


def summarize_folders(results: List[Dict[str, Any]], root_path=None) -> List[Dict[str, Any]]:
    stats = defaultdict(lambda: {"count": 0, "size": 0})
    for item in results:
        p = Path(item["path"])
        parent = str(p.parent)
        if root_path:
            try:
                parent = str(Path(parent).relative_to(root_path))
                if parent == ".":
                    parent = "[root]"
            except Exception:
                pass
        stats[parent]["count"] += 1
        stats[parent]["size"] += item["size"]
    rows = [{"folder": folder, "count": data["count"], "size": data["size"]} for folder, data in stats.items()]
    rows.sort(key=lambda x: (-x["count"], x["folder"]))
    return rows


# =========================
# Watch / report helpers
# =========================

def append_watch_log(profile_name: str, cycle: int, metadata: Dict[str, Any], added, removed, changed, unchanged, baseline_summary=None) -> Path:
    log_path = WATCH_LOG_DIR / f"watch_{sanitize_name(profile_name)}.jsonl"
    record = {
        "logged_at": pretty_dt(),
        "cycle": cycle,
        "profile": profile_name,
        "path": metadata.get("scanned_path", ""),
        "algorithm": metadata.get("algorithm", ""),
        "file_count": metadata.get("file_count", 0),
        "cache_hits": metadata.get("cache_hits", 0),
        "fresh_hashed": metadata.get("fresh_hashed", 0),
        "elapsed_seconds": metadata.get("elapsed_seconds", 0),
        "added": len(added),
        "removed": len(removed),
        "changed": len(changed),
        "unchanged": len(unchanged),
        "timestamp": metadata.get("timestamp", ""),
        "baseline_summary": baseline_summary or {},
    }
    with open(log_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")
    return log_path


def load_watch_log(profile_name: str) -> Tuple[Path, List[Dict[str, Any]]]:
    log_path = WATCH_LOG_DIR / f"watch_{sanitize_name(profile_name)}.jsonl"
    records: List[Dict[str, Any]] = []
    if not log_path.exists():
        return log_path, records

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    records.append(json.loads(line))
                except Exception:
                    continue
    except Exception:
        pass
    return log_path, records


def default_profile_report_dir(profile_name: str) -> Path:
    out = REPORT_DIR / sanitize_name(profile_name)
    out.mkdir(exist_ok=True, parents=True)
    return out


def export_change_report(
    report_name: str,
    source_label: str,
    added,
    removed,
    changed,
    unchanged,
    extra_meta=None,
    target_dir=None,
    changed_only=False,
) -> Path:
    target_dir = target_dir or REPORT_DIR
    target_dir.mkdir(exist_ok=True, parents=True)
    stamp = now_str()
    out = target_dir / f"report_{sanitize_name(report_name)}_{stamp}.json"
    data = {
        "metadata": {
            "report_name": report_name,
            "source_label": source_label,
            "generated_at": pretty_dt(),
            "added_count": len(added),
            "removed_count": len(removed),
            "changed_count": len(changed),
            "unchanged_count": len(unchanged),
            "changed_only_mode": changed_only,
            **(extra_meta or {}),
        },
        "added": [] if changed_only else added,
        "removed": [] if changed_only else removed,
        "changed": changed,
        "unchanged_sample": [] if changed_only else unchanged[:100],
    }
    safe_write_json(out, data)
    return out


# =========================
# Saved object paths / list helpers
# =========================

def baseline_path_for_name(name: str) -> Path:
    return BASELINE_DIR / f"baseline_{sanitize_name(name)}.json"


def manifest_path_for_name(name: str) -> Path:
    return MANIFEST_DIR / f"manifest_{sanitize_name(name)}.json"


def list_baselines() -> List[Path]:
    return sorted(BASELINE_DIR.glob("baseline_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def list_manifests() -> List[Path]:
    return sorted(MANIFEST_DIR.glob("manifest_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def list_bookmarks() -> List[Path]:
    return sorted(BOOKMARK_DIR.glob("bookmark_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def list_reports() -> List[Path]:
    return sorted(REPORT_DIR.rglob("report_*.json"), key=lambda p: p.stat().st_mtime, reverse=True)


def save_baseline_from_results(results, metadata, name: str) -> Path:
    out = baseline_path_for_name(name)
    baseline_meta = dict(metadata)
    baseline_meta["baseline_name"] = name
    baseline_meta["saved_at"] = pretty_dt()
    baseline_meta["type"] = "trusted_baseline"
    export_json(results, out, baseline_meta)
    return out


def save_manifest_from_results(results, metadata, name: str) -> Path:
    out = manifest_path_for_name(name)
    manifest_meta = dict(metadata)
    manifest_meta["manifest_name"] = name
    manifest_meta["saved_at"] = pretty_dt()
    manifest_meta["type"] = "manifest"
    export_json(results, out, manifest_meta)
    return out


def evaluate_alerts(added_count, removed_count, changed_count, thresholds):
    thresholds = thresholds or {}
    added_limit = int(thresholds.get("added", 0))
    removed_limit = int(thresholds.get("removed", 0))
    changed_limit = int(thresholds.get("changed", 0))

    triggered = []
    if added_count > added_limit:
        triggered.append(f"added>{added_limit}")
    if removed_count > removed_limit:
        triggered.append(f"removed>{removed_limit}")
    if changed_count > changed_limit:
        triggered.append(f"changed>{changed_limit}")

    return {
        "added_limit": added_limit,
        "removed_limit": removed_limit,
        "changed_limit": changed_limit,
        "triggered": triggered,
        "alert": bool(triggered),
    }


def save_bookmarks(items, label="flagged") -> Path:
    stamp = now_str()
    out = BOOKMARK_DIR / f"bookmark_{sanitize_name(label)}_{stamp}.json"
    safe_write_json(out, items)
    return out


# =========================
# Display helpers
# =========================

def display_results(results, title="Results", limit=None, start_index=0) -> None:
    if not results:
        console.print(Panel.fit("No results to display.", border_style="yellow"))
        return

    if limit is None:
        limit = int(UI_SETTINGS.get("result_limit", 200))

    table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold green")
    table.add_column("#", style="cyan", no_wrap=True)
    table.add_column("File Name", style="bold white")
    table.add_column("Size", style="magenta", justify="right")
    table.add_column("Hash", style="green")
    table.add_column("Path", style="yellow")

    display_items = results[start_index:start_index + limit]
    for i, item in enumerate(display_items, start=start_index + 1):
        table.add_row(
            str(i),
            Path(item["path"]).name,
            human_size(item["size"]),
            item["hash"],
            item["path"],
        )

    console.print(table)
    shown_end = min(start_index + limit, len(results))
    console.print(f"[cyan]Showing {start_index + 1}-{shown_end} of {len(results)} result(s).[/cyan]")
def paged_display_results(results, title="Paged Results", page_size=None) -> None:
    page_size = page_size or int(UI_SETTINGS.get("page_size", 50))
    if not results:
        console.print(Panel.fit("No results to display.", border_style="yellow"))
        return

    page = 0
    while True:
        clear_screen()
        console.print(Panel.fit(f"[bold green]{title}[/bold green]", border_style="green"))

        start = page * page_size
        if start >= len(results):
            page = max(0, (len(results) - 1) // page_size)
            start = page * page_size

        display_results(results, title=f"{title} - Page {page + 1}", limit=page_size, start_index=start)

        choice = Prompt.ask("n=next, p=prev, q=quit", choices=["n", "p", "q"], default="q")
        if choice == "n":
            if start + page_size < len(results):
                page += 1
        elif choice == "p":
            if page > 0:
                page -= 1
        else:
            break


def display_duplicates(duplicates):
    if not duplicates:
        console.print(Panel.fit("No duplicate hashes found.", border_style="green"))
        return

    table = Table(title="Duplicate Hashes", box=box.MINIMAL_DOUBLE_HEAD, header_style="bold red")
    table.add_column("Hash", style="red")
    table.add_column("Count", style="cyan", justify="right")
    table.add_column("Files", style="yellow")

    for hash_value, items in duplicates.items():
        joined_paths = "\n".join(item["path"] for item in items[:20])
        if len(items) > 20:
            joined_paths += f"\n... and {len(items) - 20} more"
        table.add_row(hash_value, str(len(items)), joined_paths)

    console.print(table)


def display_duplicate_group_stats(rows, limit=20):
    if not rows:
        console.print(Panel.fit("No duplicate groups found.", border_style="yellow"))
        return

    table = Table(title="Duplicate Group Summary", box=box.SIMPLE_HEAVY, header_style="bold red")
    table.add_column("#", style="cyan")
    table.add_column("Hash", style="red")
    table.add_column("Files", style="yellow", justify="right")
    table.add_column("Total Size", style="magenta", justify="right")
    table.add_column("Wasted Size", style="bold white", justify="right")

    for i, row in enumerate(rows[:limit], start=1):
        table.add_row(
            str(i),
            row["hash"],
            str(row["count"]),
            human_size(row["total_size"]),
            human_size(row["wasted_size"]),
        )
    console.print(table)


def display_duplicate_groups_paged(duplicates) -> None:
    if not duplicates:
        console.print(Panel.fit("No duplicate hashes found.", border_style="green"))
        return

    dup_rows = []
    for hash_value, items in duplicates.items():
        for item in items:
            dup_rows.append({
                "path": item["path"],
                "size": item["size"],
                "mtime": item.get("mtime", 0),
                "hash": hash_value,
            })

    paged_display_results(dup_rows, title="Duplicate Review", page_size=25)


def display_errors(errors):
    if not errors:
        console.print(Panel.fit("No errors recorded.", border_style="green"))
        return

    table = Table(title="Errors", box=box.MINIMAL_DOUBLE_HEAD, header_style="bold red")
    table.add_column("Path", style="red")
    table.add_column("Error", style="yellow")

    for path, err in errors[:300]:
        table.add_row(path, err)

    console.print(table)
    if len(errors) > 300:
        console.print(f"[yellow]Showing first 300 of {len(errors)} errors.[/yellow]")


def display_comparison(added, removed, changed, unchanged, title="Comparison Summary"):
    summary = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold cyan")
    summary.add_column("Category", style="bold white")
    summary.add_column("Count", justify="right")

    summary.add_row("Added", str(len(added)))
    summary.add_row("Removed", str(len(removed)))
    summary.add_row("Changed", str(len(changed)))
    summary.add_row("Unchanged", str(len(unchanged)))
    console.print(summary)

    if added:
        console.print(f"[green]Added sample:[/green] {len(added[:5])} shown")
        for item in added[:5]:
            console.print(f"  + {item['path']}")

    if removed:
        console.print(f"[red]Removed sample:[/red] {len(removed[:5])} shown")
        for item in removed[:5]:
            console.print(f"  - {item['path']}")

    if changed:
        table = Table(title="Changed Files", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Path", style="yellow")
        table.add_column("Old Size", style="magenta")
        table.add_column("New Size", style="magenta")
        table.add_column("Old Hash", style="red")
        table.add_column("New Hash", style="green")
        for item in changed[:20]:
            table.add_row(
                item["path"],
                human_size(item["old_size"]),
                human_size(item["new_size"]),
                item["old_hash"],
                item["new_hash"],
            )
        console.print(table)


def display_alerts(alert_info):
    if not alert_info:
        return
    if alert_info.get("alert"):
        console.print(Panel.fit(
            "[bold red]ALERT TRIGGERED[/bold red]\n"
            f"Thresholds exceeded: {', '.join(alert_info.get('triggered', []))}",
            border_style="red"
        ))
    else:
        console.print(Panel.fit(
            "[bold green]No alert triggered.[/bold green]\n"
            f"Limits: added<={alert_info.get('added_limit', 0)}, "
            f"removed<={alert_info.get('removed_limit', 0)}, "
            f"changed<={alert_info.get('changed_limit', 0)}",
            border_style="green"
        ))


def display_verification(verified, mismatched, missing, unexpected):
    summary = Table(title="Manifest Verification Summary", box=box.SIMPLE_HEAVY, header_style="bold cyan")
    summary.add_column("Category")
    summary.add_column("Count", justify="right")

    summary.add_row("Verified", str(len(verified)))
    summary.add_row("Mismatched", str(len(mismatched)))
    summary.add_row("Missing", str(len(missing)))
    summary.add_row("Unexpected", str(len(unexpected)))

    console.print(summary)

    if mismatched:
        table = Table(title="Mismatched Files", box=box.MINIMAL_DOUBLE_HEAD)
        table.add_column("Path", style="yellow")
        table.add_column("Manifest Size", style="magenta")
        table.add_column("Current Size", style="magenta")
        table.add_column("Manifest Hash", style="red")
        table.add_column("Current Hash", style="green")
        for item in mismatched[:20]:
            table.add_row(
                item["path"],
                human_size(item["manifest_size"]),
                human_size(item["current_size"]),
                item["manifest_hash"],
                item["current_hash"],
            )
        console.print(table)


def display_extension_summary(rows, limit=30):
    if not rows:
        console.print(Panel.fit("No extension summary available.", border_style="yellow"))
        return

    table = Table(title="Extension Summary", box=box.SIMPLE_HEAVY, header_style="bold green")
    table.add_column("#", style="cyan")
    table.add_column("Extension", style="bold white")
    table.add_column("Count", style="yellow", justify="right")
    table.add_column("Total Size", style="magenta", justify="right")

    for i, row in enumerate(rows[:limit], start=1):
        table.add_row(str(i), row["extension"], str(row["count"]), human_size(row["size"]))

    console.print(table)
    if len(rows) > limit:
        console.print(f"[yellow]Showing first {limit} of {len(rows)} extension groups.[/yellow]")


def display_folder_summary(rows, limit=40):
    if not rows:
        console.print(Panel.fit("No folder summary available.", border_style="yellow"))
        return
    table = Table(title="Folder Summary", box=box.SIMPLE_HEAVY, header_style="bold green")
    table.add_column("#", style="cyan")
    table.add_column("Folder", style="bold white")
    table.add_column("Count", style="yellow", justify="right")
    table.add_column("Total Size", style="magenta", justify="right")

    for i, row in enumerate(rows[:limit], start=1):
        table.add_row(str(i), row["folder"], str(row["count"]), human_size(row["size"]))

    console.print(table)
    if len(rows) > limit:
        console.print(f"[yellow]Showing first {limit} of {len(rows)} folders.[/yellow]")


def display_watch_log(records, title="Watch History", limit=50):
    if not records:
        console.print(Panel.fit("No watch history records found.", border_style="yellow"))
        return

    table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold green")
    table.add_column("#", style="cyan")
    table.add_column("Logged At", style="bold white")
    table.add_column("Cycle", style="yellow", justify="right")
    table.add_column("Files", style="cyan", justify="right")
    table.add_column("Added", style="green", justify="right")
    table.add_column("Removed", style="red", justify="right")
    table.add_column("Changed", style="magenta", justify="right")
    table.add_column("Seconds", style="yellow", justify="right")

    display_items = records[-limit:]
    for i, rec in enumerate(display_items, start=1):
        table.add_row(
            str(i),
            rec.get("logged_at", ""),
            str(rec.get("cycle", 0)),
            str(rec.get("file_count", 0)),
            str(rec.get("added", 0)),
            str(rec.get("removed", 0)),
            str(rec.get("changed", 0)),
            f"{rec.get('elapsed_seconds', 0):.2f}",
        )

    console.print(table)


def print_dashboard():
    if not last_scan_results:
        console.print(Panel.fit("No scan has been run in this session yet.", border_style="yellow"))
        return

    total_size = sum(item["size"] for item in last_scan_results)
    largest = max(last_scan_results, key=lambda x: x["size"], default=None)

    panel_text = (
        f"[bold green]{APP_TITLE}[/bold green]\n"
        f"Version: {APP_VERSION}\n"
        f"Path: {last_scan_metadata.get('scanned_path', 'Unknown')}\n"
        f"Algorithm: {last_scan_metadata.get('algorithm', 'Unknown')}\n"
        f"Timestamp: {last_scan_metadata.get('timestamp', 'Unknown')}\n"
        f"Files: {len(last_scan_results)}\n"
        f"Total Size: {human_size(total_size)}\n"
        f"Duplicate Groups: {len(last_duplicates)}\n"
        f"Errors: {len(last_errors)}\n"
        f"Cache Hits: {last_scan_metadata.get('cache_hits', 0)}\n"
        f"Hashed Fresh: {last_scan_metadata.get('fresh_hashed', 0)}\n"
        f"Scan Seconds: {last_scan_metadata.get('elapsed_seconds', 0):.2f}\n"
        f"Page Size: {UI_SETTINGS.get('page_size', 50)}\n"
    )

    if largest:
        panel_text += f"Largest File: {Path(largest['path']).name}\nLargest Size: {human_size(largest['size'])}\n"

    if last_baseline_comparison:
        panel_text += (
            f"Baseline Added: {len(last_baseline_comparison['added'])}\n"
            f"Baseline Removed: {len(last_baseline_comparison['removed'])}\n"
            f"Baseline Changed: {len(last_baseline_comparison['changed'])}\n"
        )

    console.print(Panel.fit(panel_text, border_style="green"))


# =========================
# Profile persistence
# =========================

def load_profiles() -> Dict[str, Any]:
    data = safe_read_json(PROFILE_FILE, {})
    return data if isinstance(data, dict) else {}


def save_profiles(profiles: Dict[str, Any]) -> None:
    safe_write_json(PROFILE_FILE, profiles)


def list_profiles_table(profiles: Dict[str, Any]):
    if not profiles:
        console.print(Panel.fit("No saved profiles.", border_style="yellow"))
        return
    table = Table(title="Saved Profiles", box=box.SIMPLE_HEAVY, header_style="bold green")
    table.add_column("#", style="cyan")
    table.add_column("Name", style="bold white")
    table.add_column("Tags", style="magenta")
    table.add_column("Path", style="yellow")
    table.add_column("Algorithm", style="green")
    table.add_column("Extensions", style="cyan")
    table.add_column("Excludes", style="red")
    table.add_column("Last Run", style="bold white")
    table.add_column("Baseline", style="bold white")

    for i, (name, profile) in enumerate(sorted(profiles.items()), start=1):
        ext_str = ",".join(profile.get("extensions", [])) if profile.get("extensions") else "All"
        tags_str = ",".join(profile.get("tags", [])) if profile.get("tags") else "-"
        excludes_str = str(len(profile.get("exclude_dirs", [])))
        last_run = profile.get("last_run_at", "-") or "-"
        table.add_row(
            str(i),
            name,
            tags_str,
            profile.get("path", ""),
            profile.get("algorithm_preset", profile.get("algorithm", "sha256")),
            ext_str,
            excludes_str,
            last_run,
            profile.get("baseline_path", "") or "-"
        )

    console.print(table)


# =========================
# Menus / actions
# =========================

def run_scan():
    show_header("New Integrity Scan")

    root_input = Prompt.ask("Enter folder path to scan", default=".")
    algo_input = Prompt.ask(
        "Algorithm or preset",
        choices=list(SUPPORTED_ALGOS.keys()) + list(ALGO_PRESETS.keys()),
        default=UI_SETTINGS.get("default_algorithm", "sha256")
    ).lower()
    algo_name = resolve_algorithm(algo_input)
    ext_input = Prompt.ask("Extension filter (blank for all files)", default="")
    exclude_input = Prompt.ask("Exclude folders (comma separated, blank for none)", default="")
    include_pattern_input = Prompt.ask("Include file patterns (comma separated, e.g. *.txt, blank for none)", default="")
    exclude_pattern_input = Prompt.ask("Exclude file patterns (comma separated, e.g. *.tmp, blank for none)", default="")

    excluded_dirs = parse_csv_list(exclude_input)
    include_patterns = parse_csv_list(include_pattern_input)
    exclude_patterns = parse_csv_list(exclude_pattern_input)
    extensions = parse_extensions(ext_input)
    use_incremental = Confirm.ask("Use incremental cache / skip unchanged files?", default=True)

    root_path = Path(root_input).expanduser().resolve()
    if not root_path.exists():
        console.print(f"[bold red]Error:[/bold red] Path does not exist: {root_path}")
        wait_for_enter()
        return
    if not root_path.is_dir():
        console.print(f"[bold red]Error:[/bold red] Path is not a directory: {root_path}")
        wait_for_enter()
        return

    excluded_dirs = [str(Path(p).expanduser().resolve()) for p in excluded_dirs]

    run_scan_config(
        root_path,
        algo_name,
        extensions,
        use_incremental,
        show_output=True,
        excluded_dirs=excluded_dirs,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )
    wait_for_enter()


def export_last_scan():
    show_header("Export Last Scan")
    if not last_filtered_results:
        console.print("[yellow]No scan data available. Run a scan first.[/yellow]")
        wait_for_enter()
        return

    suffix = Prompt.ask("Optional export label", default="").strip()
    metadata = dict(last_scan_metadata)
    metadata["exported_result_count"] = len(last_filtered_results)

    json_path, csv_path, txt_path = export_scan_bundle(last_filtered_results, metadata, suffix)
    console.print(Panel.fit(
        f"[bold green]Export Complete[/bold green]\nJSON: {json_path}\nCSV:  {csv_path}\nTXT:  {txt_path}",
        border_style="green"
    ))
    wait_for_enter()
def compare_with_previous():
    global last_diff_result
    show_header("Compare With Previous Scan")
    if not last_scan_results:
        console.print("[yellow]No current scan data available. Run a scan first.[/yellow]")
        wait_for_enter()
        return

    json_path = Path(Prompt.ask("Enter previous JSON scan path")).expanduser().resolve()
    if not json_path.exists():
        console.print(f"[red]File not found:[/red] {json_path}")
        wait_for_enter()
        return

    try:
        show_header("Comparison Results")
        _, old_results = load_json_results(json_path)
        added, removed, changed, unchanged = compare_scans(old_results, last_scan_results)
        last_diff_result = {
            "source": str(json_path),
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged": unchanged,
            "summary": build_diff_summary(added, removed, changed, unchanged),
        }
        display_comparison(added, removed, changed, unchanged)

        if Confirm.ask("Bookmark all diff findings?", default=False):
            out = save_bookmarks(added + removed + changed, "diff_findings")
            console.print(f"[green]Bookmarks saved:[/green] {out}")

        if Confirm.ask("Export change report?", default=False):
            out = export_change_report("compare_previous", str(json_path), added, removed, changed, unchanged)
            console.print(f"[green]Report exported:[/green] {out}")

    except Exception as e:
        console.print(f"[red]Comparison failed:[/red] {e}")
    wait_for_enter()


def compare_last_scan_to_baseline():
    global last_baseline_comparison, last_diff_result

    show_header("Compare To Baseline")
    if not last_scan_results:
        console.print("[yellow]No current scan data available. Run a scan first.[/yellow]")
        wait_for_enter()
        return

    baseline_path = Path(Prompt.ask("Enter baseline JSON path")).expanduser().resolve()
    if not baseline_path.exists():
        console.print(f"[red]Baseline not found:[/red] {baseline_path}")
        wait_for_enter()
        return

    try:
        show_header("Baseline Drift Results")
        base_meta, base_results = load_json_results(baseline_path)
        added, removed, changed, unchanged = compare_scans(base_results, last_scan_results)
        summary = build_diff_summary(added, removed, changed, unchanged)
        last_baseline_comparison = {
            "baseline_path": str(baseline_path),
            "baseline_meta": base_meta,
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged": unchanged,
            "summary": summary,
        }
        last_diff_result = {
            "source": str(baseline_path),
            "added": added,
            "removed": removed,
            "changed": changed,
            "unchanged": unchanged,
            "summary": summary,
        }
        display_comparison(added, removed, changed, unchanged, title="Baseline Drift Summary")

        if Confirm.ask("Bookmark all drift findings?", default=False):
            out = save_bookmarks(added + removed + changed, "baseline_drift")
            console.print(f"[green]Bookmarks saved:[/green] {out}")

        if Confirm.ask("Export baseline drift report?", default=False):
            out = export_change_report("baseline_drift", str(baseline_path), added, removed, changed, unchanged)
            console.print(f"[green]Report exported:[/green] {out}")

    except Exception as e:
        console.print(f"[red]Baseline comparison failed:[/red] {e}")
    wait_for_enter()


def verify_against_previous_manifest():
    global last_manifest_comparison

    show_header("Verify Against Manifest")
    if not last_scan_results:
        console.print("[yellow]No current scan data available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    json_path = Path(Prompt.ask("Enter manifest JSON path")).expanduser().resolve()
    if not json_path.exists():
        console.print(f"[red]File not found:[/red] {json_path}")
        wait_for_enter()
        return

    try:
        show_header("Manifest Verification Results")
        manifest_meta, manifest_results = load_json_results(json_path)
        verified, mismatched, missing, unexpected = verify_against_manifest(manifest_results, last_scan_results)
        last_manifest_comparison = {
            "manifest_path": str(json_path),
            "manifest_meta": manifest_meta,
            "verified": verified,
            "mismatched": mismatched,
            "missing": missing,
            "unexpected": unexpected,
        }
        display_verification(verified, mismatched, missing, unexpected)
    except Exception as e:
        console.print(f"[red]Verification failed:[/red] {e}")
    wait_for_enter()


def verify_single_file():
    show_header("Single File Verification")
    file_path = Path(Prompt.ask("Enter file path to verify")).expanduser().resolve()
    manifest_path = Path(Prompt.ask("Enter manifest JSON path")).expanduser().resolve()

    if not file_path.exists() or not file_path.is_file():
        console.print(f"[red]Invalid file:[/red] {file_path}")
        wait_for_enter()
        return
    if not manifest_path.exists():
        console.print(f"[red]Manifest not found:[/red] {manifest_path}")
        wait_for_enter()
        return

    try:
        manifest_meta, manifest_results = load_json_results(manifest_path)
    except Exception as e:
        console.print(f"[red]Failed to load manifest:[/red] {e}")
        wait_for_enter()
        return

    algo_name = manifest_meta.get("algorithm", "sha256")
    manifest_map = {item["path"]: item for item in manifest_results}
    target_key = str(file_path)

    if target_key not in manifest_map:
        console.print("[yellow]File path not present in manifest.[/yellow]")
        wait_for_enter()
        return

    try:
        stat = file_path.stat()
        current_hash = hash_file(file_path, algo_name)
        current_size = stat.st_size

        expected = manifest_map[target_key]
        matches = expected["hash"] == current_hash and expected["size"] == current_size

        table = Table(title="Single File Verification", box=box.SIMPLE_HEAVY, header_style="bold green")
        table.add_column("Field", style="bold white")
        table.add_column("Expected", style="yellow")
        table.add_column("Current", style="cyan")

        table.add_row("Path", expected["path"], target_key)
        table.add_row("Size", str(expected["size"]), str(current_size))
        table.add_row("Hash", expected["hash"], current_hash)
        table.add_row("Algorithm", algo_name, algo_name)

        console.print(table)
        console.print(Panel.fit(
            "Verification passed." if matches else "Verification failed: size and/or hash mismatch.",
            border_style="green" if matches else "red"
        ))
    except Exception as e:
        console.print(f"[red]Verification failed:[/red] {e}")
    wait_for_enter()


def save_current_scan_as_baseline():
    show_header("Save Baseline")
    if not last_scan_results:
        console.print("[yellow]No scan data available. Run a scan first.[/yellow]")
        wait_for_enter()
        return

    name = Prompt.ask("Baseline name").strip()
    if not name:
        console.print("[red]Baseline name cannot be empty.[/red]")
        wait_for_enter()
        return

    out = save_baseline_from_results(last_scan_results, last_scan_metadata, name)
    console.print(f"[green]Baseline saved:[/green] {out}")
    wait_for_enter()


def save_current_scan_as_manifest():
    show_header("Save Manifest")
    if not last_scan_results:
        console.print("[yellow]No scan data available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    name = Prompt.ask("Manifest name").strip()
    if not name:
        console.print("[red]Manifest name cannot be empty.[/red]")
        wait_for_enter()
        return

    out = save_manifest_from_results(last_scan_results, last_scan_metadata, name)
    console.print(f"[green]Manifest saved:[/green] {out}")
    wait_for_enter()


def bookmark_last_baseline_drift():
    show_header("Bookmark Baseline Drift")
    if not last_baseline_comparison:
        console.print("[yellow]No baseline comparison available yet.[/yellow]")
        wait_for_enter()
        return

    which = Prompt.ask("Bookmark which set", choices=["added", "removed", "changed", "all"], default="changed")
    if which == "added":
        items = last_baseline_comparison["added"]
    elif which == "removed":
        items = last_baseline_comparison["removed"]
    elif which == "changed":
        items = last_baseline_comparison["changed"]
    else:
        items = last_baseline_comparison["added"] + last_baseline_comparison["removed"] + last_baseline_comparison["changed"]

    out = save_bookmarks(items, f"baseline_{which}")
    console.print(f"[green]Bookmarks saved:[/green] {out}")
    wait_for_enter()


def review_duplicates_helper():
    show_header("Duplicate Review")
    if not last_duplicates:
        console.print("[yellow]No duplicate groups available. Run a scan first.[/yellow]")
        wait_for_enter()
        return

    group_rows = duplicate_group_stats(last_duplicates)
    display_duplicate_group_stats(group_rows)
    display_duplicates(last_duplicates)

    if Confirm.ask("Open paged duplicate review?", default=True):
        display_duplicate_groups_paged(last_duplicates)

    if Confirm.ask("Bookmark all duplicate entries?", default=False):
        dup_items = []
        for items in last_duplicates.values():
            dup_items.extend(items)
        out = save_bookmarks(dup_items, "duplicates")
        console.print(f"[green]Duplicate bookmarks saved:[/green] {out}")

    if Confirm.ask("Bookmark top duplicate groups only?", default=False):
        top_items = []
        for row in group_rows[:5]:
            top_items.extend(row["items"])
        out = save_bookmarks(top_items, "top_duplicate_groups")
        console.print(f"[green]Top duplicate group bookmarks saved:[/green] {out}")

    wait_for_enter()


def show_last_duplicates():
    show_header("Duplicate Hashes")
    if not last_scan_results:
        console.print("[yellow]No scan data available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    display_duplicates(last_duplicates)
    wait_for_enter()


def show_last_errors():
    show_header("Errors")
    if not last_scan_results and not last_errors:
        console.print("[yellow]No scan data available yet.[/yellow]")
        wait_for_enter()
        return
    display_errors(last_errors)
    wait_for_enter()


def show_last_results():
    show_header("Displayed Results")
    if not last_filtered_results:
        console.print("[yellow]No results available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    display_results(last_filtered_results, title=f"Displayed Results - {last_scan_metadata.get('algorithm', 'sha256').upper()}")
    wait_for_enter()


def show_last_results_paged():
    show_header("Paged Results")
    if not last_filtered_results:
        console.print("[yellow]No results available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    paged_display_results(last_filtered_results, title="Displayed Results", page_size=int(UI_SETTINGS.get("page_size", 50)))


def list_exports():
    show_header("Export Files")
    files = sorted(EXPORT_DIR.glob("*"), key=lambda p: p.stat().st_mtime, reverse=True)
    list_file_group(files, "Export Files")
    wait_for_enter()


def list_cache_files():
    show_header("Cache Files")
    files = sorted(CACHE_DIR.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)
    list_file_group(files, "Cache Files")
    wait_for_enter()
def clear_cache_menu():
    show_header("Clear Cache Files")
    files = sorted(CACHE_DIR.glob("*.json"))
    if not files:
        console.print(Panel.fit("No cache files to delete.", border_style="yellow"))
        wait_for_enter()
        return
    console.print(f"[yellow]Found {len(files)} cache file(s).[/yellow]")
    if Confirm.ask("Delete all cache files?", default=False):
        deleted = 0
        for file in files:
            try:
                file.unlink()
                deleted += 1
            except Exception as e:
                console.print(f"[red]Failed to delete {file}: {e}[/red]")
        console.print(f"[green]Deleted {deleted} cache file(s).[/green]")
    wait_for_enter()


def sort_last_results_menu():
    global last_filtered_results
    show_header("Sort Results")
    if not last_scan_results:
        console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    sort_key = Prompt.ask("Sort by", choices=["path", "name", "size", "hash", "mtime"], default="path")
    reverse = Confirm.ask("Reverse sort?", default=False)
    last_filtered_results = sort_results(last_filtered_results or last_scan_results, sort_key, reverse)
    show_header("Sorted Results")
    display_results(last_filtered_results, title=f"Sorted Results - {sort_key}")
    wait_for_enter()


def search_last_results_menu():
    global last_filtered_results
    show_header("Search Results")
    if not last_scan_results:
        console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    query = Prompt.ask("Enter search text (file name, path, or hash)")
    filtered = filter_results(last_scan_results, query)
    last_filtered_results = filtered
    show_header("Search Results")
    console.print(f"[green]Matched {len(filtered)} result(s).[/green]")
    display_results(filtered, title=f"Search Results - {query}")
    wait_for_enter()


def reset_filtered_view():
    global last_filtered_results
    show_header("Reset View")
    if not last_scan_results:
        console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    last_filtered_results = list(last_scan_results)
    console.print("[green]Display view reset to full last scan.[/green]")
    wait_for_enter()


def show_largest_files():
    show_header("Largest Files")
    if not last_scan_results:
        console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    count = IntPrompt.ask("How many largest files to show?", default=20)
    largest = sort_results(last_scan_results, "size", reverse=True)[:count]
    show_header(f"Largest {count} Files")
    display_results(largest, title=f"Largest {count} Files", limit=count)
    wait_for_enter()


def show_extension_summary():
    show_header("Extension Summary")
    if not last_scan_results:
        console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    display_extension_summary(summarize_extensions(last_scan_results))
    wait_for_enter()


def show_folder_summary():
    show_header("Folder Summary")
    if not last_scan_results:
        console.print("[yellow]No scan results available. Run a scan first.[/yellow]")
        wait_for_enter()
        return
    display_folder_summary(summarize_folders(last_scan_results, root_path=last_scan_metadata.get("scanned_path")))
    wait_for_enter()


def list_file_group(files: List[Path], title: str):
    if not files:
        console.print(Panel.fit(f"No {title.lower()} found.", border_style="yellow"))
        return

    table = Table(title=title, box=box.SIMPLE_HEAVY, header_style="bold green")
    table.add_column("#", style="cyan")
    table.add_column("Path", style="bold white")
    table.add_column("Size", style="magenta", justify="right")
    table.add_column("Modified", style="yellow")
    for i, file in enumerate(files, start=1):
        modified = datetime.fromtimestamp(file.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
        table.add_row(str(i), str(file), human_size(file.stat().st_size), modified)

    console.print(table)


def preview_json_file(path: Path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        snippet = json.dumps(data, indent=2)[:8000]
        console.print(Panel(snippet, title=str(path), border_style="green"))
    except Exception as e:
        console.print(f"[red]Failed to open file:[/red] {e}")


def manage_file_collection_menu(title, files_func, allow_preview=True):
    show_header(title)
    files = files_func()
    list_file_group(files, title)
    if not files:
        wait_for_enter()
        return

    if allow_preview and Confirm.ask("Preview a file?", default=False):
        path_input = Prompt.ask("Enter exact path to preview")
        p = Path(path_input).expanduser().resolve()
        if p.exists():
            show_header(f"{title} Preview")
            preview_json_file(p)
            wait_for_enter()
            show_header(title)
            list_file_group(files_func(), title)

    path_input = Prompt.ask("Enter exact path to delete, or blank to return", default="").strip()
    if path_input:
        p = Path(path_input).expanduser().resolve()
        if p.exists() and Confirm.ask(f"Delete {p}?", default=False):
            try:
                p.unlink()
                console.print(f"[green]Deleted:[/green] {p}")
            except Exception as e:
                console.print(f"[red]Delete failed:[/red] {e}")
    wait_for_enter()


def about_menu():
    show_header("About")
    text = (
        f"[bold green]{APP_TITLE}[/bold green]\n"
        f"Version: {APP_VERSION}\n\n"
        f"{APP_TAGLINE}\n\n"
        "Main features:\n"
        "- recursive hashing\n"
        "- manifests and baselines\n"
        "- drift comparison\n"
        "- duplicate triage\n"
        "- saved profiles/jobs\n"
        "- watch mode\n"
        "- reports and bookmarks\n"
        "- saved UI settings\n"
        "- include/exclude pattern rules\n"
    )
    console.print(Panel.fit(text, border_style="green"))
    wait_for_enter()


def maintenance_menu():
    show_header("Maintenance")
    console.print(Panel.fit(
        "1. List export files\n"
        "2. List cache files\n"
        "3. Clear cache files\n"
        "4. List reports\n"
        "5. List bookmarks\n"
        "6. Back up profile file\n"
        "7. Open app log preview\n"
        "0. Back",
        border_style="green"
    ))
    choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "7", "0"], default="0")
    if choice == "1":
        list_exports()
    elif choice == "2":
        list_cache_files()
    elif choice == "3":
        clear_cache_menu()
    elif choice == "4":
        show_header("Reports")
        list_file_group(list_reports(), "Reports")
        wait_for_enter()
    elif choice == "5":
        show_header("Bookmarks")
        list_file_group(list_bookmarks(), "Bookmarks")
        wait_for_enter()
    elif choice == "6":
        show_header("Back Up Profile File")
        if PROFILE_FILE.exists():
            backup = BASE_DIR / f"scan_profiles_backup_{now_str()}.json"
            shutil.copy2(PROFILE_FILE, backup)
            console.print(f"[green]Profile backup created:[/green] {backup}")
        else:
            console.print("[yellow]No profile file exists yet.[/yellow]")
        wait_for_enter()
    elif choice == "7":
        show_header("App Log Preview")
        if APP_LOG_FILE.exists():
            try:
                text = APP_LOG_FILE.read_text(encoding="utf-8")[-8000:]
                console.print(Panel(text, title=str(APP_LOG_FILE), border_style="green"))
            except Exception as e:
                console.print(f"[red]Could not read log:[/red] {e}")
        else:
            console.print("[yellow]No app log yet.[/yellow]")
        wait_for_enter()
def ui_settings_menu():
    global UI_SETTINGS
    while True:
        show_header("UI Settings")
        console.print(Panel.fit(
            f"1. Toggle screen clearing ({UI_SETTINGS.get('clear_screen', True)})\n"
            f"2. Toggle pause after views ({UI_SETTINGS.get('pause_after_views', True)})\n"
            f"3. Change page size ({UI_SETTINGS.get('page_size', 50)})\n"
            f"4. Change default algorithm ({UI_SETTINGS.get('default_algorithm', 'sha256')})\n"
            f"5. Change default result limit ({UI_SETTINGS.get('result_limit', 200)})\n"
            "6. Reset to defaults\n"
            "0. Back",
            border_style="green"
        ))
        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "0"], default="0")
        if choice == "1":
            UI_SETTINGS["clear_screen"] = not UI_SETTINGS.get("clear_screen", True)
            save_ui_settings(UI_SETTINGS)
        elif choice == "2":
            UI_SETTINGS["pause_after_views"] = not UI_SETTINGS.get("pause_after_views", True)
            save_ui_settings(UI_SETTINGS)
        elif choice == "3":
            UI_SETTINGS["page_size"] = IntPrompt.ask("Page size", default=int(UI_SETTINGS.get("page_size", 50)))
            save_ui_settings(UI_SETTINGS)
        elif choice == "4":
            UI_SETTINGS["default_algorithm"] = Prompt.ask(
                "Default algorithm",
                choices=list(SUPPORTED_ALGOS.keys()) + list(ALGO_PRESETS.keys()),
                default=UI_SETTINGS.get("default_algorithm", "sha256")
            )
            save_ui_settings(UI_SETTINGS)
        elif choice == "5":
            UI_SETTINGS["result_limit"] = IntPrompt.ask("Result display limit", default=int(UI_SETTINGS.get("result_limit", 200)))
            save_ui_settings(UI_SETTINGS)
        elif choice == "6":
            UI_SETTINGS = dict(DEFAULT_UI_SETTINGS)
            save_ui_settings(UI_SETTINGS)
        else:
            break


def quick_actions_menu():
    while True:
        show_header("Quick Actions")
        console.print(Panel.fit(
            "1. Run new scan\n"
            "2. Show paged results\n"
            "3. Export last scan\n"
            "4. Save last scan as baseline\n"
            "5. Save last scan as manifest\n"
            "6. Review duplicates\n"
            "7. Show dashboard\n"
            "0. Back",
            border_style="green"
        ))
        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "7", "0"], default="1")
        if choice == "1":
            run_scan()
        elif choice == "2":
            show_last_results_paged()
        elif choice == "3":
            export_last_scan()
        elif choice == "4":
            save_current_scan_as_baseline()
        elif choice == "5":
            save_current_scan_as_manifest()
        elif choice == "6":
            review_duplicates_helper()
        elif choice == "7":
            show_header("Session Dashboard")
            print_dashboard()
            wait_for_enter()
        else:
            break


def profile_dashboard():
    show_header("Profile Dashboard")
    profiles = load_profiles()
    if not profiles:
        console.print(Panel.fit("No saved profiles.", border_style="yellow"))
        wait_for_enter()
        return

    table = Table(title="Profile Dashboard", box=box.SIMPLE_HEAVY, header_style="bold green")
    table.add_column("Profile", style="bold white")
    table.add_column("Tags", style="magenta")
    table.add_column("Path", style="yellow")
    table.add_column("Algorithm", style="green")
    table.add_column("Baseline", style="cyan")
    table.add_column("Excludes", style="red")
    table.add_column("Last Run", style="yellow")
    table.add_column("Last Files", style="bold white")
    table.add_column("Report Mode", style="green")
    for name, profile in sorted(profiles.items()):
        tags_str = ",".join(profile.get("tags", [])) if profile.get("tags") else "-"
        report_mode = profile.get("report_mode", "full")
        table.add_row(
            name,
            tags_str,
            profile.get("path", ""),
            profile.get("algorithm_preset", profile.get("algorithm", "sha256")),
            "Yes" if profile.get("baseline_path") else "No",
            str(len(profile.get("exclude_dirs", []))),
            profile.get("last_run_at", "-") or "-",
            str(profile.get("last_run_file_count", "-")),
            report_mode,
        )

    console.print(table)
    wait_for_enter()


def add_profile():
    show_header("Add Profile")
    profiles = load_profiles()
    name = Prompt.ask("Profile name").strip()
    if not name:
        console.print("[red]Profile name cannot be empty.[/red]")
        wait_for_enter()
        return

    root_input = Prompt.ask("Folder path", default=".")
    algo_input = Prompt.ask(
        "Algorithm or preset",
        choices=list(SUPPORTED_ALGOS.keys()) + list(ALGO_PRESETS.keys()),
        default=UI_SETTINGS.get("default_algorithm", "sha256")
    ).lower()
    algo_name = resolve_algorithm(algo_input)
    ext_input = Prompt.ask("Extension filter (blank for all files)", default="")
    exclude_input = Prompt.ask("Exclude folders (comma separated, blank for none)", default="")
    include_pattern_input = Prompt.ask("Include file patterns (comma separated, blank for none)", default="")
    exclude_pattern_input = Prompt.ask("Exclude file patterns (comma separated, blank for none)", default="")
    tags_input = Prompt.ask("Tags/categories (comma separated, blank for none)", default="")

    extensions = sorted(list(parse_extensions(ext_input)))
    exclude_dirs = parse_csv_list(exclude_input)
    include_patterns = parse_csv_list(include_pattern_input)
    exclude_patterns = parse_csv_list(exclude_pattern_input)
    tags = parse_csv_list(tags_input)

    incremental = Confirm.ask("Use incremental cache?", default=True)
    auto_export = Confirm.ask("Auto-export after profile run?", default=False)
    watch_log = Confirm.ask("Write watch history log for watch mode?", default=True)
    report_on_change_only = Confirm.ask("Only export report when changes are found?", default=True)
    report_mode = Prompt.ask("Report mode", choices=["full", "changed_only"], default="full")
    note = Prompt.ask("Optional note", default="").strip()

    baseline_path = ""
    if Confirm.ask("Link a baseline now?", default=False):
        bp = Path(Prompt.ask("Baseline JSON path")).expanduser().resolve()
        if bp.exists():
            baseline_path = str(bp)

    alert_thresholds = {
        "added": IntPrompt.ask("Alert threshold for added files", default=0),
        "removed": IntPrompt.ask("Alert threshold for removed files", default=0),
        "changed": IntPrompt.ask("Alert threshold for changed files", default=0),
    }

    root_path = Path(root_input).expanduser().resolve()
    if not root_path.exists() or not root_path.is_dir():
        console.print(f"[red]Invalid directory:[/red] {root_path}")
        wait_for_enter()
        return

    exclude_dirs = [str(Path(p).expanduser().resolve()) for p in exclude_dirs]

    profiles[name] = {
        "path": str(root_path),
        "algorithm": algo_name,
        "algorithm_preset": algo_input,
        "extensions": extensions,
        "exclude_dirs": exclude_dirs,
        "include_patterns": include_patterns,
        "exclude_patterns": exclude_patterns,
        "tags": tags,
        "incremental": incremental,
        "auto_export": auto_export,
        "watch_log": watch_log,
        "report_on_change_only": report_on_change_only,
        "report_mode": report_mode,
        "note": note,
        "baseline_path": baseline_path,
        "alert_thresholds": alert_thresholds,
        "last_run_at": "",
        "last_run_file_count": 0,
        "last_run_changed_count": 0,
        "created": pretty_dt(),
    }
    save_profiles(profiles)
    console.print(f"[green]Saved profile:[/green] {name}")
    wait_for_enter()


def edit_profile():
    show_header("Edit Profile")
    profiles = load_profiles()
    if not profiles:
        console.print(Panel.fit("No saved profiles.", border_style="yellow"))
        wait_for_enter()
        return

    list_profiles_table(profiles)
    name = Prompt.ask("Enter profile name to edit").strip()
    if name not in profiles:
        console.print("[red]Profile not found.[/red]")
        wait_for_enter()
        return

    profile = profiles[name]
    root_input = Prompt.ask("Folder path", default=profile.get("path", "."))
    current_algo_default = profile.get("algorithm_preset", profile.get("algorithm", "sha256"))
    algo_input = Prompt.ask(
        "Algorithm or preset",
        choices=list(SUPPORTED_ALGOS.keys()) + list(ALGO_PRESETS.keys()),
        default=current_algo_default
    ).lower()
    algo_name = resolve_algorithm(algo_input)

    ext_default = ",".join(profile.get("extensions", []))
    exclude_default = ",".join(profile.get("exclude_dirs", []))
    include_pattern_default = ",".join(profile.get("include_patterns", []))
    exclude_pattern_default = ",".join(profile.get("exclude_patterns", []))
    tags_default = ",".join(profile.get("tags", []))

    ext_input = Prompt.ask("Extension filter", default=ext_default)
    exclude_input = Prompt.ask("Exclude folders", default=exclude_default)
    include_pattern_input = Prompt.ask("Include file patterns", default=include_pattern_default)
    exclude_pattern_input = Prompt.ask("Exclude file patterns", default=exclude_pattern_default)
    tags_input = Prompt.ask("Tags/categories", default=tags_default)

    extensions = sorted(list(parse_extensions(ext_input)))
    exclude_dirs = [str(Path(p).expanduser().resolve()) for p in parse_csv_list(exclude_input)]
    include_patterns = parse_csv_list(include_pattern_input)
    exclude_patterns = parse_csv_list(exclude_pattern_input)
    tags = parse_csv_list(tags_input)

    incremental = Confirm.ask("Use incremental cache?", default=profile.get("incremental", True))
    auto_export = Confirm.ask("Auto-export after profile run?", default=profile.get("auto_export", False))
    watch_log = Confirm.ask("Write watch history log for watch mode?", default=profile.get("watch_log", True))
    report_on_change_only = Confirm.ask("Only export report when changes are found?", default=profile.get("report_on_change_only", True))
    report_mode = Prompt.ask("Report mode", choices=["full", "changed_only"], default=profile.get("report_mode", "full"))
    note = Prompt.ask("Optional note", default=profile.get("note", "")).strip()

    current_baseline = profile.get("baseline_path", "")
    baseline_input = Prompt.ask("Baseline JSON path (blank to clear)", default=current_baseline)
    baseline_path = ""
    if baseline_input.strip():
        baseline_path = str(Path(baseline_input).expanduser().resolve())

    alert_thresholds = {
        "added": IntPrompt.ask("Alert threshold for added files", default=int(profile.get("alert_thresholds", {}).get("added", 0))),
        "removed": IntPrompt.ask("Alert threshold for removed files", default=int(profile.get("alert_thresholds", {}).get("removed", 0))),
        "changed": IntPrompt.ask("Alert threshold for changed files", default=int(profile.get("alert_thresholds", {}).get("changed", 0))),
    }

    root_path = Path(root_input).expanduser().resolve()
    if not root_path.exists() or not root_path.is_dir():
        console.print(f"[red]Invalid directory:[/red] {root_path}")
        wait_for_enter()
        return
    profiles[name] = {
        "path": str(root_path),
        "algorithm": algo_name,
        "algorithm_preset": algo_input,
        "extensions": extensions,
        "exclude_dirs": exclude_dirs,
        "include_patterns": include_patterns,
        "exclude_patterns": exclude_patterns,
        "tags": tags,
        "incremental": incremental,
        "auto_export": auto_export,
        "watch_log": watch_log,
        "report_on_change_only": report_on_change_only,
        "report_mode": report_mode,
        "note": note,
        "baseline_path": baseline_path,
        "alert_thresholds": alert_thresholds,
        "last_run_at": profile.get("last_run_at", ""),
        "last_run_file_count": profile.get("last_run_file_count", 0),
        "last_run_changed_count": profile.get("last_run_changed_count", 0),
        "created": profile.get("created", pretty_dt()),
        "updated": pretty_dt(),
    }
    save_profiles(profiles)
    console.print(f"[green]Updated profile:[/green] {name}")
    wait_for_enter()


def clone_profile():
    show_header("Clone Profile")
    profiles = load_profiles()
    if not profiles:
        console.print("[yellow]No saved profiles.[/yellow]")
        wait_for_enter()
        return

    list_profiles_table(profiles)
    source = Prompt.ask("Enter source profile name").strip()
    if source not in profiles:
        console.print("[red]Profile not found.[/red]")
        wait_for_enter()
        return

    new_name = Prompt.ask("Enter new cloned profile name").strip()
    if not new_name:
        console.print("[red]New profile name cannot be empty.[/red]")
        wait_for_enter()
        return
    if new_name in profiles:
        console.print("[red]A profile with that name already exists.[/red]")
        wait_for_enter()
        return

    cloned = json.loads(json.dumps(profiles[source]))
    cloned["created"] = pretty_dt()
    cloned["updated"] = pretty_dt()
    cloned["last_run_at"] = ""
    cloned["last_run_file_count"] = 0
    cloned["last_run_changed_count"] = 0
    profiles[new_name] = cloned
    save_profiles(profiles)
    console.print(f"[green]Cloned profile '{source}' to '{new_name}'.[/green]")
    wait_for_enter()


def delete_profile():
    show_header("Delete Profile")
    profiles = load_profiles()
    if not profiles:
        console.print(Panel.fit("No saved profiles.", border_style="yellow"))
        wait_for_enter()
        return
    list_profiles_table(profiles)
    name = Prompt.ask("Enter profile name to delete").strip()
    if name not in profiles:
        console.print("[red]Profile not found.[/red]")
        wait_for_enter()
        return
    if Confirm.ask(f"Delete profile '{name}'?", default=False):
        del profiles[name]
        save_profiles(profiles)
        console.print(f"[green]Deleted profile:[/green] {name}")
    wait_for_enter()


def filter_profiles_by_tag():
    show_header("Filter Profiles By Tag")
    profiles = load_profiles()
    if not profiles:
        console.print("[yellow]No saved profiles.[/yellow]")
        wait_for_enter()
        return
    tag = Prompt.ask("Enter tag/category").strip().lower()
    filtered = {
        name: p for name, p in profiles.items()
        if any(t.lower() == tag for t in p.get("tags", []))
    }
    list_profiles_table(filtered)
    wait_for_enter()


def run_profile_scan():
    global last_baseline_comparison, last_diff_result

    show_header("Run Profile")
    profiles = load_profiles()
    if not profiles:
        console.print(Panel.fit("No saved profiles.", border_style="yellow"))
        wait_for_enter()
        return

    list_profiles_table(profiles)
    name = Prompt.ask("Enter profile name to run").strip()
    if name not in profiles:
        console.print("[red]Profile not found.[/red]")
        wait_for_enter()
        return
    profile = profiles[name]
    root_path = Path(profile["path"]).expanduser().resolve()
    algo_name = resolve_algorithm(profile.get("algorithm_preset", profile.get("algorithm", "sha256")))
    extensions = set(profile.get("extensions", []))
    excluded_dirs = profile.get("exclude_dirs", [])
    include_patterns = profile.get("include_patterns", [])
    exclude_patterns = profile.get("exclude_patterns", [])
    incremental = profile.get("incremental", True)

    if not root_path.exists() or not root_path.is_dir():
        console.print(f"[red]Profile path invalid:[/red] {root_path}")
        wait_for_enter()
        return

    console.print(f"[green]Running profile:[/green] {name}")
    scan_data = run_scan_config(
        root_path,
        algo_name,
        extensions,
        incremental,
        show_output=True,
        excluded_dirs=excluded_dirs,
        include_patterns=include_patterns,
        exclude_patterns=exclude_patterns,
    )

    changed_count = 0
    baseline_path = profile.get("baseline_path", "")
    if scan_data and baseline_path:
        bp = Path(baseline_path).expanduser().resolve()
        if bp.exists():
            _, base_results = load_json_results(bp)
            added, removed, changed, unchanged = compare_scans(base_results, scan_data["results"])
            changed_count = len(changed)
            summary = build_diff_summary(added, removed, changed, unchanged)
            last_baseline_comparison = {
                "baseline_path": str(bp),
                "added": added,
                "removed": removed,
                "changed": changed,
                "unchanged": unchanged,
                "summary": summary,
            }
            last_diff_result = {
                "source": str(bp),
                "added": added,
                "removed": removed,
                "changed": changed,
                "unchanged": unchanged,
                "summary": summary,
            }
            console.print()
            display_comparison(added, removed, changed, unchanged, title=f"Baseline Drift - {name}")
            alert_info = evaluate_alerts(len(added), len(removed), len(changed), profile.get("alert_thresholds", {}))
            display_alerts(alert_info)

            should_report = True
            if profile.get("report_on_change_only", True) and (len(added) == 0 and len(removed) == 0 and len(changed) == 0):
                should_report = False

            if should_report and Confirm.ask("Export drift report?", default=False):
                target_dir = default_profile_report_dir(name)
                changed_only = profile.get("report_mode", "full") == "changed_only"
                out = export_change_report(
                    f"profile_{name}_baseline",
                    str(bp),
                    added,
                    removed,
                    changed,
                    unchanged,
                    target_dir=target_dir,
                    changed_only=changed_only,
                )
                console.print(f"[green]Report exported:[/green] {out}")

    if scan_data and profile.get("auto_export", False):
        metadata = dict(scan_data["metadata"])
        metadata["profile_name"] = name
        json_path, csv_path, txt_path = export_scan_bundle(scan_data["results"], metadata, f"profile_{name}")
        console.print(Panel.fit(
            f"[bold green]Auto Export Complete[/bold green]\nJSON: {json_path}\nCSV:  {csv_path}\nTXT:  {txt_path}",
            border_style="green"
        ))

    profiles[name]["last_run_at"] = pretty_dt()
    profiles[name]["last_run_file_count"] = scan_data["metadata"]["file_count"] if scan_data else 0
    profiles[name]["last_run_changed_count"] = changed_count
    save_profiles(profiles)

    wait_for_enter()


def watch_profile():
    show_header("Watch Profile")
    profiles = load_profiles()
    if not profiles:
        console.print(Panel.fit("No saved profiles.", border_style="yellow"))
        wait_for_enter()
        return
    list_profiles_table(profiles)
    name = Prompt.ask("Enter profile name to watch").strip()
    if name not in profiles:
        console.print("[red]Profile not found.[/red]")
        wait_for_enter()
        return

    profile = profiles[name]
    root_path = Path(profile["path"]).expanduser().resolve()
    algo_name = resolve_algorithm(profile.get("algorithm_preset", profile.get("algorithm", "sha256")))
    extensions = set(profile.get("extensions", []))
    excluded_dirs = profile.get("exclude_dirs", [])
    include_patterns = profile.get("include_patterns", [])
    exclude_patterns = profile.get("exclude_patterns", [])
    incremental = profile.get("incremental", True)
    auto_export = profile.get("auto_export", False)
    watch_log_enabled = profile.get("watch_log", True)
    baseline_path = profile.get("baseline_path", "")
    thresholds = profile.get("alert_thresholds", {})
    report_on_change_only = profile.get("report_on_change_only", True)
    report_mode = profile.get("report_mode", "full")

    if not root_path.exists() or not root_path.is_dir():
        console.print(f"[red]Profile path invalid:[/red] {root_path}")
        wait_for_enter()
        return

    interval = IntPrompt.ask("Watch interval in seconds", default=30)
    export_each_cycle = Confirm.ask("Export JSON/CSV/TXT each cycle?", default=auto_export)
    verbose_mode = Confirm.ask("Verbose watch output?", default=True)
    compare_to_baseline = bool(baseline_path and Path(baseline_path).expanduser().resolve().exists())

    baseline_results = None
    if compare_to_baseline:
        _, baseline_results = load_json_results(Path(baseline_path).expanduser().resolve())

    clear_screen()
    console.print(Panel.fit(
        f"[bold green]Watch Mode Started[/bold green]\nProfile: {name}\nPath: {root_path}\nInterval: {interval}s\nLogging: {watch_log_enabled}\nBaseline linked: {compare_to_baseline}\nVerbose: {verbose_mode}\nStop with Ctrl+C",
        border_style="green"
    ))

    previous_results = None
    cycle = 0

    try:
        while True:
            cycle += 1
            if verbose_mode:
                console.print(f"\n[bold cyan]Watch cycle {cycle} started at {pretty_dt()}[/bold cyan]")

            scan_data = run_scan_config(
                root_path,
                algo_name,
                extensions,
                incremental,
                show_output=False,
                excluded_dirs=excluded_dirs,
                include_patterns=include_patterns,
                exclude_patterns=exclude_patterns,
            )

            if scan_data is None:
                console.print("[yellow]No matching files found in this cycle.[/yellow]")
            else:
                results = scan_data["results"]
                metadata = dict(scan_data["metadata"])
                metadata["profile_name"] = name

                if verbose_mode:
                    console.print(Panel.fit(
                        f"[bold green]Cycle {cycle} Complete[/bold green]\nFiles: {len(results)}\nCache Hits: {metadata.get('cache_hits', 0)}\nHashed Fresh: {metadata.get('fresh_hashed', 0)}\nElapsed: {metadata.get('elapsed_seconds', 0):.2f}s",
                        border_style="green"
                    ))

                added, removed, changed, unchanged = [], [], [], []
                if previous_results is not None:
                    added, removed, changed, unchanged = compare_scans(previous_results, results)
                    if verbose_mode:
                        display_comparison(added, removed, changed, unchanged, title=f"Watch Change Summary - Cycle {cycle}")
                    else:
                        console.print(
                            f"[cyan]Cycle {cycle}:[/cyan] "
                            f"added={len(added)} removed={len(removed)} changed={len(changed)} unchanged={len(unchanged)}"
                        )
                else:
                    if verbose_mode:
                        console.print("[yellow]No previous cycle to compare against yet.[/yellow]")
                        baseline_summary = {}
                should_report = False

                if baseline_results is not None:
                    b_added, b_removed, b_changed, b_unchanged = compare_scans(baseline_results, results)
                    baseline_summary = {
                        "added": len(b_added),
                        "removed": len(b_removed),
                        "changed": len(b_changed),
                        "unchanged": len(b_unchanged),
                    }

                    if verbose_mode:
                        console.print(Panel.fit(
                            f"[bold cyan]Baseline Drift[/bold cyan]\nAdded: {len(b_added)}\nRemoved: {len(b_removed)}\nChanged: {len(b_changed)}",
                            border_style="cyan"
                        ))
                    else:
                        console.print(
                            f"[magenta]Baseline:[/magenta] "
                            f"added={len(b_added)} removed={len(b_removed)} changed={len(b_changed)}"
                        )

                    display_alerts(evaluate_alerts(len(b_added), len(b_removed), len(b_changed), thresholds))

                    if report_on_change_only:
                        should_report = any([len(b_added), len(b_removed), len(b_changed)])
                    else:
                        should_report = True

                    if should_report:
                        target_dir = default_profile_report_dir(name)
                        changed_only = report_mode == "changed_only"
                        out = export_change_report(
                            f"watch_{name}_cycle_{cycle}",
                            baseline_path,
                            b_added,
                            b_removed,
                            b_changed,
                            b_unchanged,
                            extra_meta={"cycle": cycle, "profile": name},
                            target_dir=target_dir,
                            changed_only=changed_only,
                        )
                        console.print(f"[green]Drift report exported:[/green] {out}")

                if watch_log_enabled:
                    log_path = append_watch_log(name, cycle, metadata, added, removed, changed, unchanged, baseline_summary)
                    if verbose_mode:
                        console.print(f"[green]Watch log updated:[/green] {log_path}")

                if export_each_cycle:
                    json_path, _, _ = export_scan_bundle(results, metadata, f"watch_{name}_cycle_{cycle}")
                    console.print(f"[green]Cycle export complete:[/green] {json_path}")

                previous_results = results

            console.print(f"[cyan]Sleeping for {interval} second(s)...[/cyan]")
            time.sleep(interval)

    except KeyboardInterrupt:
        console.print("\n[bold yellow]Watch mode stopped by user.[/bold yellow]")
        wait_for_enter()


def view_watch_history():
    show_header("Watch History")
    profiles = load_profiles()
    if profiles:
        list_profiles_table(profiles)
    name = Prompt.ask("Enter profile name for watch history").strip()
    log_path, records = load_watch_log(name)
    console.print(f"[cyan]Log file:[/cyan] {log_path}")
    display_watch_log(records, title=f"Watch History - {name}")
    wait_for_enter()


def profiles_menu():
    while True:
        show_header("Profiles Menu")
        console.print(Panel.fit(
            "[bold green]Profiles Menu[/bold green]\n"
            "1. Profile dashboard\n"
            "2. List profiles\n"
            "3. Filter profiles by tag\n"
            "4. Add profile\n"
            "5. Edit profile\n"
            "6. Clone profile\n"
            "7. Delete profile\n"
            "8. Run profile now\n"
            "9. Watch profile\n"
            "10. View watch history\n"
            "0. Back",
            border_style="green"
        ))
        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "0"], default="1")
        if choice == "1":
            profile_dashboard()
        elif choice == "2":
            show_header("Saved Profiles")
            list_profiles_table(load_profiles())
            wait_for_enter()
        elif choice == "3":
            filter_profiles_by_tag()
        elif choice == "4":
            add_profile()
        elif choice == "5":
            edit_profile()
        elif choice == "6":
            clone_profile()
        elif choice == "7":
            delete_profile()
        elif choice == "8":
            run_profile_scan()
        elif choice == "9":
            watch_profile()
        elif choice == "10":
            view_watch_history()
        else:
            break


def baselines_menu():
    while True:
        show_header("Baselines Menu")
        console.print(Panel.fit(
            "[bold green]Baselines Menu[/bold green]\n"
            "1. List baselines\n"
            "2. Save current scan as baseline\n"
            "3. Compare last scan to baseline\n"
            "4. Bookmark last baseline drift\n"
            "5. Delete a baseline\n"
            "0. Back",
            border_style="green"
        ))
        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "0"], default="1")
        if choice == "1":
            show_header("Baselines")
            list_file_group(list_baselines(), "Baselines")
            wait_for_enter()
        elif choice == "2":
            save_current_scan_as_baseline()
        elif choice == "3":
            compare_last_scan_to_baseline()
        elif choice == "4":
            bookmark_last_baseline_drift()
        elif choice == "5":
            manage_file_collection_menu("Baselines", list_baselines)
        else:
            break


def manifests_menu():
    while True:
        show_header("Manifest Manager")
        console.print(Panel.fit(
            "[bold green]Manifest Manager[/bold green]\n"
            "1. List manifests\n"
            "2. Save current scan as manifest\n"
            "3. Verify last scan against manifest\n"
            "4. Verify single file against manifest\n"
            "5. Delete a manifest\n"
            "0. Back",
            border_style="green"
        ))
        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "5", "0"], default="1")
        if choice == "1":
            show_header("Manifests")
            list_file_group(list_manifests(), "Manifests")
            wait_for_enter()
        elif choice == "2":
            save_current_scan_as_manifest()
        elif choice == "3":
            verify_against_previous_manifest()
        elif choice == "4":
            verify_single_file()
        elif choice == "5":
            manage_file_collection_menu("Manifests", list_manifests)
        else:
            break


def bookmarks_menu():
    while True:
        show_header("Bookmarks Menu")
        console.print(Panel.fit(
            "[bold green]Bookmarks Menu[/bold green]\n"
            "1. List bookmark files\n"
            "2. Delete a bookmark file\n"
            "0. Back",
            border_style="green"
        ))
        choice = Prompt.ask("Select option", choices=["1", "2", "0"], default="1")
        if choice == "1":
            show_header("Bookmarks")
            list_file_group(list_bookmarks(), "Bookmarks")
            wait_for_enter()
        elif choice == "2":
            manage_file_collection_menu("Bookmarks", list_bookmarks)
        else:
            break


def reports_menu():
    while True:
        show_header("Reports Menu")
        console.print(Panel.fit(
            "[bold green]Reports Menu[/bold green]\n"
            "1. List reports\n"
            "2. Preview a report\n"
            "3. Export last diff report\n"
            "4. Delete a report\n"
            "0. Back",
            border_style="green"
        ))
        choice = Prompt.ask("Select option", choices=["1", "2", "3", "4", "0"], default="1")
        if choice == "1":
            show_header("Reports")
            list_file_group(list_reports(), "Reports")
            wait_for_enter()
        elif choice == "2":
            show_header("Reports")
            files = list_reports()
            list_file_group(files, "Reports")
            if files:
                path_input = Prompt.ask("Enter exact report path to preview")
                p = Path(path_input).expanduser().resolve()
                if p.exists():
                    show_header("Report Preview")
                    preview_json_file(p)
                    wait_for_enter()
        elif choice == "3":
            show_header("Export Last Diff Report")
            if not last_diff_result:
                console.print("[yellow]No diff result available yet.[/yellow]")
            else:
                changed_only = Confirm.ask("Changed-only report?", default=False)
                out = export_change_report(
                    "last_diff",
                    last_diff_result["source"],
                    last_diff_result["added"],
                    last_diff_result["removed"],
                    last_diff_result["changed"],
                    last_diff_result["unchanged"],
                    changed_only=changed_only,
                )
                console.print(f"[green]Report exported:[/green] {out}")
            wait_for_enter()
        elif choice == "4":
            manage_file_collection_menu("Reports", list_reports)
        else:
            break


def main_menu():
    while True:
        show_header(f"{APP_TITLE} {APP_VERSION}")
        console.print(Panel.fit(
            "1. Quick actions\n"
            "2. Run new scan\n"
            "3. Show displayed results\n"
            "4. Show displayed results (paged)\n"
            "5. Search in last scan results\n"
            "6. Sort displayed results\n"
            "7. Reset displayed view to full scan\n"
            "8. Show duplicate hashes\n"
            "9. Review duplicates\n"
            "10. Show largest files\n"
            "11. Export displayed results\n"
            "12. Compare last scan with previous JSON scan\n"
            "13. Compare last scan to baseline\n"
            "14. Verify last scan against manifest\n"
            "15. Verify single file against manifest\n"
            "16. Show last scan errors\n"
            "17. Show session dashboard\n"
            "18. Show extension summary\n"
            "19. Show folder summary\n"
            "20. Profiles menu\n"
            "21. Baselines menu\n"
            "22. Manifest manager\n"
            "23. Bookmarks menu\n"
            "24. Reports menu\n"
            "25. UI settings\n"
            "26. Maintenance\n"
            "27. About\n"
            "0. Exit",
            border_style="green"
        ))

        choice = Prompt.ask("Select option", choices=[str(i) for i in range(28)], default="1")

        if choice == "1":
            quick_actions_menu()
        elif choice == "2":
            run_scan()
        elif choice == "3":
            show_last_results()
        elif choice == "4":
            show_last_results_paged()
        elif choice == "5":
            search_last_results_menu()
        elif choice == "6":
            sort_last_results_menu()
        elif choice == "7":
            reset_filtered_view()
        elif choice == "8":
            show_last_duplicates()
        elif choice == "9":
            review_duplicates_helper()
        elif choice == "10":
            show_largest_files()
        elif choice == "11":
            export_last_scan()
        elif choice == "12":
            compare_with_previous()
        elif choice == "13":
            compare_last_scan_to_baseline()
        elif choice == "14":
            verify_against_previous_manifest()
        elif choice == "15":
            verify_single_file()
        elif choice == "16":
            show_last_errors()
        elif choice == "17":
            show_header("Session Dashboard")
            print_dashboard()
            wait_for_enter()
        elif choice == "18":
            show_extension_summary()
        elif choice == "19":
            show_folder_summary()
        elif choice == "20":
            profiles_menu()
        elif choice == "21":
            baselines_menu()
        elif choice == "22":
            manifests_menu()
        elif choice == "23":
            bookmarks_menu()
        elif choice == "24":
            reports_menu()
        elif choice == "25":
            ui_settings_menu()
        elif choice == "26":
            maintenance_menu()
        elif choice == "27":
            about_menu()
        else:
            clear_screen()
            console.print("[bold green]Goodbye.[/bold green]")
            break


if __name__ == "__main__":
    try:
        main_menu()
    except KeyboardInterrupt:
        clear_screen()
        console.print("[bold yellow]Exited by user.[/bold yellow]")