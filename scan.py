#!/usr/bin/env python3
"""
DLL Sideload Scanner — discover per-machine sideloading targets.

Scans installed software and builds a ranked catalog of EXE+DLL pairs
that can be packaged for sideloading.  Each result is a deployable fact:
copy the signed EXE, bundle our proxy DLL, drop the folder anywhere.

Usage:
  python scan.py                          # scan all drives
  python scan.py C:\\Users D:\\Apps          # specific paths
  python scan.py --signed-only --json     # JSON, signed only
  python scan.py -o targets.json          # save for package.py
"""

import argparse
import json
import sys
from pathlib import Path

from scanner import DLLScanner, ScanResult, SideloadTarget


# ── Display ───────────────────────────────────────────────────

_VECTOR_TAG = {"replace": "RPL", "search_order": "SRO", "phantom": "PHT"}


def print_table(result: ScanResult):
    candidates = result.candidates

    by_vector = {}
    for c in candidates:
        by_vector.setdefault(c.vector, []).append(c)

    print(f"\n{'=' * 90}")
    print(f" DLL Sideload Scanner - Targets")
    print(f"{'=' * 90}")
    print(f" Scanned:  {result.total_exes} executables in {result.elapsed_sec}s")
    print(f" Found:    {len(candidates)} targets "
          f"({len(by_vector.get('replace', []))} replace, "
          f"{len(by_vector.get('search_order', []))} search-order, "
          f"{len(by_vector.get('phantom', []))} phantom)")
    print(f" Errors:   {result.errors}")
    print(f"{'=' * 90}")

    # Print top candidates sorted by score
    print(f"\n {'#':>4}  {'S':>2} {'VEC':3} {'IMP':3} {'ARC':3}  "
          f"{'DLL':<28} {'COMP':>4}  EXE")
    print(f" {'-'*4}  {'-'*2} {'-'*3} {'-'*3} {'-'*3}  "
          f"{'-'*28} {'-'*4}  {'-'*35}")

    for i, c in enumerate(candidates):
        sig = "S" if c.exe_signed else " "
        vec = _VECTOR_TAG[c.vector]
        imp = "D" if c.import_type == "delayed" else " "
        comp = len(c.companion_dlls)
        print(f" {i:>4}  {sig:>2} {vec:3} {imp:>3} {c.arch:3}  "
              f"{c.dll_name:<28} {comp:>4}  {c.exe_path}")

    print()


def print_detail(candidate: SideloadTarget, index: int):
    """Print detailed info for a single target."""
    c = candidate
    print(f"\n--- Target #{index} (score {c.score}) ---")
    print(f"  EXE:        {c.exe_path}")
    print(f"  DLL:        {c.dll_name}")
    print(f"  Vector:     {c.vector}")
    print(f"  Import:     {c.import_type}")
    print(f"  Arch:       {c.arch}")
    print(f"  Signed:     {'yes' if c.exe_signed else 'no'}")
    if c.source_dll:
        print(f"  Source DLL: {c.source_dll}")
    if c.companion_dlls:
        print(f"  Companions: {len(c.companion_dlls)}")
        for comp in c.companion_dlls[:10]:
            print(f"              {comp}")
        if len(c.companion_dlls) > 10:
            print(f"              ... and {len(c.companion_dlls) - 10} more")
    else:
        print(f"  Companions: 0 (clean 2-file package)")
    print()


# ── CLI ───────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Scan for DLL sideloading targets",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "paths", nargs="*", default=None,
        help="Directories to scan (default: all drives)",
    )
    parser.add_argument(
        "-t", "--threads", type=int, default=8,
        help="Worker threads (default: 8)",
    )
    parser.add_argument(
        "--signed-only", action="store_true",
        help="Only report signed host EXEs",
    )
    parser.add_argument(
        "--skip-windows", action="store_true",
        help="Skip the Windows directory tree",
    )
    parser.add_argument(
        "--min-score", type=int, default=0,
        help="Minimum score threshold",
    )
    parser.add_argument(
        "--vector", choices=["replace", "search_order", "phantom"],
        help="Only show targets with this vector",
    )
    parser.add_argument(
        "--max-companions", type=int, default=None,
        help="Max companion DLLs (0 = only clean 2-file packages)",
    )
    parser.add_argument(
        "-o", "--output", type=str, default=None,
        help="Save JSON results to file (use with package.py)",
    )
    parser.add_argument(
        "--json", action="store_true",
        help="Print JSON to stdout",
    )
    parser.add_argument(
        "-q", "--quiet", action="store_true",
        help="Suppress progress messages",
    )
    parser.add_argument(
        "--top", type=int, default=None,
        help="Only show top N results",
    )
    args = parser.parse_args()

    scanner = DLLScanner(
        threads=args.threads,
        progress=not args.quiet,
        skip_windows=args.skip_windows,
    )

    result = scanner.scan(scan_paths=args.paths or None)

    # ── Filters ──
    if args.signed_only:
        result.candidates = [c for c in result.candidates if c.exe_signed]
    if args.vector:
        result.candidates = [c for c in result.candidates if c.vector == args.vector]
    if args.min_score > 0:
        result.candidates = [c for c in result.candidates if c.score >= args.min_score]
    if args.max_companions is not None:
        result.candidates = [c for c in result.candidates
                             if len(c.companion_dlls) <= args.max_companions]
    if args.top:
        result.candidates = result.candidates[:args.top]

    result.total_candidates = len(result.candidates)

    # ── Output ──
    if args.json:
        print(json.dumps(result.to_dict(), indent=2))
    else:
        print_table(result)

    if args.output:
        with open(args.output, "w", encoding="utf-8") as f:
            json.dump(result.to_dict(), f, indent=2)
        if not args.quiet:
            print(f"[*] Saved {len(result.candidates)} targets to {args.output}")
            print(f"[*] Use: python package.py {args.output} --pick 0")


if __name__ == "__main__":
    main()
