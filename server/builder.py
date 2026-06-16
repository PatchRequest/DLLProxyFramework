"""Build pipeline — generate + compile proxy DLL from uploaded original."""

import os
import shutil
import subprocess
import sys
from pathlib import Path

FRAMEWORK_ROOT = Path(__file__).resolve().parent.parent
BUILDS_DIR = Path(__file__).resolve().parent / "builds"


def _find_compiler() -> str | None:
    """Detect available compiler."""
    for cmd in ["cl", "gcc", "x86_64-w64-mingw32-gcc"]:
        if shutil.which(cmd):
            return "msvc" if cmd == "cl" else "gcc"
    return None


def build_proxy(
    build_id: str,
    original_dll_path: Path,
    dll_name: str,
    arch: str,
    compiler: str | None = None,
    payload_dll_path: Path | None = None,
    payload_export: str | None = None,
) -> Path:
    """
    Generate and compile a proxy DLL.

    Returns path to the compiled proxy DLL.
    Raises RuntimeError on failure.
    """
    if compiler is None:
        compiler = _find_compiler()
    if compiler is None:
        raise RuntimeError("No compiler found (need cl.exe or gcc on PATH)")

    build_dir = BUILDS_DIR / build_id
    gen_dir = build_dir / "gen"
    gen_dir.mkdir(parents=True, exist_ok=True)

    # ── 1. Generate proxy source ──
    gen_script = str(FRAMEWORK_ROOT / "generate.py")
    cmd = [
        sys.executable, gen_script, str(original_dll_path),
        "--payload", "--embed", "--block",
        "--compiler", compiler,
        "--arch", arch,
        "-o", str(gen_dir),
    ]
    if payload_dll_path:
        cmd.extend(["--payload-dll", str(payload_dll_path)])
    if payload_export:
        cmd.extend(["--payload-export", payload_export])

    result = subprocess.run(cmd, capture_output=True, text=True, cwd=str(FRAMEWORK_ROOT))
    if result.returncode != 0:
        raise RuntimeError(f"generate.py failed: {result.stderr}")

    # ── 1b. Inject proof payload (only when no binary payload is embedded) ──
    if not payload_dll_path:
        _inject_payload(gen_dir)

    # ── 2. Compile ──
    proxy_dll_name = dll_name
    if compiler == "msvc":
        _compile_msvc(gen_dir, proxy_dll_name)
    else:
        _compile_gcc(gen_dir, proxy_dll_name)

    compiled = gen_dir / proxy_dll_name
    if not compiled.exists():
        raise RuntimeError(f"Compiled DLL not found at {compiled}")

    # Move to build root
    final = build_dir / proxy_dll_name
    shutil.move(str(compiled), str(final))

    return final


PROOF_PAYLOAD = r"""#include "payload.h"
#include <stdio.h>

DWORD WINAPI payload_main(LPVOID lpParam) {
    (void)lpParam;
    FILE *f = fopen("proof.txt", "w");
    if (f) {
        fprintf(f, "payload executed in PID %lu\n", GetCurrentProcessId());
        fclose(f);
    }
    return 0;
}
"""


def _inject_payload(gen_dir: Path):
    """Replace the template payload.c with one that writes proof.txt."""
    payload_c = gen_dir / "payload.c"
    if payload_c.exists():
        payload_c.write_text(PROOF_PAYLOAD, encoding="utf-8")


def _compile_msvc(gen_dir: Path, dll_name: str):
    """Compile with MSVC using the generated build_msvc.bat."""
    bat = gen_dir / "build_msvc.bat"
    if not bat.exists():
        raise RuntimeError("build_msvc.bat not found in generated output")

    result = subprocess.run(
        ["cmd", "/c", str(bat)],
        capture_output=True, text=True,
        cwd=str(gen_dir),
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"MSVC build failed:\n{result.stdout}\n{result.stderr}")


def _compile_gcc(gen_dir: Path, dll_name: str):
    """Compile with MinGW using the generated Makefile."""
    makefile = gen_dir / "Makefile"
    if not makefile.exists():
        raise RuntimeError("Makefile not found in generated output")

    make_cmd = "mingw32-make" if shutil.which("mingw32-make") else "make"
    result = subprocess.run(
        [make_cmd],
        capture_output=True, text=True,
        cwd=str(gen_dir),
        timeout=120,
    )
    if result.returncode != 0:
        raise RuntimeError(f"GCC build failed:\n{result.stdout}\n{result.stderr}")
