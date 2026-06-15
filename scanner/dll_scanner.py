"""
DLL Sideload Scanner — build a catalog of per-machine sideloading targets.

Scans installed executables and catalogs every EXE+DLL pair usable for
sideloading.  The output is a ranked pick-list: copy the signed EXE, bundle
our proxy DLL, deploy as a self-contained package.

Vectors detected:
  replace       DLL already beside the EXE — copy both, swap DLL with proxy
  search_order  DLL in System32, absent from app dir — EXE will load from app
                dir first if we place our proxy there
  phantom       DLL imported (delayed) but missing from disk — any DLL we drop
                with that name gets loaded
"""

import os
import string
import tempfile
import time
import winreg
from dataclasses import dataclass, field, asdict
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed

import pefile


# ── Data ──────────────────────────────────────────────────────

@dataclass
class SideloadTarget:
    exe_path: str
    dll_name: str
    vector: str                 # "replace" | "search_order" | "phantom"
    import_type: str            # "static" | "delayed"
    arch: str                   # "x86" | "x64"
    exe_signed: bool
    source_dll: str             # real DLL path for proxy generation ("" for phantom)
    companion_dlls: list[str] = field(default_factory=list)
    score: int = 0


@dataclass
class ScanResult:
    scan_paths: list[str]
    total_exes: int
    total_candidates: int
    candidates: list[SideloadTarget] = field(default_factory=list)
    errors: int = 0
    elapsed_sec: float = 0.0

    def to_dict(self) -> dict:
        return asdict(self)


# ── Registry / system info ────────────────────────────────────

def get_known_dlls() -> set[str]:
    """KnownDLLs are always loaded from System32 — cannot be hijacked."""
    known: set[str] = set()
    views = [winreg.KEY_READ | winreg.KEY_WOW64_64KEY,
             winreg.KEY_READ | winreg.KEY_WOW64_32KEY]
    for access in views:
        try:
            key = winreg.OpenKey(
                winreg.HKEY_LOCAL_MACHINE,
                r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
                0, access,
            )
            i = 0
            while True:
                try:
                    _, value, _ = winreg.EnumValue(key, i)
                    if isinstance(value, str) and value.lower().endswith(".dll"):
                        known.add(value.lower())
                    i += 1
                except OSError:
                    break
            winreg.CloseKey(key)
        except OSError:
            pass
    return known


def build_system_dll_index() -> dict[str, str]:
    """Map lowercase DLL filename -> full path for System32/SysWOW64/Windows."""
    windir = Path(os.environ.get("WINDIR", r"C:\Windows"))
    dirs = [windir / "System32", windir / "SysWOW64",
            windir / "System", windir]
    index: dict[str, str] = {}
    for d in dirs:
        if not d.is_dir():
            continue
        try:
            for f in d.iterdir():
                if f.suffix.lower() == ".dll":
                    index.setdefault(f.name.lower(), str(f))
        except PermissionError:
            pass
    return index


def get_path_dirs() -> list[str]:
    raw = os.environ.get("PATH", "")
    return [d for d in raw.split(";") if d and os.path.isdir(d)]


def get_all_drives() -> list[str]:
    drives = []
    for letter in string.ascii_uppercase:
        root = f"{letter}:\\"
        if os.path.isdir(root):
            drives.append(root)
    return drives


# ── Filters ───────────────────────────────────────────────────

def _is_api_set(name: str) -> bool:
    return name.startswith("api-ms-") or name.startswith("ext-ms-")

# Mapped by the kernel before normal DLL search runs.
_LOADER_IMPLICIT = frozenset({"ntdll.dll"})

_SKIP_DIRS = frozenset({
    "$recycle.bin", "$windows.~bt", "$windows.~ws",
    "winsxs", "servicing", "installer", "assembly",
    "microsoft.net", "immersivecontrolpanel",
    "node_modules", "__pycache__", ".git", ".hg",
    ".venv", "venv", "site-packages",
})


# ── Scoring ───────────────────────────────────────────────────

# DLLs that are common sideloading targets — boring names nobody looks at twice.
_STEALTH_DLLS = frozenset({
    "version.dll", "winmm.dll", "dbghelp.dll", "dwmapi.dll",
    "uxtheme.dll", "propsys.dll", "profapi.dll", "cryptsp.dll",
    "cryptbase.dll", "wtsapi32.dll", "msimg32.dll", "iphlpapi.dll",
    "userenv.dll", "dwrite.dll", "mswsock.dll", "secur32.dll",
    "netapi32.dll", "winhttp.dll", "urlmon.dll", "dhcpcsvc.dll",
    "crypt32.dll", "wintrust.dll", "ncrypt.dll", "dpapi.dll",
    "coloradapterclient.dll", "textinputframework.dll",
})


def _compute_score(
    vector: str,
    import_type: str,
    signed: bool,
    companion_count: int,
    dll_lower: str,
) -> int:
    s = 0

    # Signed EXE — process looks legitimate in logs / EDR
    if signed:
        s += 4

    # Vector reliability
    if vector == "replace":
        s += 3          # proven: the EXE already loads this DLL from here
    elif vector == "search_order":
        s += 2          # standard mechanism, very reliable
    else:  # phantom
        s += 1          # works, but unusual import might draw attention

    # Stealth DLL name — well-known, boring, nobody blinks
    if dll_lower in _STEALTH_DLLS:
        s += 2

    # Fewer companion DLLs = simpler package
    if companion_count == 0:
        s += 2          # perfect: just EXE + our proxy
    elif companion_count <= 3:
        s += 1

    # Delayed imports are safer (loaded on demand, less crash risk)
    if import_type == "delayed":
        s += 1

    return s


# ── Filesystem walk ───────────────────────────────────────────

def find_executables(scan_paths: list[str], skip_windows: bool = False) -> list[str]:
    windir = os.environ.get("WINDIR", r"C:\Windows").lower()
    exes: list[str] = []
    for root in scan_paths:
        for dirpath, dirnames, filenames in os.walk(root, topdown=True):
            if skip_windows and dirpath.lower().startswith(windir):
                dirnames.clear()
                continue
            dirnames[:] = [
                d for d in dirnames
                if d.lower() not in _SKIP_DIRS and not d.startswith("$")
            ]
            for f in filenames:
                if f.lower().endswith(".exe"):
                    exes.append(os.path.join(dirpath, f))
    return exes


# ── Per-EXE analysis ─────────────────────────────────────────

def _collect_imports(pe: pefile.PE) -> list[tuple[str, str]]:
    """(dll_name, "static"|"delayed") for every import."""
    imports: list[tuple[str, str]] = []
    if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_IMPORT:
            if entry.dll:
                imports.append((entry.dll.decode("utf-8", errors="replace"), "static"))
    if hasattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT"):
        for entry in pe.DIRECTORY_ENTRY_DELAY_IMPORT:
            if entry.dll:
                imports.append((entry.dll.decode("utf-8", errors="replace"), "delayed"))
    return imports


def analyze_exe(
    exe_path: str,
    known_dlls: set[str],
    system_dll_index: dict[str, str],
    path_dirs: list[str],
) -> list[SideloadTarget]:
    try:
        pe = pefile.PE(exe_path, fast_load=True)
        pe.parse_data_directories(directories=[
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT"],
            pefile.DIRECTORY_ENTRY["IMAGE_DIRECTORY_ENTRY_SECURITY"],
        ])
    except Exception:
        return []

    arch = "x64" if pe.FILE_HEADER.Machine == 0x8664 else "x86"
    signed = (pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress != 0
              and pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size != 0)
    imports = _collect_imports(pe)
    pe.close()

    exe_dir = os.path.dirname(exe_path)

    # ── Build local DLL map (imports that exist beside the EXE) ──
    local_dlls: dict[str, str] = {}       # dll_lower -> full path
    for dll_name, _ in imports:
        dll_lower = dll_name.lower()
        local_path = os.path.join(exe_dir, dll_name)
        if os.path.isfile(local_path):
            local_dlls[dll_lower] = local_path

    candidates: list[SideloadTarget] = []
    seen: set[str] = set()

    for dll_name, import_type in imports:
        dll_lower = dll_name.lower()
        if dll_lower in seen:
            continue
        seen.add(dll_lower)

        # ── Skip unhijackable ──
        if _is_api_set(dll_lower):
            continue
        if dll_lower in known_dlls or dll_lower in _LOADER_IMPLICIT:
            continue

        # ── Classify vector ──
        if dll_lower in local_dlls:
            vector = "replace"
            source_dll = local_dlls[dll_lower]
        else:
            source_dll = system_dll_index.get(dll_lower, "")
            if not source_dll:
                for d in path_dirs:
                    p = os.path.join(d, dll_name)
                    if os.path.isfile(p):
                        source_dll = p
                        break
            if source_dll:
                vector = "search_order"
            else:
                vector = "phantom"

        # Phantom + static import = the EXE cannot start without this DLL.
        # Either it's truly broken or we're missing a resolution path. Skip.
        if vector == "phantom" and import_type == "static":
            continue

        # ── Companion DLLs: other local DLLs the EXE needs (we must copy them too) ──
        companions = [name for name in local_dlls if name != dll_lower]

        score = _compute_score(vector, import_type, signed, len(companions), dll_lower)

        candidates.append(SideloadTarget(
            exe_path=exe_path,
            dll_name=dll_name,
            vector=vector,
            import_type=import_type,
            arch=arch,
            exe_signed=signed,
            source_dll=source_dll,
            companion_dlls=companions,
            score=score,
        ))

    return candidates


# ── Scanner ───────────────────────────────────────────────────

class DLLScanner:
    def __init__(self, threads: int = 8, progress: bool = True, skip_windows: bool = False):
        self.threads = threads
        self.progress = progress
        self.skip_windows = skip_windows

    def _log(self, msg: str):
        if self.progress:
            print(msg, flush=True)

    def scan(self, scan_paths: list[str] | None = None) -> ScanResult:
        t0 = time.time()

        if scan_paths is None:
            scan_paths = get_all_drives()

        known_dlls = get_known_dlls()
        system_idx = build_system_dll_index()
        path_dirs = get_path_dirs()

        self._log(f"[*] KnownDLLs:       {len(known_dlls)} entries")
        self._log(f"[*] System DLL index: {len(system_idx)} DLLs")
        self._log(f"[*] Scan paths:      {', '.join(scan_paths)}")
        if self.skip_windows:
            self._log("[*] Skipping Windows directory")

        exes = find_executables(scan_paths, skip_windows=self.skip_windows)
        self._log(f"[*] Found {len(exes)} executables")

        all_candidates: list[SideloadTarget] = []
        errors = 0
        done = 0

        with ThreadPoolExecutor(max_workers=self.threads) as pool:
            futures = {
                pool.submit(analyze_exe, exe, known_dlls, system_idx, path_dirs): exe
                for exe in exes
            }
            for future in as_completed(futures):
                done += 1
                if self.progress and done % 500 == 0:
                    print(f"    [{done}/{len(exes)}] ...", flush=True)
                try:
                    all_candidates.extend(future.result())
                except Exception:
                    errors += 1

        all_candidates.sort(key=lambda c: c.score, reverse=True)

        return ScanResult(
            scan_paths=scan_paths,
            total_exes=len(exes),
            total_candidates=len(all_candidates),
            candidates=all_candidates,
            errors=errors,
            elapsed_sec=round(time.time() - t0, 2),
        )
