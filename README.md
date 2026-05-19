# DLL Proxy Framework

Generate proxy DLL projects for DLL sideloading and hijacking research. Point it at a DLL, get a ready-to-compile project that mirrors all exports and forwards them to the original — with a slot for your payload code.

## Workflow

1. Pick a target DLL (e.g. from [hijacklibs.net](https://hijacklibs.net))
2. Run the generator
3. Edit `payload.c` with your loader code
4. Build with MSVC or MinGW
5. Deploy

```
python generate.py C:\Windows\System32\version.dll --payload --embed --block
```

## Features

- **Export mirroring** — Analyzes PE export table and generates assembly trampolines (`jmp [ptr]`) that transparently forward all calls to the original DLL. Handles named exports, ordinal-only exports, forwarded exports, and C++ mangled names.
- **Embed mode** (`--embed`) — Bakes the original DLL as a PE resource. At load time it extracts to `%TEMP%` and loads it. No need to ship a second DLL file.
- **Payload thread** (`--payload`) — Generates a `payload.c` template. Your code runs in a separate thread after all exports are resolved.
- **Block mode** (`--block`) — Suspends the main thread so the process can't exit before your payload finishes. Uses a two-layer approach: primary suspend + atexit fallback. No loader lock issues.
- **Dual compiler support** — Generates both MSVC (`.asm` + `build_msvc.bat`) and MinGW (`.S` + `Makefile`) build files.
- **Both architectures** — x86 and x64, auto-detected from the input DLL.

## Installation

```
pip install -r requirements.txt
```

Requires Python 3.10+ and either Visual Studio (MSVC) or MinGW-w64 for building.

## Usage

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

### Examples

Minimal proxy (no payload, load original from disk):
```
python generate.py C:\Windows\System32\version.dll
```

Full sideloading setup with embedded DLL and blocking payload:
```
python generate.py C:\Windows\System32\version.dll --payload --embed --block
```

MSVC-only, verbose:
```
python generate.py C:\Windows\System32\dbghelp.dll --payload --compiler msvc -v
```

## Generated Project Structure

```
version_proxy/
├── proxy.c              # DllMain, function pointer table, init/cleanup
├── proxy.h              # Exported function pointer declarations
├── exports.def          # Module definition file (maps exports to trampolines)
├── trampolines.asm      # MSVC MASM — one jmp [ptr] per export
├── trampolines.S        # MinGW GAS — same, AT&T/Intel syntax
├── payload.c            # Your code goes here
├── payload.h            # Payload thread declaration
├── resource.rc          # Embedded DLL resource (--embed)
├── resource.h           # Resource IDs
├── original_version.dll # Copy of original DLL (--embed)
├── build_msvc.bat       # Build with cl.exe + ml64.exe
└── Makefile             # Build with gcc + as
```

## Building

**MSVC** — open a Developer Command Prompt:
```
cd output\version_proxy
build_msvc.bat
```

**MinGW**:
```
cd output/version_proxy
make
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

When the host process would exit immediately (e.g. printing `--help`), `--block` keeps it alive:

1. **Primary**: The payload thread suspends the main thread (after loader lock releases). Main is frozen before it can reach `main()` or `ExitProcess`. Payload runs, then calls `ExitProcess(0)`.
2. **Fallback**: If main wins the race, `atexit` handler blocks until the payload signals completion.

Both paths are deadlock-free — no loader lock involvement.

## Testing

A test suite is included that verifies all four mode combinations against `version.dll`. Requires MSVC (Developer Command Prompt).

```
cd test
run_tests.bat
```

This generates proxies, builds them, and runs a test host (`test_host.c`) that loads the proxy DLL, calls `GetFileVersionInfoSizeA`, and exits immediately. The tests verify:

| Test | Mode | Verifies |
|------|------|----------|
| 1 | `--embed --payload` | Embedded DLL extraction + export forwarding works |
| 2 | `--embed --payload --block` | Block mode keeps process alive, payload completes |
| 3 | `--payload` (no embed) | Side-by-side DLL loading + export forwarding works |
| 4 | `--payload --block` (no embed) | Block mode works without embedding |

Expected output:
```
============================================================
 DLL Proxy Framework - Test Suite
============================================================

[*] Compiling test host...
[+] test_host.exe ready

[TEST 1] --embed --payload
------------------------------------------------------------
[+] PASS: Embed forwarding works, host exited normally

[TEST 2] --embed --payload --block
------------------------------------------------------------
[+] PASS: Embed + block kept process alive, payload completed

[TEST 3] --payload (no embed, no block)
------------------------------------------------------------
[+] PASS: Non-embed forwarding works, host exited normally

[TEST 4] --payload --block (no embed)
------------------------------------------------------------
[+] PASS: Non-embed + block works, payload completed

============================================================
 Results: 4 passed, 0 failed
============================================================
```

## Non-Embed Mode

Without `--embed`, the proxy loads the original DLL from disk at runtime. Rename the original and place it alongside the proxy:

```
target_app/
├── version.dll              # Your proxy
├── original_version.dll     # The real DLL (renamed)
└── app.exe                  # Host application
```

## License

MIT
