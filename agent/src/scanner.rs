use std::collections::HashSet;
use std::path::{Path, PathBuf};

use pelite::pe64::{Pe as Pe64, PeFile as PeFile64};
use pelite::pe32::{Pe as Pe32, PeFile as PeFile32};
use pelite::FileMap;
use serde::Serialize;
use walkdir::WalkDir;
use winreg::enums::*;
use winreg::RegKey;

#[derive(Debug, Clone, Serialize)]
pub struct SideloadTarget {
    pub exe_path: String,
    pub dll_name: String,
    pub vector: String,
    pub import_type: String,
    pub arch: String,
    pub exe_signed: bool,
    pub source_dll: String,
    pub companion_dlls: Vec<String>,
    pub score: i32,
}

const STEALTH_DLLS: &[&str] = &[
    "version.dll", "winmm.dll", "dbghelp.dll", "dwmapi.dll",
    "uxtheme.dll", "propsys.dll", "profapi.dll", "cryptsp.dll",
    "cryptbase.dll", "wtsapi32.dll", "msimg32.dll", "iphlpapi.dll",
    "userenv.dll", "dwrite.dll", "mswsock.dll", "secur32.dll",
    "netapi32.dll", "winhttp.dll", "urlmon.dll", "dhcpcsvc.dll",
    "crypt32.dll", "wintrust.dll", "ncrypt.dll", "dpapi.dll",
];

const SKIP_DIRS: &[&str] = &[
    "$recycle.bin", "winsxs", "servicing", "installer", "assembly",
    "microsoft.net", "node_modules", "__pycache__", ".git",
    "site-packages",
];

pub fn get_known_dlls() -> HashSet<String> {
    let mut known = HashSet::new();
    for &hive_flag in &[KEY_WOW64_64KEY, KEY_WOW64_32KEY] {
        if let Ok(key) = RegKey::predef(HKEY_LOCAL_MACHINE).open_subkey_with_flags(
            r"SYSTEM\CurrentControlSet\Control\Session Manager\KnownDLLs",
            KEY_READ | hive_flag,
        ) {
            for val in key.enum_values().flatten() {
                let s: String = match val.1.vtype {
                    winreg::enums::RegType::REG_SZ => {
                        String::from_utf16_lossy(
                            &val.1.bytes.chunks_exact(2)
                                .map(|c| u16::from_le_bytes([c[0], c[1]]))
                                .collect::<Vec<_>>()
                        ).trim_end_matches('\0').to_string()
                    }
                    _ => continue,
                };
                let lower = s.to_lowercase();
                if lower.ends_with(".dll") {
                    known.insert(lower);
                }
            }
        }
    }
    known
}

pub fn build_system_dll_index() -> std::collections::HashMap<String, PathBuf> {
    let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
    let windir = Path::new(&windir);
    let dirs = [
        windir.join("System32"),
        windir.join("SysWOW64"),
        windir.join("System"),
        windir.to_path_buf(),
    ];

    let mut index = std::collections::HashMap::new();
    for d in &dirs {
        if let Ok(entries) = std::fs::read_dir(d) {
            for entry in entries.flatten() {
                let path = entry.path();
                if path.extension().and_then(|e| e.to_str()) == Some("dll") {
                    if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                        index.entry(name.to_lowercase()).or_insert_with(|| path.clone());
                    }
                }
            }
        }
    }
    index
}

fn is_api_set(name: &str) -> bool {
    name.starts_with("api-ms-") || name.starts_with("ext-ms-")
}

fn compute_score(vector: &str, import_type: &str, signed: bool, companion_count: usize, dll_lower: &str) -> i32 {
    let mut s: i32 = 0;
    if signed { s += 4; }
    match vector {
        "replace" => s += 3,
        "search_order" => s += 2,
        _ => s += 1,
    }
    if STEALTH_DLLS.contains(&dll_lower) { s += 2; }
    if companion_count == 0 { s += 2; } else if companion_count <= 3 { s += 1; }
    if import_type == "delayed" { s += 1; }
    s
}

struct PeInfo {
    arch: String,
    signed: bool,
    imports: Vec<(String, String)>, // (dll_name, "static"|"delayed")
}

fn parse_pe(path: &Path) -> Option<PeInfo> {
    let map = FileMap::open(path).ok()?;
    let bytes = map.as_ref();

    // Check PE signature
    if bytes.len() < 64 { return None; }
    let pe_offset = u32::from_le_bytes(bytes[60..64].try_into().ok()?) as usize;
    if bytes.len() < pe_offset + 6 { return None; }
    let machine = u16::from_le_bytes(bytes[pe_offset+4..pe_offset+6].try_into().ok()?);
    let is_64 = machine == 0x8664;

    let mut imports = Vec::new();
    let signed;

    if is_64 {
        let pe = PeFile64::from_bytes(bytes).ok()?;
        if let Ok(imp) = pe.imports() {
            for desc in imp {
                if let Ok(name) = desc.dll_name() {
                    imports.push((name.to_string(), "static".into()));
                }
            }
        }
        signed = pe.security().is_ok();
    } else {
        let pe = PeFile32::from_bytes(bytes).ok()?;
        if let Ok(imp) = pe.imports() {
            for desc in imp {
                if let Ok(name) = desc.dll_name() {
                    imports.push((name.to_string(), "static".into()));
                }
            }
        }
        signed = pe.security().is_ok();
    }

    Some(PeInfo {
        arch: if is_64 { "x64".into() } else { "x86".into() },
        signed,
        imports,
    })
}

pub fn analyze_exe(
    exe_path: &Path,
    known_dlls: &HashSet<String>,
    system_index: &std::collections::HashMap<String, PathBuf>,
) -> Vec<SideloadTarget> {
    let info = match parse_pe(exe_path) {
        Some(i) => i,
        None => return vec![],
    };

    let exe_dir = match exe_path.parent() {
        Some(d) => d,
        None => return vec![],
    };

    // Build local DLL map
    let mut local_dlls: std::collections::HashMap<String, PathBuf> = std::collections::HashMap::new();
    for (dll_name, _) in &info.imports {
        let local_path = exe_dir.join(dll_name);
        if local_path.is_file() {
            local_dlls.insert(dll_name.to_lowercase(), local_path);
        }
    }

    let mut candidates = Vec::new();
    let mut seen = HashSet::new();

    for (dll_name, import_type) in &info.imports {
        let dll_lower = dll_name.to_lowercase();
        if !seen.insert(dll_lower.clone()) { continue; }
        if is_api_set(&dll_lower) { continue; }
        if known_dlls.contains(&dll_lower) || dll_lower == "ntdll.dll" { continue; }

        let (vector, source_dll) = if local_dlls.contains_key(&dll_lower) {
            ("replace", local_dlls[&dll_lower].to_string_lossy().into_owned())
        } else if let Some(sys_path) = system_index.get(&dll_lower) {
            ("search_order", sys_path.to_string_lossy().into_owned())
        } else {
            ("phantom", String::new())
        };

        // Phantom + static = EXE can't start without it, skip
        if vector == "phantom" && import_type == "static" { continue; }

        let companions: Vec<String> = local_dlls.keys()
            .filter(|k| *k != &dll_lower)
            .cloned()
            .collect();

        let score = compute_score(vector, import_type, info.signed, companions.len(), &dll_lower);

        candidates.push(SideloadTarget {
            exe_path: exe_path.to_string_lossy().into_owned(),
            dll_name: dll_name.clone(),
            vector: vector.into(),
            import_type: import_type.clone(),
            arch: info.arch.clone(),
            exe_signed: info.signed,
            source_dll,
            companion_dlls: companions,
            score,
        });
    }

    candidates
}

pub fn find_executables(scan_paths: &[&str], skip_windows: bool) -> Vec<PathBuf> {
    let windir = std::env::var("WINDIR")
        .unwrap_or_else(|_| r"C:\Windows".into())
        .to_lowercase();

    let mut exes = Vec::new();
    for root in scan_paths {
        for entry in WalkDir::new(root)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| {
                if !e.file_type().is_dir() { return true; }
                let name = e.file_name().to_string_lossy().to_lowercase();
                if name.starts_with('$') { return false; }
                if SKIP_DIRS.iter().any(|&s| s == name) { return false; }
                if skip_windows {
                    let p = e.path().to_string_lossy().to_lowercase();
                    if p.starts_with(&windir) { return false; }
                }
                true
            })
        {
            if let Ok(entry) = entry {
                if entry.file_type().is_file() {
                    if let Some(ext) = entry.path().extension() {
                        if ext.eq_ignore_ascii_case("exe") {
                            exes.push(entry.into_path());
                        }
                    }
                }
            }
        }
    }
    exes
}

pub fn scan_system(scan_paths: &[&str]) -> Vec<SideloadTarget> {
    let known_dlls = get_known_dlls();
    let system_index = build_system_dll_index();

    eprintln!("[*] KnownDLLs: {} entries", known_dlls.len());
    eprintln!("[*] System DLL index: {} DLLs", system_index.len());

    let exes = find_executables(scan_paths, true);
    eprintln!("[*] Found {} executables", exes.len());

    let mut all_targets = Vec::new();
    for (i, exe) in exes.iter().enumerate() {
        if (i + 1) % 500 == 0 {
            eprintln!("    [{}/{}] ...", i + 1, exes.len());
        }
        all_targets.extend(analyze_exe(exe, &known_dlls, &system_index));
    }

    all_targets.sort_by(|a, b| b.score.cmp(&a.score));
    eprintln!("[+] Found {} sideload targets", all_targets.len());
    all_targets
}
