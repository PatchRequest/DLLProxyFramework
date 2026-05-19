use std::fs;
use std::io::Write;

#[unsafe(no_mangle)]
pub extern "C" fn cheat_main() {
    let pid = std::process::id();
    let msg = format!(
        "Rust cheat running!\nPID: {}\nThis code is executing inside the hijacked process.\n",
        pid
    );

    if let Ok(mut f) = fs::File::create("rust_proof.txt") {
        let _ = f.write_all(msg.as_bytes());
    }
}
