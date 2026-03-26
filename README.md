# 🔑 Basic Surface-Layer Keylogger

An educational keystroke logging project built in **Python** and **Rust**, demonstrating offensive security concepts for penetration testing research.

> ⚠️ **Legal Disclaimer**: This tool is for **authorized security testing and educational purposes only**. Unauthorized use against systems you do not own or have explicit written permission to test is **illegal** and may violate computer fraud laws (CFAA, CMA, etc.). The author assumes no liability for misuse.

---

## 📂 Project Structure

```
keylogger/
├── head.py                    # Python implementation (Phase 3)
├── rust_logger/               # Rust implementation (Phase 4)
│   ├── Cargo.toml
│   └── src/main.rs
└── README.md
```

## 🐍 Python Version (`head.py`)

A hardened keylogger using raw OS APIs instead of commonly-flagged libraries.

### Features
- **Raw Input Capture** — `ctypes` and `/dev/input` instead of `pynput`/`pyHook`
- **AES-256-GCM Encryption** — Hardware-derived keys via HKDF (no key stored on disk)
- **Clipboard Monitoring** — Via `xclip`/`xsel` (no `pyperclip`)
- **Screenshot Capture** — Via `scrot`/`import` (no `PIL`)
- **Active Window Tracking** — Logs application context per keystroke
- **Multi-Channel Exfiltration** — HTTPS POST and SMTP with proper TLS
- **Persistence** — systemd user service (Linux), COM hijack (Windows)

### Requirements
```bash
pip install cryptography requests
```

### Usage
```bash
python3 head.py
```

---

## 🦀 Rust Version (`rust_logger/`)

A compiled native binary that addresses behavioral detection vectors.

### Why Rust?
| Problem | Solution |
|---|---|
| Python runtime is suspicious | 626KB stripped native ELF |
| `/dev/input` requires root | X11 XRecord — userland, no privileges |
| Library signatures flagged by EDR | Zero third-party runtime dependencies |
| Predictable network beaconing | Random payload padding + jittered timing |

### Features
- **X11 XRecord** — Protocol-level keyboard capture without root
- **AES-256-GCM** — Hardware-derived keys via `ring` HKDF
- **Double-fork Daemonization** — Breaks parent-child process chain
- **Process Blending** — `prctl(PR_SET_NAME)` masquerades as `dbus-daemon`
- **Anti-Correlation** — Random 64–512 byte padding on every payload
- **Stripped Binary** — No symbols, no debug info, LTO optimized

### Build
```bash
cd rust_logger
cargo build --release
```

Binary output: `target/release/shadow_logger`

### Dependencies
| Crate | Purpose |
|---|---|
| `x11-dl` | X11/XRecord keyboard capture |
| `ring` | AES-256-GCM + HKDF key derivation |
| `ureq` | HTTPS client with native TLS |
| `flate2` | Gzip compression |
| `rand` | Jitter and random padding |
| `libc` | `prctl`, `fork`, `setsid` |

---

## 🧠 Concepts Demonstrated

This project explores several offensive security topics:

1. **Multi-layer input capture** — OS-level hooks + application context awareness
2. **Process blending** — Making malicious processes look legitimate
3. **Resilient persistence** — Multiple fallback mechanisms with self-healing
4. **Covert exfiltration** — Traffic that resists pattern analysis
5. **Cryptographic key management** — Hardware-derived keys with no disk artifacts

## 📚 Further Learning

- [MITRE ATT&CK — Input Capture](https://attack.mitre.org/techniques/T1056/)
- [MITRE ATT&CK — Boot/Logon Persistence](https://attack.mitre.org/techniques/T1547/)
- [OffSec OSCP Certification](https://www.offsec.com/courses/pen-200/)
- [HackTheBox](https://www.hackthebox.com/) — Practice in legal environments

## 📜 License

This project is for educational purposes. Use responsibly and legally.
