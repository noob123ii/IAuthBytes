<p align="center">
  <h1 align="center">IAuthBytes</h1>
  <p align="center">malware scanner & runtime protector for Gorilla Tag</p>
</p>

---

<p align="center">
  <a href="https://github.com/noob123ii/IAuthBytes/releases"><img src="https://img.shields.io/badge/version-1.0.0-blue?style=for-the-badge"></a>
  <a href="https://github.com/noob123ii/IAuthBytes/releases/latest"><img src="https://img.shields.io/badge/download-latest-green?style=for-the-badge"></a>
  <a href="https://github.com/noob123ii/IAuthBytes/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-orange?style=for-the-badge"></a>
</p>

---

# IAuthBytes

a malware scanner and runtime protector built specifically for [Gorilla Tag](https://store.steampowered.com/app/1533390/Gorilla_Tag/). detects and quarantines `.graze` malware, trojanized DLLs, and other shady stuff that circulates in mod folders.

built with WPF + WebView2. scans using raw byte patterns instead of just checking filenames, which makes it way harder for malware to dodge.

<details>
<summary><b>why does this exist?</b></summary>

gorilla tag's modding scene has a real malware problem. malicious `.graze` files and fake DLLs show up in plugin folders, steal accounts, log keystrokes, even dump browser data. most "protectors" are either outdated, easily bypassed, or are malware themselves.

IAuthBytes takes a different approach: raw byte pattern scanning, 42+ detection categories with multi-indicator logic, and an open-source codebase you can actually read. no server connections, no telemetry, no bs.

</details>

<details>
<summary><b>installation</b></summary>

1. **download** the latest release from [releases](https://github.com/noob123ii/IAuthBytes/releases/latest)
2. **run** `IAuthBytes.exe`
3. it'll auto-find your Gorilla Tag install via Steam, or you can set the path manually
4. hit **Scan** and quarantine anything suspicious

### building from source

```
git clone https://github.com/noob123ii/IAuthBytes.git
cd IAuthBytes
dotnet build IAuthBytes.slnx
```

needs .NET 10.0 SDK.

### obfuscated build

the UI (HTML/CSS/JS) is embedded as a resource from the obfuscated output. to rebuild:

```
python build_obfuscated.py
dotnet build IAuthBytes.slnx
```

the clean UI source is in `index.template.html`. the obfuscation pipeline (`build_obfuscated.py`) produces the obfuscated `IAuthBytes/index.html`.

</details>

<details open>
<summary><b>features</b></summary>

### file scanner
- raw byte pattern scanning (ASCII + UTF-16LE) in DLL binaries
- `.graze` file and directory detection
- 42+ detection categories with multi-indicator pattern matching
- PE header parsing for imports, resources, and entropy analysis
- multi-indicator threshold: 2+ suspicious flags OR any single strong indicator auto-flags
- tamper detection against known GT DLL baselines (size + SHA-256)

### detection categories
steam stealers, keyloggers, LSASS dumpers, ransomware, injection APIs, process hollowing, reflective PE loading, clipboard monitors, screen capture, DLL sideloading, credential theft, browser stealers, privilege escalation, UAC bypass, Discord token theft, crypto wallet stealers, WiFi/password theft, webcam/audio capture, self-deletion, anti-sandbox, DLL hijacking, env var exfiltration, screenshot+exfil, network share abuse, certificate/credential theft, string obfuscation, hidden console injection, anti-analysis, and more.

### runtime protection
- file system watcher for new `.graze` or suspicious DLL creation
- process monitor checking for shady running processes (GT + system-wide)
- network monitor watching GT's connections for non-Steam outbound traffic
- PowerShell and registry persistence detection
- 30+ memory patterns for malicious code detection
- DLL proxy detection
- 36 child process patterns for suspicious spawns
- expanded network port monitoring
- system-wide process scanning and TCP listener monitoring

### anti-hook & self-protection
- debugger detection (5 methods: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess x3)
- thread hijacking detection (Thread32First + NtQueryInformationThread)
- hardware breakpoint detection (DR0-DR3 via GetThreadContext, x86 + x64)
- inline hook scanning on 21+ critical APIs across 8 DLLs (ntdll, kernel32, user32, advapi32, ws2_32, winhttp, crypt32, shell32) with 32-bit + 64-bit patterns
- IAT hook detection via .text section entropy analysis
- EAT hook detection (export address table validation)
- hook engine signature detection (EasyHook trampolines, Detours patterns)
- external process access detection (hooks, injectors, debuggers reading IAuthBytes memory) with 18 excluded Windows processes
- handle abuse detection (full/write+dup access from external processes)
- module injection detection (unexpected DLLs loaded into IAuthBytes)
- self-integrity verification: MZ/PE header validation, file size bounds, SHA-256 hash vs stored baseline
- **code page locking**: .text section set to PAGE_EXECUTE_READ to prevent runtime patching
- **IAT integrity monitoring**: periodic verification of import address table against cached snapshot
- **DLL load monitoring**: detects new DLLs loaded from untrusted paths at runtime (15s interval)
- **memory region scanning**: detects RWX pages and writable code memory regions
- **filesystem watchers**: monitors app directory for new DLLs/EXEs (hijacking) and core file changes (IAuthBytes.exe, index.html)
- continuous .text section monitoring (30-second timer) — detects runtime patches to IAuthBytes's own code
- 3 self-tests: hook detection baseline, .text integrity cache, process access count

### self-protection (IAuthBytes.exe)
- **code page locking**: VirtualProtect marks .text as PAGE_EXECUTE_READ — blocks runtime code patching
- **DLL load monitoring**: snapshots 127+ modules at startup, detects new DLLs from untrusted paths
- **IAT integrity**: caches import directory, verifies every 30s against byte-level changes
- **memory region scanning**: walks virtual memory regions for RWX pages and unauthorized writable code
- **filesystem watchers**: FileSystemWatcher on app directory — flags new DLLs/EXEs and core file modifications
- **TamperDetector self-protection**: exe hash monitoring (SHA-256, 30s), install directory watcher, security file monitoring
- all protections run on timers and log CRITICAL alerts when tampering is detected

### quarantine
- threats moved to `%LocalAppData%\IAuthBytes\Quarantine`
- metadata saved with original path and detection reason
- supports both files and directories
- critical threats auto-deleted, others quarantined

### auto-update
- checks `LatestUpdate.txt` on GitHub for new versions
- SHA-256 integrity verification before installing
- downloads release zip, extracts to temp, copies files preserving user data (Logs, Crashes, WebView2 cache)
- PowerShell restart script for seamless updates

### ui
- dark theme with 10 color schemes and 10 background effects
- WebView2-based interface with rounded edges (12px window, 10px cards)
- real-time scan progress with phase indicators
- toast notifications with severity types (success, warning, error, info)
- background blur toggle (0-20px slider)
- full-screen update modal with progress bar
- settings persistence via localStorage
- title: "IAuthBytes - Made by Notlucy"

### ui obfuscation (v5)
- template literal encryption
- 4-layer XOR number obfuscation
- string encryption with shuffled arrays
- identifier renaming (71 identifiers)
- anti-debugging: timing loop (>200ms), Function constructor trap, DevTools detection
- MutationObserver for DOM tamper detection
- toString override on critical objects
- console warning banner
- function hash integrity verification (7 callback functions)
- the clean source lives in `index.template.html`; the obfuscated output is embedded as a resource

</details>

<details>
<summary><b>detection details</b></summary>

### how it works

for each file, IAuthBytes:

1. reads the first 1MB + last 1MB (scan window for performance)
2. searches for malicious byte sequences in ASCII and UTF-16LE
3. parses PE headers to extract imports, resources, and entropy
4. checks against 42+ detection categories
5. applies multi-indicator threshold

### strong indicators (auto-flag on their own)

| category | what it catches |
|----------|----------------|
| steam stealer | steals Steam session/cookies |
| keylogger | records keystrokes |
| LSASS dump | dumps process memory for credentials |
| ransomware | encrypts user files |
| injection APIs | writes code into other processes |
| process hollowing | runs code inside legitimate process shells |
| reflective PE loading | loads DLLs from memory without disk |
| credential theft | harvests passwords/tokens |
| browser stealer | steals browser cookies/passwords |
| privilege escalation | exploits to gain admin rights |
| UAC bypass | circumvents Windows UAC |
| hidden console injection | injects into hidden console windows |
| anti-analysis | detects debuggers/VMs to evade analysis |
| Discord token theft | steals Discord tokens and user data |
| crypto wallet stealer | targets cryptocurrency wallets |
| WiFi/password theft | harvests saved WiFi credentials and passwords |

### known good DLLs (whitelisted)

`UnityPlayer.dll`, `steam_api.dll`, `steam_api64.dll`, `dsound.dll`, `dinput8.dll`, `d3d9.dll`, `opengl32.dll`, `winhttp.dll`, `version.dll`, `ogg.dll`, `vorbis.dll`, `vorbisfile.dll`, `System.dll`, `mono-2.0-bdwgc.dll`, and more.

</details>

<details>
<summary><b>project structure</b></summary>

```
IAuthBytes/
├── IAuthBytes/
│   ├── MainWindow.xaml / .xaml.cs      — WPF window + WebView2 host
│   ├── Scanner.cs                      — 42+ detection categories, 8-phase scan
│   ├── AntiHook.cs                     — anti-hook, self-protection, continuous monitoring
│   ├── RuntimeGuard.cs                 — file/process/network monitoring, system-wide scanning
│   ├── TamperDetector.cs               — GT DLL baseline + self-protection (exe hash + file watchers)
│   ├── PeAnalyzer.cs                   — PE header parsing
│   ├── UpdateChecker.cs                — version check, SHA-256 integrity, auto-update
│   ├── Models.cs                       — data models with threat tag colors
│   ├── Logger.cs                       — daily log rotation
│   ├── index.html                      — obfuscated UI (embedded resource)
│   └── icon.ico
├── HookTest/
│   ├── Injector/                       — hook injection test harness
│   ├── RuntimeTest/                    — runtime detection test harness (10 tests)
│   └── AttackTest/                     — comprehensive attack test (29 tests: hooking, tampering, HTML injection, obfuscation bypass)
├── UpdateDetection/
│   └── LatestUpdate.txt                — version metadata with SHA-256 integrity
├── build_obfuscated.py                 — JS obfuscation pipeline v5
├── index.template.html                 — clean UI source
├── publish.bat                         — release zip builder
├── IAuthBytes.slnx                     — solution file
└── README.md
```

</details>

<details>
<summary><b>requirements</b></summary>

- Windows 10 or 11
- .NET 10.0 Desktop Runtime
- Gorilla Tag installed via Steam

</details>

---

<details>
<summary><b>known limitations</b></summary>

**false positives will happen.** the scanner uses heuristics and byte pattern matching, which means it can flag legitimate files that happen to match suspicious patterns. this is especially true for modded DLLs or custom plugins that use similar APIs to what malware uses. always check what's flagged before quarantineing anything.

**since it's open source, malware authors can bypass it.** the detection patterns, thresholds, and logic are all public. anyone can read the code and write malware that avoids triggering them. this is an inherent limitation of any open-source security tool — transparency is a tradeoff. the detection signatures will be updated over time to keep up with new threats, but there's no guarantee of catching everything.

</details>

---

> [!NOTE]
> This product is not affiliated with Gorilla Tag or Another Axiom LLC and is not endorsed or otherwise sponsored by Another Axiom LLC. Portions of the materials contained herein are property of Another Axiom LLC. © 2026 Another Axiom LLC.

---

**MIT License** — do whatever you want with it, just don't blame me if you quarantine the wrong thing.
