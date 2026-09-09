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

IAuthBytes takes a different approach: raw byte pattern scanning, 28+ detection categories with multi-indicator logic, and an open-source codebase you can actually read. no server connections, no telemetry, no bs.

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

</details>

<details open>
<summary><b>features</b></summary>

### file scanner
- raw byte pattern scanning (ASCII + UTF-16LE) in DLL binaries
- `.graze` file and directory detection
- 28+ detection categories: steam stealers, keyloggers, LSASS dumpers, ransomware, injection APIs, process hollowing, reflective PE loading, clipboard monitors, screen capture, DLL sideloading, credential theft, browser stealers, privilege escalation, UAC bypass, and more
- PE header parsing for imports, resources, and entropy analysis
- multi-indicator threshold: 2+ suspicious flags OR any single strong indicator auto-flags
- tamper detection against known GT DLL baselines (size + SHA-256)

### runtime protection
- file system watcher for new `.graze` or suspicious DLL creation
- process monitor checking for shady running processes
- network monitor watching GT's connections for non-Steam outbound traffic
- PowerShell and registry persistence detection

### anti-hook & self-protection
- debugger detection (5 methods: IsDebuggerPresent, CheckRemoteDebuggerPresent, NtQueryInformationProcess x3)
- inline hook scanning on 21+ critical APIs across 8 DLLs (ntdll, kernel32, user32, advapi32, ws2_32, winhttp, crypt32, shell32)
- IAT hook detection via .text section entropy analysis
- external process access detection (hooks, injectors, debuggers reading IAuthBytes memory)
- handle abuse detection (full/write+dup access from external processes)
- module injection detection (unexpected DLLs loaded into IAuthBytes)
- self-integrity verification: MZ/PE header validation, file size bounds, SHA-256 hash vs stored baseline
- continuous .text section monitoring (30-second timer) — detects runtime patches to IAuthBytes's own code
- 3 self-tests: hook detection baseline, .text integrity cache, process access count

### quarantine
- threats moved to `%LocalAppData%\IAuthBytes\Quarantine`
- metadata saved with original path and detection reason
- supports both files and directories

### ui
- dark theme with 10 color schemes and 10 background effects
- WebView2-based interface
- real-time scan progress with phase indicators
- toast notifications with severity types

### ui obfuscation
- the HTML/CSS/JS powering the UI is obfuscated via a custom Python build pipeline (`build_obfuscated.py`)
- string encryption, identifier renaming, function hash obfuscation — makes it hard to reverse-engineer the C# ↔ JS communication protocol or tamper with UI logic
- anti-debugging traps and integrity checks in the JS layer
- the clean source lives in `index.template.html`; the obfuscated output is embedded as a resource in the final build

</details>

<details>
<summary><b>detection details</b></summary>

### how it works

for each file, IAuthBytes:

1. reads the first 1MB + last 1MB (scan window for performance)
2. searches for malicious byte sequences in ASCII and UTF-16LE
3. parses PE headers to extract imports, resources, and entropy
4. checks against 28+ detection categories
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

### known good DLLs (whitelisted)

`UnityPlayer.dll`, `steam_api.dll`, `steam_api64.dll`, `dsound.dll`, `dinput8.dll`, `d3d9.dll`, `opengl32.dll`, `winhttp.dll`, `version.dll`, `ogg.dll`, `vorbis.dll`, `vorbisfile.dll`, `System.dll`, `mono-2.0-bdwgc.dll`, and more.

</details>

<details>
<summary><b>project structure</b></summary>

```
IAuthBytes/
├── IAuthBytes/
│   ├── MainWindow.xaml / .xaml.cs      — WPF window + WebView2 host
│   ├── Scanner.cs                      — 28+ detection categories, 7-phase scan
│   ├── AntiHook.cs                     — anti-hook detection, self-integrity, continuous monitoring
│   ├── RuntimeGuard.cs                 — file/process/network monitoring
│   ├── TamperDetector.cs               — GT DLL baseline verification
│   ├── PeAnalyzer.cs                   — PE header parsing
│   ├── Models.cs                       — data models
│   ├── Logger.cs                       — daily log rotation
│   ├── index.html                      — obfuscated UI (embedded resource)
│   └── icon.ico
├── DiagnosticScan/                     — console diagnostic tool
├── HookTest/                           — hook injection test harness
├── build_obfuscated.py                 — JS obfuscation pipeline
├── index.template.html                 — clean UI source
└── IAuthBytes.slnx
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
