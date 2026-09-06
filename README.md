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

### quarantine
- threats moved to `%LocalAppData%\IAuthBytes\Quarantine`
- metadata saved with original path and detection reason
- supports both files and directories

### ui
- dark theme with 10 color schemes and 10 background effects
- WebView2-based interface
- real-time scan progress with phase indicators
- toast notifications with severity types

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
│   ├── RuntimeGuard.cs                 — file/process/network monitoring
│   ├── TamperDetector.cs               — GT DLL baseline verification
│   ├── PeAnalyzer.cs                   — PE header parsing
│   ├── Models.cs                       — data models
│   ├── Logger.cs                       — daily log rotation
│   ├── index.html                      — obfuscated UI (embedded resource)
│   └── icon.ico
├── DiagnosticScan/                     — console diagnostic tool
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

> [!NOTE]
> This product is not affiliated with Gorilla Tag or Another Axiom LLC and is not endorsed or otherwise sponsored by Another Axiom LLC. Portions of the materials contained herein are property of Another Axiom LLC. © 2026 Another Axiom LLC.

---

**MIT License** — do whatever you want with it, just don't blame me if you quarantine the wrong thing.
