using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;

namespace IAuthBytes
{
    internal class ScanProgress
    {
        public int Phase { get; set; }
        public string PhaseName { get; set; } = "";
        public string CurrentFile { get; set; } = "";
        public int FilesScanned { get; set; }
        public int TotalFiles { get; set; }
        public double Percentage { get; set; }
    }

    internal class ScanResult
    {
        public List<ThreatInfo> Threats { get; set; } = new();
        public int FilesScanned { get; set; }
        public string GtPath { get; set; } = "";
        public string Status { get; set; } = "complete";
        public string Error { get; set; } = "";
    }

    internal static class Scanner
    {
        private static readonly HashSet<string> KnownGoodDlls = new(StringComparer.OrdinalIgnoreCase)
        {
            "UnityPlayer.dll", "UnityPlayer.so",
            "steam_api.dll", "steam_api64.dll",
            "dsound.dll", "dinput8.dll", "d3d9.dll", "opengl32.dll",
            "winhttp.dll", "version.dll",
            "ogg.dll", "vorbis.dll", "vorbisfile.dll",
            "audiokinetic.dll", "wwise.dll",
            "System.Drawing.dll", "mscorlib.dll", "netstandard.dll",
            "mono-2.0-bdwgc.dll", "mono-2.0.dll", "mono.dll",
            "System.dll", "System.Core.dll", "System.Xml.dll"
        };

        private static readonly HashSet<string> KnownGtDlls = new(StringComparer.OrdinalIgnoreCase)
        {
            "BepInEx.dll", "BepInEx.Preloader.dll", "0Harmony.dll", "HarmonyXInterop.dll",
            "MonoMod.RuntimeDetour.dll", "MonoMod.Utils.dll",
            "Il2CppDumper.dll", "UnhollowerBaseLib.dll", "Il2CppInterop.Runtime.dll",
            "MelonLoader.dll", "MelonLoader.Mod.dll",
            "NeosModLoader.dll", "CardinalLoader.dll",
            "GorillaTagUtils.dll", "GorillaTagModding.dll",
            "Utilla.dll", "GorillaCosmetics.dll",
            "GorillaExtensions.dll", "GorillaInfo.dll",
            "GorillaQuiver.dll", "GTagCustomBackgrounds.dll"
        };

        private static readonly HashSet<string> KnownGtDllsWithSize = new(StringComparer.OrdinalIgnoreCase)
        {
            "UnityPlayer.dll", "BepInEx.dll", "0Harmony.dll", "HarmonyXInterop.dll",
            "MonoMod.RuntimeDetour.dll", "MonoMod.Utils.dll"
        };

        private static readonly HashSet<string> KnownGoodExes = new(StringComparer.OrdinalIgnoreCase)
        {
            "Gorilla Tag.exe", "UnityCrashHandler64.exe", "Unity Hub.exe",
            "Steam.exe", "steam.exe"
        };

        private static readonly HashSet<int> SuspiciousPorts = new()
        {
            4444, 5555, 1234, 6666, 7777, 8888, 9999, 1337, 31337, 44444, 55555, 12345, 54321
        };

        private static readonly HashSet<string> StrongIndicators = new(StringComparer.OrdinalIgnoreCase)
        {
            "Steam stealer", "Keylogger", "LSASS dump", "Ransomware",
            "Injection APIs", "Process hollowing", "Reflective PE loading",
            "Clipboard", "Screen capture", "Download-and-execute",
            "Credential theft", "Browser stealer", "Privilege escalation",
            "UAC bypass", "Service install", "Scheduled task", "WMI persistence",
            "Data exfiltration", "DNS exfiltration", "PowerShell execution",
            "DLL sideloading", "Socket C2", "Multi-stage loader",
            "Hidden console injection", "PowerShell download", "Anti-analysis",
            "VM detection", "Shellcode pattern", "Embedded executable",
            "Packed payload", "Reflection abuse",
            "Inline hook", "JMP hook", "CALL hook", "Indirect JMP hook",
            "NOP sled", "Push+RET hook", "MOV RAX+JMP hook",
            "Debugger detected", "Remote debugger detected", "NtQuery debug port detected",
            "Symbolic link detected", "Reparse point detected",
            "Double extension detected", "Magic byte mismatch",
            "Text file contains", "Image file contains", "PDF file contains",
            "Archive file contains", "Binary file with invalid PE header",
            "IAuthBytes executable has invalid", "IAuthBytes binary hash mismatch"
        };

        private static List<ThreatInfo> DetectPeThreats(string filePath, byte[] fileBytes, PeAnalyzer.PeInfo pe, bool isPlugin, bool isGtDll, bool isKnownGood)
        {
            var threats = new List<ThreatInfo>();
            string fileName = Path.GetFileName(filePath);
            string textContent = Encoding.UTF8.GetString(fileBytes);
            int strongCount = 0;
            var reasons = new List<string>();

            if (isKnownGood)
                return threats;

            int scanLen = Math.Min(fileBytes.Length, 1_048_576);
            int lastStart = Math.Max(0, fileBytes.Length - 1_048_576);
            var firstWindow = new byte[scanLen];
            Buffer.BlockCopy(fileBytes, 0, firstWindow, 0, scanLen);
            byte[] lastWindow = scanLen < fileBytes.Length ? new byte[Math.Min(1_048_576, fileBytes.Length - lastStart)] : Array.Empty<byte>();
            if (lastWindow.Length > 0)
                Buffer.BlockCopy(fileBytes, lastStart, lastWindow, 0, lastWindow.Length);

            bool HasAscii(string s) => ContainsAscii(firstWindow, s) || (lastWindow.Length > 0 && ContainsAscii(lastWindow, s));
            bool HasUtf16(string s) => ContainsUtf16LE(firstWindow, s) || (lastWindow.Length > 0 && ContainsUtf16LE(lastWindow, s));
            bool HasPattern(string s) => HasAscii(s) || HasUtf16(s);

            string dllList = string.Join(" ", pe.ImportedDlls).ToLowerInvariant();
            string funcList = string.Join(" ", pe.ImportedFunctions).ToLowerInvariant();
            string allText = textContent;

            bool hasAllocConsole = HasPattern("AllocConsole");
            bool hasFreeConsole = HasPattern("FreeConsole");
            bool hasGetConsoleWindow = HasPattern("GetConsoleWindow");
            bool hasSetConsoleTitle = HasPattern("SetConsoleTitle");
            if (hasAllocConsole && hasFreeConsole && (hasGetConsoleWindow || hasSetConsoleTitle))
            {
                strongCount++; reasons.Add("Hidden console injection");
            }

            if (HasPattern("Assembly.Load") && HasPattern("payload"))
            {
                bool hasMzHeader = false;
                for (int i = 0; i < fileBytes.Length - 1; i++)
                {
                    if (fileBytes[i] == 0x4D && fileBytes[i + 1] == 0x5A)
                    {
                        int peOff = i + 0x3C;
                        if (peOff + 4 < fileBytes.Length)
                        {
                            int peSig = BitConverter.ToInt32(fileBytes, peOff);
                            if (peSig > 0 && peSig < fileBytes.Length - 4 &&
                                fileBytes[peSig] == 0x50 && fileBytes[peSig + 1] == 0x45)
                            {
                                hasMzHeader = true;
                                break;
                            }
                        }
                    }
                }
                if (hasMzHeader)
                {
                    strongCount++; reasons.Add("Embedded executable");
                }
            }

            if (HasPattern("__StaticArrayInitTypeSize") && HasPattern("Assembly.Load"))
            {
                strongCount++; reasons.Add("Packed payload");
            }

            if (HasPattern("SteamAPI_Init") || HasPattern("GetAuthSessionTicket") ||
                HasPattern("SteamClient") || HasPattern("SteamUser"))
            {
                bool hasWebhook = HasPattern("webhook") || HasPattern("discord.com/api");
                bool hasUpload = HasPattern("UploadString") || HasPattern("UploadFile");
                bool hasRegistry = HasPattern("Software\\Valve\\Steam");
                if (hasWebhook || hasUpload || hasRegistry)
                {
                    strongCount++; reasons.Add("Steam stealer");
                }
            }

            if (HasPattern("SetWindowsHookEx") && HasPattern("GetAsyncKeyState") && HasPattern("GetForegroundWindow"))
            {
                strongCount++; reasons.Add("Keylogger");
            }

            if ((HasPattern("lsass") || HasPattern("Lsass")) && HasPattern("ReadProcessMemory"))
            {
                strongCount++; reasons.Add("LSASS dump");
            }

            bool hasOpenProcess = HasPattern("OpenProcess");
            bool hasVirtAllocEx = HasPattern("VirtualAllocEx");
            bool hasWritePM = HasPattern("WriteProcessMemory");
            bool hasCRT = HasPattern("CreateRemoteThread");
            bool hasNtCreateThread = HasPattern("NtCreateThreadEx");
            bool hasVirtProtEx = HasPattern("VirtualProtectEx");
            int injectCount = new[] { hasOpenProcess, hasVirtAllocEx, hasWritePM, hasCRT, hasNtCreateThread, hasVirtProtEx }.Count(x => x);
            if (injectCount >= 4)
            {
                strongCount++; reasons.Add("Injection APIs");
            }

            bool hasNtUnmap = HasPattern("NtUnmapViewOfSection");
            bool hasSetThreadCtx = HasPattern("SetThreadContext");
            bool hasGetThreadCtx = HasPattern("GetThreadContext");
            if (hasNtUnmap && hasVirtAllocEx && hasWritePM)
            {
                strongCount++; reasons.Add("Process hollowing");
            }

            bool hasVirtualAlloc = HasPattern("VirtualAlloc");
            bool hasVirtualProtect = HasPattern("VirtualProtect");
            bool hasLoadLib = HasPattern("LoadLibrary");
            bool hasGetProcAddr = HasPattern("GetProcAddress");
            if (hasVirtualAlloc && hasVirtualProtect && hasLoadLib && hasGetProcAddr &&
                HasPattern("Marshal.GetDelegateForFunctionPointer"))
            {
                strongCount++; reasons.Add("Reflective PE loading");
            }

            if (HasPattern("OpenClipboard") || HasPattern("GetClipboardData"))
            {
                strongCount++; reasons.Add("Clipboard");
            }

            bool hasBitBlt = HasPattern("BitBlt");
            bool hasGetDC = HasPattern("GetDC");
            bool hasCreateCompatibleDC = HasPattern("CreateCompatibleDC");
            if (hasBitBlt && hasGetDC && hasCreateCompatibleDC)
            {
                strongCount++; reasons.Add("Screen capture");
            }

            if (HasPattern("ShellExecute") || HasPattern("CreateProcess"))
            {
                bool hasDownload = HasPattern("DownloadFile") || HasPattern("DownloadData");
                bool hasWebClient = HasPattern("WebClient");
                bool hasHttpUrl = HasPattern("http://") || HasPattern("https://");
                if (hasDownload && hasWebClient && hasHttpUrl)
                {
                    strongCount++; reasons.Add("Download-and-execute");
                }
            }

            if (HasPattern("CryptUnprotectData") || (HasPattern("DPAPI") && HasPattern("Credential")))
            {
                strongCount++; reasons.Add("Credential theft");
            }

            bool hasBrowserPaths = HasPattern("Chrome") || HasPattern("Firefox") || HasPattern("Edge");
            bool hasBrowserData = HasPattern("Login Data") || HasPattern("Cookies") || HasPattern("Local State");
            if (hasBrowserPaths && hasBrowserData)
            {
                strongCount++; reasons.Add("Browser stealer");
            }

            if (HasPattern("SeDebugPrivilege") || HasPattern("SeImpersonatePrivilege"))
            {
                strongCount++; reasons.Add("Privilege escalation");
            }

            if (HasPattern("ms-settings") || HasPattern("fodhelper") || HasPattern("eventvwr"))
            {
                strongCount++; reasons.Add("UAC bypass");
            }

            if (HasPattern("CreateService") || HasPattern("OpenSCManager"))
            {
                strongCount++; reasons.Add("Service install");
            }

            if (HasPattern("schtasks") || HasPattern("SchRpcRegisterTask"))
            {
                strongCount++; reasons.Add("Scheduled task");
            }

            bool hasWmiQuery = HasPattern("Win32_") || HasPattern("__InstanceModificationEvent");
            bool hasWmiConsumer = HasPattern("__EventFilter") || HasPattern("CommandLineEventConsumer");
            if (hasWmiQuery || hasWmiConsumer)
            {
                strongCount++; reasons.Add("WMI persistence");
            }

            bool hasDiscord = HasPattern("discord.com/api");
            bool hasTelegram = HasPattern("api.telegram.org");
            bool hasPastebin = HasPattern("pastebin.com");
            bool hasUploadExfil = HasPattern("UploadString") || HasPattern("UploadFile");
            if ((hasDiscord || hasTelegram || hasPastebin) && hasUploadExfil)
            {
                strongCount++; reasons.Add("Data exfiltration");
            }

            bool hasDnsQuery = HasPattern("DnsQuery");
            bool hasDnsExfil = HasPattern(".evil.com") || HasPattern(".data.");
            if (hasDnsQuery && hasDnsExfil)
            {
                strongCount++; reasons.Add("DNS exfiltration");
            }

            bool hasPowershellExec = HasPattern("powershell") || HasPattern("Invoke-Expression") || HasPattern("IEX");
            bool hasPowershellDownload = HasPattern("Invoke-WebRequest") || HasPattern("Invoke-RestMethod") ||
                                         HasPattern("Net.WebClient");
            bool hasEncodedCommand = HasPattern("-EncodedCommand") || HasPattern("-enc ");
            if (hasPowershellExec && (hasPowershellDownload || hasEncodedCommand))
            {
                strongCount++; reasons.Add("PowerShell execution");
            }

            if (HasPattern("GetAsyncKeyState") && HasPattern("GetForegroundWindow"))
            {
                int antiDbgCount = new[] { HasPattern("IsDebuggerPresent"), HasPattern("CheckRemoteDebuggerPresent"),
                    HasPattern("NtQueryInformationProcess"), HasPattern("OutputDebugString") }.Count(x => x);
                if (antiDbgCount >= 3)
                {
                    strongCount++; reasons.Add("Anti-analysis");
                }
            }

            bool hasVmDetect = HasPattern("VMWARE") || HasPattern("vmGuestServices") ||
                               HasPattern("VBoxGuest") || HasPattern("VBoxMouse") ||
                               HasPattern("SbieDll") || HasPattern("vmtoolsd");
            if (hasVmDetect)
            {
                strongCount++; reasons.Add("VM detection");
            }

            bool hasShellcode = HasPattern("0x48, 0x89, 0x5C") || HasPattern("0x48, 0x83, 0xEC");
            if (hasShellcode && (hasVirtualAlloc || hasVirtualProtect))
            {
                strongCount++; reasons.Add("Shellcode pattern");
            }

            bool hasAssemblyLoad = HasPattern("Assembly.Load") || HasPattern("Assembly.LoadFrom");
            bool hasReflection = HasPattern("Type.GetType") || HasPattern("InvokeMember") || HasPattern("MethodInfo");
            if (hasAssemblyLoad && hasReflection)
            {
                strongCount++; reasons.Add("Reflection abuse");
            }

            bool hasSocket = HasPattern("WSASocket") || HasPattern("WSAStartup");
            bool hasSocketComm = HasPattern("recv") && HasPattern("send");
            if (hasSocket && hasSocketComm)
            {
                strongCount++; reasons.Add("Socket C2");
            }

            if (hasLoadLib && HasPattern("version.dll") && HasPattern("FileAttributes.Hidden"))
            {
                strongCount++; reasons.Add("DLL sideloading");
            }

            if (HasPattern("new char[]") && HasPattern("String.Join") && HasPattern("Convert.ToChar"))
            {
                strongCount++; reasons.Add("String obfuscation");
            }

            if (HasPattern("FromBase64String") && HasPattern("Convert.") &&
                (HasPattern("Assembly.Load") || HasPattern("Process.Start")))
            {
                strongCount++; reasons.Add("Multi-stage loader");
            }

            if (fileBytes.Length > 100000)
            {
                double entropy = PeAnalyzer.CalcEntropy(fileBytes);
                if (entropy > 7.0)
                {
                    strongCount++; reasons.Add("High entropy / packing");
                }
            }

            bool hasRegRead = HasPattern("OpenSubKey") || HasPattern("GetValue");
            bool hasRegWrite = HasPattern("SetValue") || HasPattern("CreateSubKey");
            bool hasSensitiveReg = HasPattern("Software\\Valve\\Steam") || HasPattern("Credentials") ||
                                   HasPattern("CurrentControlSet\\Control\\Lsa");
            if ((hasRegRead || hasRegWrite) && hasSensitiveReg && reasons.Count < 2)
            {
                reasons.Add("Registry access");
            }

            bool hasLoadLibrary = HasPattern("LoadLibrary");
            bool hasGetProcAddress = HasPattern("GetProcAddress");
            if (hasLoadLibrary && hasGetProcAddress && HasPattern("FileAttributes.Hidden") && reasons.Count < 2)
            {
                reasons.Add("DLL sideloading");
            }

            if (isGtDll && KnownGtDllsWithSize.Contains(fileName))
            {
                var range = GetExpectedSizeRange(fileName);
                if (range.HasValue)
                {
                    double ratio = (double)fileBytes.Length / range.Value.max;
                    if (ratio > 1.05)
                    {
                        reasons.Add($"Known GT DLL oversized ({FormatSize(fileBytes.Length)} vs max {FormatSize(range.Value.max)})");
                    }
                }
            }

            int strongReasonCount = reasons.Count(r => StrongIndicators.Contains(r));

            if (strongReasonCount > 0 || (reasons.Count >= 2 && !isKnownGood))
            {
                var severity = strongReasonCount >= 2 ? Severity.Critical :
                               strongReasonCount == 1 ? Severity.High :
                               reasons.Count >= 4 ? Severity.High :
                               Severity.Medium;

                threats.Add(new ThreatInfo
                {
                    FileName = fileName,
                    FilePath = filePath,
                    ThreatType = "Malware",
                    FileSize = FormatSize(fileBytes.Length),
                    Severity = severity,
                    Description = string.Join(" + ", reasons)
                });
            }

            return threats;
        }

        private static (long min, long max)? GetExpectedSizeRange(string dllName)
        {
            return dllName.ToLowerInvariant() switch
            {
                "unityplayer.dll" => (5_000_000, 30_000_000),
                "bepinex.dll" => (50_000, 500_000),
                "0harmony.dll" => (50_000, 500_000),
                "harmonyxinterop.dll" => (10_000, 200_000),
                "monomod.runtimedetour.dll" => (10_000, 200_000),
                "monomod.utils.dll" => (10_000, 200_000),
                _ => null
            };
        }

        private static bool ContainsAscii(byte[] data, string pattern)
        {
            if (data.Length < pattern.Length) return false;
            byte[] patBytes = Encoding.ASCII.GetBytes(pattern);
            for (int i = 0; i <= data.Length - patBytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < patBytes.Length; j++)
                {
                    if (data[i + j] != patBytes[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }

        private static bool ContainsUtf16LE(byte[] data, string pattern)
        {
            if (data.Length < pattern.Length * 2) return false;
            byte[] patBytes = Encoding.Unicode.GetBytes(pattern);
            for (int i = 0; i <= data.Length - patBytes.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < patBytes.Length; j++)
                {
                    if (data[i + j] != patBytes[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }

        public static bool IsKnownGoodModule(string lowerName)
        {
            return KnownGoodDlls.Contains(lowerName) || KnownGtDlls.Contains(lowerName) ||
                   lowerName.StartsWith("system.") || lowerName.StartsWith("microsoft.") ||
                   lowerName == "mscorlib.dll" || lowerName == "netstandard.dll";
        }

        public static string? FindGorillaTagPath()
        {
            string steamPaths = @"C:\Program Files (x86)\Steam\steamapps\common\Gorilla Tag";
            if (Directory.Exists(steamPaths)) return steamPaths;

            string steamPaths2 = @"C:\Program Files\Steam\steamapps\common\Gorilla Tag";
            if (Directory.Exists(steamPaths2)) return steamPaths2;

            string[] driveRoots = { @"C:\", @"D:\", @"E:\", @"F:\" };
            foreach (string drive in driveRoots)
            {
                string p = Path.Combine(drive, "SteamLibrary\\steamapps\\common\\Gorilla Tag");
                if (Directory.Exists(p)) return p;
            }

            try
            {
                using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(@"SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Steam App 1533390");
                if (key?.GetValue("InstallLocation") is string loc && Directory.Exists(loc)) return loc;
            }
            catch { }

            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
                if (key?.GetValue("SteamPath") is string steamPath)
                {
                    string normalized = steamPath.Replace('/', '\\');
                    string gtPath = Path.Combine(normalized, "steamapps", "common", "Gorilla Tag");
                    if (Directory.Exists(gtPath)) return gtPath;
                }
            }
            catch { }

            return null;
        }

        private static List<string> CollectGrazeFiles(string gtPath)
        {
            var files = new List<string>();
            try
            {
                string bepinex = Path.Combine(gtPath, "BepInEx");
                if (Directory.Exists(bepinex))
                {
                    foreach (string dir in Directory.EnumerateDirectories(bepinex, "*.graze", SearchOption.AllDirectories))
                        files.Add(dir);
                    foreach (string file in Directory.EnumerateFiles(bepinex, "*.graze", SearchOption.AllDirectories))
                        files.Add(file);
                }
            }
            catch { }
            return files;
        }

        private static List<string> CollectPluginFiles(string gtPath)
        {
            var files = new List<string>();
            try
            {
                string plugins = Path.Combine(gtPath, "BepInEx", "plugins");
                if (Directory.Exists(plugins))
                {
                    files.AddRange(Directory.EnumerateFiles(plugins, "*.dll", SearchOption.AllDirectories));
                    files.AddRange(Directory.EnumerateFiles(plugins, "*.exe", SearchOption.AllDirectories));
                }
            }
            catch { }
            return files;
        }

        private static List<string> CollectDllFiles(string gtPath)
        {
            var files = new List<string>();
            try
            {
                files.AddRange(Directory.EnumerateFiles(gtPath, "*.dll", SearchOption.TopDirectoryOnly));
                string mono = Path.Combine(gtPath, "MonoBleedingEdge");
                if (Directory.Exists(mono))
                    files.AddRange(Directory.EnumerateFiles(mono, "*.dll", SearchOption.AllDirectories));
            }
            catch { }
            return files;
        }

        private static List<string> CollectExeFiles(string gtPath)
        {
            var files = new List<string>();
            try
            {
                files.AddRange(Directory.EnumerateFiles(gtPath, "*.exe", SearchOption.TopDirectoryOnly));
            }
            catch { }
            return files;
        }

        private static List<string> CollectConfigFiles(string gtPath)
        {
            var files = new List<string>();
            try
            {
                string bepinex = Path.Combine(gtPath, "BepInEx");
                if (Directory.Exists(bepinex))
                {
                    files.AddRange(Directory.EnumerateFiles(bepinex, "*.cfg", SearchOption.AllDirectories));
                    files.AddRange(Directory.EnumerateFiles(bepinex, "*.json", SearchOption.AllDirectories));
                    files.AddRange(Directory.EnumerateFiles(bepinex, "*.xml", SearchOption.AllDirectories));
                }
            }
            catch { }
            return files;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        }

        private static readonly byte[] GrazeSignature = Encoding.ASCII.GetBytes(".graze");
        private static readonly byte[] GrazeSignatureUtf16 = Encoding.Unicode.GetBytes(".graze");
        private static readonly byte[] MzHeader = { 0x4D, 0x5A };
        private static readonly byte[] PeSignature = { 0x50, 0x45, 0x00, 0x00 };
        private static readonly byte[] ElfSignature = { 0x7F, 0x45, 0x4C, 0x46 };
        private static readonly byte[] ZipSignature = { 0x50, 0x4B, 0x03, 0x04 };
        private static readonly byte[] GzSignature = { 0x1F, 0x8B };
        private static readonly byte[] Bz2Signature = { 0x42, 0x5A, 0x68 };
        private static readonly byte[] XzSignature = { 0xFD, 0x37, 0x7A, 0x58, 0x5A, 0x00 };

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool GetFileAttributesEx(string lpFileName, int fInfoLevelId, out WIN32_FILE_ATTRIBUTE_DATA lpFileInformation);

        [StructLayout(LayoutKind.Sequential)]
        private struct WIN32_FILE_ATTRIBUTE_DATA
        {
            public int dwFileAttributes;
            public long ftCreationTime;
            public long ftLastAccessTime;
            public long ftLastWriteTime;
            public int nFileSizeHigh;
            public int nFileSizeLow;
        }

        private const int GET_FILEEX_INFO_LEVELS = 0;
        private const int FILE_ATTRIBUTE_HIDDEN = 0x02;
        private const int FILE_ATTRIBUTE_SYSTEM = 0x04;
        private const int FILE_ATTRIBUTE_REPARSE_POINT = 0x400;

        public static ScanResult RunScan(string gtPath, Action<ScanProgress>? onProgress = null, CancellationToken ct = default)
        {
            var result = new ScanResult { GtPath = gtPath };

            try
            {
                if (string.IsNullOrEmpty(gtPath) || !Directory.Exists(gtPath))
                {
                    result.Error = "Gorilla Tag path not found";
                    result.Status = "error";
                    return result;
                }

                var phases = new[]
                {
                    new { Name = ".graze", Files = CollectGrazeFiles(gtPath) },
                    new { Name = "Plugins", Files = CollectPluginFiles(gtPath) },
                    new { Name = "DLLs", Files = CollectDllFiles(gtPath) },
                    new { Name = "EXEs", Files = CollectExeFiles(gtPath) },
                    new { Name = "Configs", Files = CollectConfigFiles(gtPath) }
                };

                int totalFiles = phases.Sum(p => p.Files.Count);
                int filesScanned = 0;

                for (int phaseIdx = 0; phaseIdx < phases.Length; phaseIdx++)
                {
                    var phase = phases[phaseIdx];

                    onProgress?.Invoke(new ScanProgress
                    {
                        Phase = phaseIdx,
                        PhaseName = phase.Name,
                        CurrentFile = $"Scanning {phase.Name}...",
                        FilesScanned = filesScanned,
                        TotalFiles = totalFiles,
                        Percentage = totalFiles > 0 ? (double)filesScanned / totalFiles * 100 : 0
                    });

                    foreach (string filePath in phase.Files)
                    {
                        ct.ThrowIfCancellationRequested();

                        string fileName = Path.GetFileName(filePath);

                        onProgress?.Invoke(new ScanProgress
                        {
                            Phase = phaseIdx,
                            PhaseName = phase.Name,
                            CurrentFile = fileName,
                            FilesScanned = filesScanned,
                            TotalFiles = totalFiles,
                            Percentage = totalFiles > 0 ? (double)filesScanned / totalFiles * 100 : 0
                        });

                        try
                        {
                            byte[] fileBytes = File.ReadAllBytes(filePath);
                            var threats = AnalyzeFile(filePath, fileBytes);
                            result.Threats.AddRange(threats);
                        }
                        catch { }

                        filesScanned++;
                    }

                    onProgress?.Invoke(new ScanProgress
                    {
                        Phase = phaseIdx + 1,
                        PhaseName = phaseIdx + 1 < phases.Length ? phases[phaseIdx + 1].Name : "Complete",
                        CurrentFile = phase.Name + " complete",
                        FilesScanned = filesScanned,
                        TotalFiles = totalFiles,
                        Percentage = totalFiles > 0 ? (double)filesScanned / totalFiles * 100 : 0
                    });
                }

                result.FilesScanned = filesScanned;

                onProgress?.Invoke(new ScanProgress
                {
                    Phase = 5,
                    PhaseName = "Anti-Hook",
                    CurrentFile = "Checking for hooks and tampering...",
                    FilesScanned = filesScanned,
                    TotalFiles = totalFiles,
                    Percentage = 100
                });

                try
                {
                    var antiHookThreats = AntiHook.RunAntiHookCheck(gtPath);
                    result.Threats.AddRange(antiHookThreats);
                }
                catch { }

                onProgress?.Invoke(new ScanProgress
                {
                    Phase = 6,
                    PhaseName = "Tamper Check",
                    CurrentFile = "Verifying file integrity...",
                    FilesScanned = filesScanned,
                    TotalFiles = totalFiles,
                    Percentage = 100
                });

                try
                {
                    var manifest = TamperDetector.FindSteamManifest(gtPath);
                    if (manifest != null)
                    {
                        var (buildId, version) = TamperDetector.ParseSteamManifest(manifest);
                        if (!string.IsNullOrEmpty(buildId))
                        {
                            var tamperThreats = TamperDetector.RunTamperCheck(gtPath, buildId, version);
                            result.Threats.AddRange(tamperThreats);
                        }
                    }
                }
                catch { }

                onProgress?.Invoke(new ScanProgress
                {
                    Phase = 7,
                    PhaseName = "Complete",
                    CurrentFile = $"Scan complete — {filesScanned} files, {result.Threats.Count} threats",
                    FilesScanned = filesScanned,
                    TotalFiles = totalFiles,
                    Percentage = 100
                });
            }
            catch (OperationCanceledException)
            {
                result.Status = "cancelled";
            }
            catch (Exception ex)
            {
                result.Error = ex.Message;
                result.Status = "error";
                Logger.LogException("Scan", ex);
            }

            return result;
        }

        private static List<ThreatInfo> AnalyzeFile(string filePath, byte[] fileBytes)
        {
            var threats = new List<ThreatInfo>();
            string fileName = Path.GetFileName(filePath);
            string ext = Path.GetExtension(filePath).ToLowerInvariant();
            bool isPlugin = filePath.Contains("plugins", StringComparison.OrdinalIgnoreCase);
            bool isGtDll = KnownGtDlls.Contains(fileName);
            bool isKnownGood = KnownGoodDlls.Contains(fileName) || KnownGoodExes.Contains(fileName);

            threats.AddRange(DetectGrazeByBytes(filePath, fileBytes, fileName));
            threats.AddRange(DetectHiddenFile(filePath, fileName));
            threats.AddRange(DetectDoubleExtension(filePath, fileName));
            threats.AddRange(DetectSymlink(filePath, fileName));
            threats.AddRange(DetectMagicMismatch(filePath, fileBytes, fileName, ext));

            if (ext == ".dll" || ext == ".exe")
            {
                var pe = PeAnalyzer.Analyze(fileBytes);
                if (pe.IsValid)
                {
                    threats.AddRange(DetectPeThreats(filePath, fileBytes, pe, isPlugin, isGtDll, isKnownGood));
                }
                else if (isPlugin)
                {
                    double entropy = PeAnalyzer.CalcEntropy(fileBytes);
                    if (entropy > 6.5 && fileBytes.Length > 10000)
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = fileName,
                            FilePath = filePath,
                            ThreatType = "Obfuscation",
                            FileSize = FormatSize(fileBytes.Length),
                            Severity = Severity.Medium,
                            Description = $"High entropy ({entropy:F1}) in unsigned plugin — possible packing"
                        });
                    }
                }
            }

            if (ext == ".graze" || Directory.Exists(filePath))
            {
                threats.Add(new ThreatInfo
                {
                    FileName = fileName,
                    FilePath = filePath,
                    ThreatType = "Graze",
                    FileSize = "",
                    Severity = Severity.High,
                    Description = ".graze item detected — malicious mod loader artifact"
                });
            }

            return threats;
        }

        private static List<ThreatInfo> DetectGrazeByBytes(string filePath, byte[] fileBytes, string fileName)
        {
            var threats = new List<ThreatInfo>();

            if (fileBytes.Length < 10) return threats;

            bool hasGrazeAscii = ContainsAscii(fileBytes, ".graze") || ContainsAscii(fileBytes, "graze");
            bool hasGrazeUtf16 = ContainsUtf16LE(fileBytes, ".graze") || ContainsUtf16LE(fileBytes, "graze");

            if (hasGrazeAscii || hasGrazeUtf16)
            {
                string ext = Path.GetExtension(filePath).ToLowerInvariant();
                if (ext != ".graze")
                {
                    bool isKnownGood = KnownGoodDlls.Contains(fileName) || KnownGoodExes.Contains(fileName);
                    if (!isKnownGood)
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = fileName,
                            FilePath = filePath,
                            ThreatType = "Graze",
                            FileSize = FormatSize(fileBytes.Length),
                            Severity = Severity.Critical,
                            Description = $"File contains .graze byte signatures but has {ext} extension — likely disguised malware"
                        });
                    }
                }
            }

            if (fileBytes.Length >= 4)
            {
                bool hasMz = fileBytes[0] == 0x4D && fileBytes[1] == 0x5A;
                bool hasGrazeContent = hasGrazeAscii || hasGrazeUtf16;

                if (hasMz && hasGrazeContent)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = fileName,
                        FilePath = filePath,
                        ThreatType = "Graze",
                        FileSize = FormatSize(fileBytes.Length),
                        Severity = Severity.Critical,
                        Description = "PE file containing .graze loader signatures — trojanized DLL"
                    });
                }
            }

            return threats;
        }

        private static List<ThreatInfo> DetectHiddenFile(string filePath, string fileName)
        {
            var threats = new List<ThreatInfo>();

            try
            {
                if (GetFileAttributesEx(filePath, GET_FILEEX_INFO_LEVELS, out var attrData))
                {
                    int attrs = attrData.dwFileAttributes;

                    if ((attrs & FILE_ATTRIBUTE_HIDDEN) != 0)
                    {
                        string ext = Path.GetExtension(filePath).ToLowerInvariant();
                        bool isKnownGood = KnownGoodDlls.Contains(fileName) || KnownGoodExes.Contains(fileName);

                        if (!isKnownGood && (ext == ".graze" || ext == ".dll" || ext == ".exe"))
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = fileName,
                                FilePath = filePath,
                                ThreatType = "Hidden",
                                FileSize = FormatSize(((long)attrData.nFileSizeHigh << 32) | (uint)attrData.nFileSizeLow),
                                Severity = Severity.High,
                                Description = $"Hidden file detected — {fileName} has hidden attribute set"
                            });
                        }
                    }

                    if ((attrs & FILE_ATTRIBUTE_REPARSE_POINT) != 0)
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = fileName,
                            FilePath = filePath,
                            ThreatType = "Symlink",
                            FileSize = "",
                            Severity = Severity.Medium,
                            Description = $"Reparse point detected — {fileName} may be a symlink or junction"
                        });
                    }
                }
            }
            catch { }

            return threats;
        }

        private static List<ThreatInfo> DetectDoubleExtension(string filePath, string fileName)
        {
            var threats = new List<ThreatInfo>();

            string lowerName = fileName.ToLowerInvariant();
            string[] suspiciousPatterns = {
                ".graze.dll", ".graze.exe", ".graze.scr", ".graze.com",
                ".graze.bat", ".graze.cmd", ".graze.pif", ".graze.vbs",
                ".dll.graze", ".exe.graze", ".scr.graze", ".com.graze",
                ".txt.graze", ".jpg.graze", ".png.graze", ".pdf.graze",
                ".doc.graze", ".docx.graze", ".xls.graze", ".xlsx.graze",
                ".mp3.graze", ".mp4.graze", ".zip.graze", ".rar.graze"
            };

            foreach (string pattern in suspiciousPatterns)
            {
                if (lowerName.Contains(pattern))
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = fileName,
                        FilePath = filePath,
                        ThreatType = "Disguise",
                        FileSize = "",
                        Severity = Severity.Critical,
                        Description = $"Double extension detected: {fileName} — likely malware disguised as {Path.GetExtension(fileName.Substring(0, fileName.Length - Path.GetExtension(fileName).Length))} file"
                    });
                    break;
                }
            }

            if (lowerName.Count(c => c == '.') >= 3)
            {
                string[] parts = lowerName.Split('.');
                if (parts.Length >= 3)
                {
                    string secondLast = parts[^2];
                    string last = parts[^1];
                    string[] realExtensions = { "dll", "exe", "scr", "com", "bat", "cmd", "vbs", "ps1", "js", "wsf" };

                    if (realExtensions.Contains(last) && secondLast.Length >= 2 && secondLast.Length <= 4)
                    {
                        bool isKnownGood = KnownGoodDlls.Contains(fileName) || KnownGoodExes.Contains(fileName);
                        if (!isKnownGood)
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = fileName,
                                FilePath = filePath,
                                ThreatType = "Disguise",
                                FileSize = "",
                                Severity = Severity.High,
                                Description = $"Suspicious multi-extension file: {fileName} — may be hiding real file type"
                            });
                        }
                    }
                }
            }

            return threats;
        }

        private static List<ThreatInfo> DetectSymlink(string filePath, string fileName)
        {
            var threats = new List<ThreatInfo>();

            try
            {
                var fileInfo = new FileInfo(filePath);
                var dirInfo = new DirectoryInfo(Path.GetDirectoryName(filePath) ?? "");

                if (dirInfo.Exists)
                {
                    foreach (var link in dirInfo.EnumerateFileSystemInfos())
                    {
                        if (link.Name.Equals(fileName, StringComparison.OrdinalIgnoreCase))
                        {
                            if (link.Attributes.HasFlag(FileAttributes.ReparsePoint))
                            {
                                threats.Add(new ThreatInfo
                                {
                                    FileName = fileName,
                                    FilePath = filePath,
                                    ThreatType = "Symlink",
                                    FileSize = "",
                                    Severity = Severity.Medium,
                                    Description = $"Symbolic link detected: {fileName} points to another location"
                                });
                            }
                            break;
                        }
                    }
                }
            }
            catch { }

            try
            {
                FileAttributes attrs = File.GetAttributes(filePath);
                if (attrs.HasFlag(FileAttributes.ReparsePoint))
                {
                    bool alreadyAdded = threats.Any(t => t.FileName == fileName && t.ThreatType == "Symlink");
                    if (!alreadyAdded)
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = fileName,
                            FilePath = filePath,
                            ThreatType = "Symlink",
                            FileSize = "",
                            Severity = Severity.Medium,
                            Description = $"Reparse point detected: {fileName} is a symlink or junction"
                        });
                    }
                }
            }
            catch { }

            return threats;
        }

        private static List<ThreatInfo> DetectMagicMismatch(string filePath, byte[] fileBytes, string fileName, string ext)
        {
            var threats = new List<ThreatInfo>();

            if (fileBytes.Length < 4) return threats;

            bool isKnownGood = KnownGoodDlls.Contains(fileName) || KnownGoodExes.Contains(fileName);
            if (isKnownGood) return threats;

            bool hasMz = fileBytes[0] == 0x4D && fileBytes[1] == 0x5A;
            bool hasElf = fileBytes[0] == 0x7F && fileBytes[1] == 0x45 && fileBytes[2] == 0x4C && fileBytes[3] == 0x46;
            bool hasZip = fileBytes[0] == 0x50 && fileBytes[1] == 0x4B && fileBytes[2] == 0x03 && fileBytes[3] == 0x04;
            bool hasGz = fileBytes[0] == 0x1F && fileBytes[1] == 0x8B;
            bool hasBz2 = fileBytes[0] == 0x42 && fileBytes[1] == 0x5A && fileBytes[2] == 0x68;
            bool hasXz = fileBytes[0] == 0xFD && fileBytes[1] == 0x37 && fileBytes[2] == 0x7A && fileBytes[3] == 0x58;
            bool hasRar = fileBytes[0] == 0x52 && fileBytes[1] == 0x61 && fileBytes[2] == 0x72 && fileBytes[3] == 0x21;
            bool has7z = fileBytes[0] == 0x37 && fileBytes[1] == 0x7A && fileBytes[2] == 0xBC && fileBytes[3] == 0xAF;
            bool hasPng = fileBytes[0] == 0x89 && fileBytes[1] == 0x50 && fileBytes[2] == 0x4E && fileBytes[3] == 0x47;
            bool hasJpg = fileBytes[0] == 0xFF && fileBytes[1] == 0xD8 && fileBytes[2] == 0xFF;
            bool hasGif = fileBytes[0] == 0x47 && fileBytes[1] == 0x49 && fileBytes[2] == 0x46;
            bool hasPdf = fileBytes[0] == 0x25 && fileBytes[1] == 0x50 && fileBytes[2] == 0x44 && fileBytes[3] == 0x46;
            bool hasPptx = hasZip && fileBytes.Length > 100;
            bool hasDocx = hasZip && fileBytes.Length > 100;

            if (ext == ".dll" || ext == ".exe" || ext == ".scr" || ext == ".com")
            {
                if (!hasMz)
                {
                    string actualType = "unknown";
                    if (hasElf) actualType = "ELF binary";
                    else if (hasZip) actualType = "ZIP archive";
                    else if (hasGz) actualType = "GZ archive";
                    else if (hasPdf) actualType = "PDF document";
                    else if (hasPng) actualType = "PNG image";
                    else if (hasJpg) actualType = "JPG image";
                    else if (hasRar) actualType = "RAR archive";
                    else if (has7z) actualType = "7Z archive";

                    if (actualType != "unknown")
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = fileName,
                            FilePath = filePath,
                            ThreatType = "Disguise",
                            FileSize = FormatSize(fileBytes.Length),
                            Severity = Severity.Critical,
                            Description = $"Magic byte mismatch: {ext} file is actually {actualType} — likely malware disguised"
                        });
                    }
                    else if (fileBytes.Length > 1000)
                    {
                        double entropy = PeAnalyzer.CalcEntropy(fileBytes);
                        if (entropy > 7.0)
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = fileName,
                                FilePath = filePath,
                                ThreatType = "Disguise",
                                FileSize = FormatSize(fileBytes.Length),
                                Severity = Severity.High,
                                Description = $"Binary file with invalid PE header and high entropy ({entropy:F1}) — possible packed payload"
                            });
                        }
                    }
                }
            }

            if (ext == ".txt" || ext == ".log" || ext == ".md" || ext == ".csv" || ext == ".xml" || ext == ".json" || ext == ".html")
            {
                if (hasMz || hasElf || hasZip || hasGz || hasBz2 || hasXz)
                {
                    string actualType = "unknown";
                    if (hasMz) actualType = "PE executable";
                    else if (hasElf) actualType = "ELF binary";
                    else if (hasZip) actualType = "ZIP archive";
                    else if (hasGz) actualType = "GZ archive";
                    else if (hasBz2) actualType = "BZ2 archive";
                    else if (hasXz) actualType = "XZ archive";

                    threats.Add(new ThreatInfo
                    {
                        FileName = fileName,
                        FilePath = filePath,
                        ThreatType = "Disguise",
                        FileSize = FormatSize(fileBytes.Length),
                        Severity = Severity.Critical,
                        Description = $"Text file contains {actualType} magic bytes — likely malware disguised as text"
                    });
                }
            }

            if (ext == ".jpg" || ext == ".jpeg" || ext == ".png" || ext == ".gif" || ext == ".bmp" || ext == ".webp")
            {
                if (hasMz || hasZip || hasElf)
                {
                    string actualType = hasMz ? "PE executable" : hasZip ? "ZIP archive" : "ELF binary";
                    threats.Add(new ThreatInfo
                    {
                        FileName = fileName,
                        FilePath = filePath,
                        ThreatType = "Disguise",
                        FileSize = FormatSize(fileBytes.Length),
                        Severity = Severity.Critical,
                        Description = $"Image file contains {actualType} magic bytes — likely malware disguised as image"
                    });
                }
            }

            if (ext == ".pdf")
            {
                if (!hasPdf && (hasMz || hasZip || hasElf))
                {
                    string actualType = hasMz ? "PE executable" : hasZip ? "ZIP archive" : "ELF binary";
                    threats.Add(new ThreatInfo
                    {
                        FileName = fileName,
                        FilePath = filePath,
                        ThreatType = "Disguise",
                        FileSize = FormatSize(fileBytes.Length),
                        Severity = Severity.Critical,
                        Description = $"PDF file contains {actualType} magic bytes — likely malware disguised as PDF"
                    });
                }
            }

            if (ext == ".zip" || ext == ".rar" || ext == ".7z" || ext == ".gz" || ext == ".tar")
            {
                if (hasMz)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = fileName,
                        FilePath = filePath,
                        ThreatType = "Disguise",
                        FileSize = FormatSize(fileBytes.Length),
                        Severity = Severity.Critical,
                        Description = $"Archive file contains PE executable magic bytes — likely malware disguised as archive"
                    });
                }
            }

            return threats;
        }

        public static string ToJson(ScanResult result)
        {
            return JsonSerializer.Serialize(result, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }

        public static string ToJson(ScanProgress progress)
        {
            return JsonSerializer.Serialize(progress, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
        }
    }
}
