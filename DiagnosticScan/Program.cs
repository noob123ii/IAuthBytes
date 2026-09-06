using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography.X509Certificates;
using System.Text;

namespace IAuthBytes
{
    class DiagnosticScan
    {
        static int Main(string[] args)
        {
            string gtagPath = args.Length > 0 ? args[0] : @"C:\Program Files (x86)\Steam\steamapps\common\Gorilla Tag";

            if (!Directory.Exists(gtagPath))
            {
                Console.WriteLine($"Path not found: {gtagPath}");
                return 1;
            }

            Console.WriteLine($"=== IAuthBytes Diagnostic Scan ===");
            Console.WriteLine($"Scanning: {gtagPath}");
            Console.WriteLine();

            var opts = new EnumerationOptions { RecurseSubdirectories = true, IgnoreInaccessible = true };
            var knownGood = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            {
                "UnityPlayer.dll", "UnityPlayer.so",
                "winhttp.dll", "version.dll", "dsound.dll", "dinput8.dll",
                "d3d9.dll", "d3d11.dll", "dxgi.dll", "opengl32.dll",
                "ogg.dll", "vorbis.dll", "vorbisfile.dll",
                "audiokinetic.dll", "wwise.dll",
                "steam_api.dll", "steam_api64.dll",
                "System.Drawing.dll",
                "mscorlib.dll", "netstandard.dll",
            };

            var dlls = Directory.EnumerateFiles(gtagPath, "*.dll", opts).ToList();
            int flagged = 0;
            int skipped = 0;
            int errored = 0;

            Console.WriteLine($"Found {dlls.Count} DLLs total");
            Console.WriteLine(new string('=', 120));
            Console.WriteLine($"{"File",-45} {"Size",10} {"Entropy",8} {"Reasons"}");
            Console.WriteLine(new string('-', 120));

            foreach (string dll in dlls)
            {
                string fileName = Path.GetFileName(dll);

                if (knownGood.Contains(fileName))
                {
                    skipped++;
                    continue;
                }

                var reasons = new List<string>();
                var info = new FileInfo(dll);

                byte[] bytes;
                try { bytes = File.ReadAllBytes(dll); }
                catch { errored++; continue; }

                // Size check
                long sizeBytes = info.Length;
                if (sizeBytes >= 9700 && sizeBytes <= 9800)
                    reasons.Add($"Malware size ({sizeBytes} bytes)");

                // Entropy
                double entropy = PeAnalyzer.CalcEntropy(bytes);
                bool highEntropy = entropy > 7.5;
                if (highEntropy)
                    reasons.Add($"High entropy ({entropy:F2})");

                // PE analysis
                var pe = PeAnalyzer.Analyze(bytes);
                if (pe.IsValid)
                {
                    if (pe.OverlaySize > 50 * 1024)
                        reasons.Add($"Overlay ({pe.OverlaySize} bytes)");

                    if (!highEntropy)
                    {
                        foreach (var section in pe.Sections)
                        {
                            if (section.Entropy > 7.5 && section.RawSize > 512)
                            {
                                reasons.Add($"High entropy section: {section.Name} ({section.Entropy:F2})");
                                break;
                            }
                        }
                    }

                    string[] suspiciousImports = { "wininet.dll", "urlmon.dll",
                        "crypt32.dll", "wldap32.dll" };
                    foreach (string importedDll in pe.ImportedDlls)
                    {
                        if (suspiciousImports.Any(s => s.Equals(importedDll, StringComparison.OrdinalIgnoreCase)))
                        {
                            reasons.Add($"Suspicious import: {importedDll}");
                            break;
                        }
                    }

                    if (pe.HasResourceSection && pe.ResourceSize > 50000)
                        reasons.Add($"Large resources ({pe.ResourceSize} bytes)");
                }

                // Raw patterns on windowed bytes
                byte[] scanBytes = bytes.Length > 2 * 1024 * 1024
                    ? GetScanWindow(bytes)
                    : bytes;

                DetectRawPatterns(scanBytes, reasons, Path.GetFileName(dll));
                DetectEmbeddedExecutables(scanBytes, reasons);

                // Unsigned check
#pragma warning disable SYSLIB0057
                try { using var cert = X509Certificate.CreateFromSignedFile(dll); if (cert == null) reasons.Add("Unsigned"); }
                catch { reasons.Add("Unsigned"); }
#pragma warning restore SYSLIB0057

                string reasonStr = reasons.Count > 0 ? string.Join(" | ", reasons) : "(clean)";

                string shortPath = dll.Replace(gtagPath, "").TrimStart('\\', '/');
                if (shortPath.Length > 44) shortPath = "..." + shortPath[^41..];

                string line = $"{shortPath,-45} {FormatSize(info.Length),10} {entropy,8:F2} {reasonStr}";

                int threatReasons = reasons.Count(r => r != "Unsigned" && !r.StartsWith("Suspicious import:"));
                string[] strongIndicators = { "Steam stealer", "Keylogger", "LSASS dump", "Ransomware",
                    "Injection APIs", "Process hollowing", "Reflective PE loading", "Clipboard",
                    "Screen capture", "Download-and-execute", "Credential theft", "Browser stealer",
                    "Privilege escalation", "UAC bypass", "Service install", "Scheduled task",
                    "WMI persistence", "Data exfiltration", "DNS exfiltration", "PowerShell execution",
                    "DLL sideloading", "Socket C2", "Multi-stage loader", "Hidden console injection",
                    "PowerShell download", "Anti-analysis", "VM detection", "Shellcode pattern",
                    "Embedded executable", "Packed payload", "Reflection abuse" };
                bool hasStrongIndicator = reasons.Any(r => strongIndicators.Contains(r));
                if (threatReasons >= 2 || hasStrongIndicator)
                {
                    Console.ForegroundColor = threatReasons >= 3 ? ConsoleColor.Red : ConsoleColor.Yellow;
                    Console.WriteLine(line);
                    Console.ResetColor();
                    flagged++;
                }
                else if (reasons.Count >= 1)
                {
                    Console.ForegroundColor = ConsoleColor.DarkGray;
                    Console.WriteLine(line);
                    Console.ResetColor();
                }
            }

            Console.WriteLine(new string('=', 120));
            Console.WriteLine($"Total: {dlls.Count} DLLs, {flagged} flagged (2+ reasons), {skipped} skipped (known good), {errored} errors");
            return flagged;
        }

        static void DetectRawPatterns(byte[] bytes, List<string> reasons, string fileName)
        {
            // Injection: requires CreateRemoteThread + VirtualAllocEx + WriteProcessMemory together
            bool foundCRT = ContainsAscii(bytes, "CreateRemoteThread");
            bool foundVAE = ContainsAscii(bytes, "VirtualAllocEx");
            bool foundWPM = ContainsAscii(bytes, "WriteProcessMemory");
            if (foundCRT && foundVAE && foundWPM)
                reasons.Add("Injection APIs");

            // Keylogger: requires GetAsyncKeyState + SetWindowsHookEx together
            if (ContainsAscii(bytes, "GetAsyncKeyState") && ContainsAscii(bytes, "SetWindowsHookEx"))
                reasons.Add("Keylogger");

            // Process hollowing: requires NtUnmapViewOfSection + SetThreadContext together
            if (ContainsAscii(bytes, "NtUnmapViewOfSection") && ContainsAscii(bytes, "SetThreadContext"))
                reasons.Add("Process hollowing");

            // Screen capture: requires BitBlt + GetDC + CreateCompatibleDC + GetDesktopWindow together
            if (ContainsAscii(bytes, "BitBlt") && ContainsAscii(bytes, "GetDC") &&
                ContainsAscii(bytes, "CreateCompatibleDC") && ContainsAscii(bytes, "GetDesktopWindow"))
                reasons.Add("Screen capture");

            // Clipboard: requires both OpenClipboard + GetClipboardData
            if (ContainsAscii(bytes, "OpenClipboard") && ContainsAscii(bytes, "GetClipboardData"))
                reasons.Add("Clipboard");

            // Steam stealer: requires GetAuthSessionTicket + discord/webhook/POST together
            bool foundSteam = ContainsAscii(bytes, "GetAuthSessionTicket") || ContainsAscii(bytes, "GetAuthTicketForWebApi");
            bool foundExfil = ContainsAscii(bytes, "discord.com") || ContainsAscii(bytes, "webhook") ||
                              ContainsAscii(bytes, "UploadString") || ContainsAscii(bytes, "UploadFile");
            if (foundSteam && foundExfil)
                reasons.Add("Steam stealer");

            // Download-and-execute: requires download + process creation + execution context
            bool foundDL = ContainsAscii(bytes, "DownloadFile") || ContainsAscii(bytes, "DownloadData") || ContainsAscii(bytes, "DownloadString");
            bool foundCreateProcess = ContainsAscii(bytes, "CreateProcess") || ContainsAscii(bytes, "ShellExecute");
            bool foundExecCtx = ContainsAscii(bytes, "powershell") || ContainsAscii(bytes, "cmd.exe") ||
                                ContainsAscii(bytes, "/c ") || ContainsAscii(bytes, "cmd /c") ||
                                ContainsAscii(bytes, "bash") || ContainsAscii(bytes, "wscript");
            if (foundDL && foundCreateProcess && foundExecCtx)
                reasons.Add("Download-and-execute");

            // Ransomware: requires .encrypted + CryptEncrypt together
            if (ContainsAscii(bytes, ".encrypted") && ContainsAscii(bytes, "CryptEncrypt"))
                reasons.Add("Ransomware");

            // LSASS dump: requires lsass + specific dump APIs
            if (ContainsAscii(bytes, "lsass") &&
                (ContainsAscii(bytes, "MiniDumpWriteDump") || ContainsAscii(bytes, "ReadProcessMemory")))
                reasons.Add("LSASS dump");

            // Socket C2: requires WSASocket/WSAConnect (raw Winsock) + C2-specific strings
            bool foundWSA = ContainsAscii(bytes, "WSASocket") || ContainsAscii(bytes, "WSAConnect") || ContainsAscii(bytes, "WSAIoctl");
            bool foundC2Str = ContainsAscii(bytes, "reverse shell") || ContainsAscii(bytes, "connect-back") ||
                              ContainsAscii(bytes, "beacon") || ContainsAscii(bytes, "command and control") ||
                              ContainsAscii(bytes, "Invoke-Mimikatz") || ContainsAscii(bytes, "meterpreter") ||
                              ContainsAscii(bytes, "reverse_tcp") || ContainsAscii(bytes, ".ssh");
            if (foundWSA && foundC2Str)
                reasons.Add("Socket C2");

            // Multi-stage: requires FromBase64 + download + obfuscation (skip framework DLLs)
            bool isFramework = fileName.StartsWith("System.", StringComparison.OrdinalIgnoreCase) ||
                               fileName.StartsWith("Microsoft.", StringComparison.OrdinalIgnoreCase) ||
                               fileName.Equals("mscorlib.dll", StringComparison.OrdinalIgnoreCase) ||
                               fileName.Equals("netstandard.dll", StringComparison.OrdinalIgnoreCase);
            bool foundObfuscation = ContainsAscii(bytes, "Invoke-Expression") || ContainsAscii(bytes, "IEX") ||
                                    ContainsAscii(bytes, "powershell") || ContainsAscii(bytes, "-enc") ||
                                    ContainsAscii(bytes, "EncodedCommand");
            if (!isFramework && ContainsAscii(bytes, "FromBase64") &&
                (ContainsAscii(bytes, "DownloadString") || ContainsAscii(bytes, "DownloadData")) && foundObfuscation)
                reasons.Add("Multi-stage loader");

            // PowerShell download: IEX + download together
            if ((ContainsAscii(bytes, "Invoke-Expression") || ContainsAscii(bytes, "IEX")) &&
                (ContainsAscii(bytes, "DownloadString") || ContainsAscii(bytes, "DownloadFile") || ContainsAscii(bytes, "Invoke-WebRequest")))
                reasons.Add("PowerShell download");

            // Reflective PE: VirtualAlloc + GetDelegateForFunctionPointer together
            if (ContainsAscii(bytes, "VirtualAlloc") && ContainsAscii(bytes, "GetDelegateForFunctionPointer"))
                reasons.Add("Reflective PE loading");

            // Credential theft: credential store access + exfil patterns
            bool foundCred = ContainsAscii(bytes, "Credentials") || ContainsAscii(bytes, "Login Data") ||
                             ContainsAscii(bytes, "Local State") || ContainsAscii(bytes, "id_rsa") ||
                             ContainsAscii(bytes, "Wlansvc") || ContainsAscii(bytes, "SAM");
            bool foundCredAccess = ContainsAscii(bytes, "CryptUnprotectData") || ContainsAscii(bytes, "CryptProtectData") ||
                                   ContainsAscii(bytes, "sqlite3") || ContainsAscii(bytes, "DPAPI");
            if (foundCred && foundCredAccess)
                reasons.Add("Credential theft");

            // Browser stealer: browser profile paths + sqlite access
            bool foundBrowserPath = ContainsAscii(bytes, "Google\\Chrome") || ContainsAscii(bytes, "Mozilla\\Firefox") ||
                                    ContainsAscii(bytes, "Microsoft\\Edge") || ContainsAscii(bytes, "BraveSoftware") ||
                                    ContainsAscii(bytes, "User Data\\Default") || ContainsAscii(bytes, "MetaMask") ||
                                    ContainsAscii(bytes, "CoinbaseWallet");
            if (foundBrowserPath && ContainsAscii(bytes, "sqlite3"))
                reasons.Add("Browser stealer");

            // Privilege escalation: token manipulation APIs + admin context
            bool foundToken = ContainsAscii(bytes, "ImpersonateLoggedOnUser") || ContainsAscii(bytes, "LogonUser") ||
                              ContainsAscii(bytes, "AdjustTokenPrivileges");
            bool foundAdmin = ContainsAscii(bytes, "Administrator") || ContainsAscii(bytes, "SeDebugPrivilege") ||
                              ContainsAscii(bytes, "SeImpersonatePrivilege");
            if (foundToken && foundAdmin)
                reasons.Add("Privilege escalation");

            // UAC bypass: known UAC bypass binaries + registry manipulation
            bool foundUACBin = ContainsAscii(bytes, "fodhelper.exe") || ContainsAscii(bytes, "eventvwr.exe") ||
                               ContainsAscii(bytes, "computerdefaults.exe") || ContainsAscii(bytes, "sdclt.exe");
            bool foundUACReg = ContainsAscii(bytes, "ms-settings") || ContainsAscii(bytes, "Shell\\Open\\command");
            if (foundUACBin && foundUACReg)
                reasons.Add("UAC bypass");

            // Service install: CreateService + OpenSCManager
            if (ContainsAscii(bytes, "CreateService") && ContainsAscii(bytes, "OpenSCManager"))
                reasons.Add("Service install");

            // Scheduled task: schtasks + create
            if ((ContainsAscii(bytes, "schtasks.exe") || ContainsAscii(bytes, "SCHEDULE_SERVICE")) &&
                (ContainsAscii(bytes, "/create") || ContainsAscii(bytes, "NewWorkItem")))
                reasons.Add("Scheduled task");

            // WMI persistence: WMI event subscription
            bool foundWMI = ContainsAscii(bytes, "__InstanceModificationEvent") || ContainsAscii(bytes, "Win32_StartupCommand") ||
                            ContainsAscii(bytes, "Win32_Process") || ContainsAscii(bytes, "__EventFilter");
            bool foundWMIExec = ContainsAscii(bytes, "Create") || ContainsAscii(bytes, "ExecMethod");
            if (foundWMI && foundWMIExec)
                reasons.Add("WMI persistence");

            // Data exfiltration: requires specific exfil channel + specific target
            bool foundExfilChannel = ContainsAscii(bytes, "discord.com/api/webhooks") || ContainsAscii(bytes, "pastebin.com/api") ||
                                     ContainsAscii(bytes, "api.telegram.org/bot") || (ContainsAscii(bytes, "webhook") && ContainsAscii(bytes, "UploadFile"));
            bool foundExfilTarget = ContainsAscii(bytes, "id_rsa") || ContainsAscii(bytes, ".ssh") ||
                                    ContainsAscii(bytes, "Login Data") || ContainsAscii(bytes, "Cookies") ||
                                    ContainsAscii(bytes, "Local State") || ContainsAscii(bytes, ".keychain");
            if (foundExfilChannel && foundExfilTarget)
                reasons.Add("Data exfiltration");

            // DNS exfiltration: DNS query + explicit evil domain
            if (ContainsAscii(bytes, "DnsQuery") && ContainsAscii(bytes, "evil.com"))
                reasons.Add("DNS exfiltration");

            // PowerShell execution: powershell + encoded command + process creation
            bool foundPSEncoded = ContainsAscii(bytes, "-EncodedCommand") || ContainsAscii(bytes, "-enc ") ||
                                  ContainsAscii(bytes, "EncodedCommand") || ContainsAscii(bytes, "-ExecutionPolicy");
            if (ContainsAscii(bytes, "powershell") && foundPSEncoded &&
                (ContainsAscii(bytes, "CreateProcess") || ContainsAscii(bytes, "Process.Start")))
                reasons.Add("PowerShell execution");

            // DLL sideloading: LoadLibrary + hiding file attributes
            if (ContainsAscii(bytes, "LoadLibrary") && ContainsAscii(bytes, "FileAttributes.Hidden"))
                reasons.Add("DLL sideloading");

            // Anti-analysis: requires 2+ debugger APIs
            int debugAPIs = 0;
            if (ContainsAscii(bytes, "IsDebuggerPresent")) debugAPIs++;
            if (ContainsAscii(bytes, "CheckRemoteDebuggerPresent")) debugAPIs++;
            if (ContainsAscii(bytes, "NtQueryInformationProcess")) debugAPIs++;
            if (ContainsAscii(bytes, "NtSetInformationThread")) debugAPIs++;
            if (debugAPIs >= 3)
                reasons.Add("Anti-analysis");

            // VM detection: VM-specific strings
            bool foundVM = ContainsAscii(bytes, "VMWARE") || ContainsAscii(bytes, "vmGuestServices") ||
                           ContainsAscii(bytes, "VBoxGuest") || ContainsAscii(bytes, "VBoxMouse") ||
                           ContainsAscii(bytes, "SbieDll") || ContainsAscii(bytes, "SxIn.dll") ||
                           ContainsAscii(bytes, "vmtoolsd") || ContainsAscii(bytes, "vmwaretray");
            if (foundVM)
                reasons.Add("VM detection");

            // Hidden console: AllocConsole + FreeConsole + (GetConsoleWindow OR SetConsoleTitle)
            bool foundAllocConsole = ContainsAscii(bytes, "AllocConsole");
            bool foundFreeConsole = ContainsAscii(bytes, "FreeConsole");
            bool foundGetConsole = ContainsAscii(bytes, "GetConsoleWindow") || ContainsAscii(bytes, "SetConsoleTitle");
            if (foundAllocConsole && foundFreeConsole && foundGetConsole)
                reasons.Add("Hidden console injection");

            // Embedded executable: Assembly.Load + payload (specific to malicious loading)
            bool foundAssemblyLoad = ContainsAscii(bytes, "Assembly.Load") || ContainsAscii(bytes, "Assembly.Load(");
            bool foundPayload = ContainsAscii(bytes, "payload");
            if (foundAssemblyLoad && foundPayload)
                reasons.Add("Embedded executable");

            // Packed payload: .NET static array init + Assembly.Load
            bool foundStaticArray = ContainsAscii(bytes, "__StaticArrayInitTypeSize");
            if (foundStaticArray && foundAssemblyLoad)
                reasons.Add("Packed payload");

            // String obfuscation: char array building + Convert.ToChar + String.Join (all 3 required)
            bool foundCharArr = ContainsAscii(bytes, "new char[]");
            bool foundStrJoin = ContainsAscii(bytes, "String.Join");
            bool foundToChar = ContainsAscii(bytes, "Convert.ToChar");
            if (foundCharArr && foundStrJoin && foundToChar)
                reasons.Add("String obfuscation");

            // Base64 obfuscation: FromBase64String + Convert + specific loader pattern
            bool foundB64 = ContainsAscii(bytes, "FromBase64String");
            bool foundConvert = ContainsAscii(bytes, "Convert.FromBase64") || ContainsAscii(bytes, "Convert.ToByte");
            if (foundB64 && foundConvert && (ContainsAscii(bytes, "Assembly.Load") || ContainsAscii(bytes, "Process.Start")))
                reasons.Add("Base64 obfuscation");

            // Reflection abuse: requires Type.GetType + InvokeMember + Assembly.Load together
            bool foundGetType = ContainsAscii(bytes, "Type.GetType");
            bool foundInvoke = ContainsAscii(bytes, "InvokeMember") || ContainsAscii(bytes, "MethodInfo.Invoke");
            if (foundGetType && foundInvoke && foundAssemblyLoad)
                reasons.Add("Reflection abuse");
        }

        static bool ContainsAscii(byte[] data, string pattern)
        {
            if (pattern.Length > data.Length) return false;

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

            byte[] patUtf16 = Encoding.Unicode.GetBytes(pattern);
            for (int i = 0; i <= data.Length - patUtf16.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < patUtf16.Length; j++)
                {
                    if (data[i + j] != patUtf16[j]) { match = false; break; }
                }
                if (match) return true;
            }

            return false;
        }

        static bool ContainsBytes(byte[] data, byte[] pattern)
        {
            if (pattern.Length > data.Length) return false;
            for (int i = 0; i <= data.Length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (data[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }

        static byte[] GetScanWindow(byte[] fullBytes)
        {
            const int MaxScanBytes = 2 * 1024 * 1024;
            int headSize = MaxScanBytes / 2;
            int tailSize = MaxScanBytes / 2;
            byte[] window = new byte[headSize + tailSize];
            Buffer.BlockCopy(fullBytes, 0, window, 0, headSize);
            Buffer.BlockCopy(fullBytes, fullBytes.Length - tailSize, window, headSize, tailSize);
            return window;
        }

        static void DetectEmbeddedExecutables(byte[] bytes, List<string> reasons)
        {
            if (bytes.Length < 1024) return;

            int mzCount = 0;
            int mzOffset = -1;
            for (int i = 64; i < bytes.Length - 1; i++)
            {
                if (bytes[i] == 0x4D && bytes[i + 1] == 0x5A)
                {
                    if (i + 64 < bytes.Length)
                    {
                        int pePtr = BitConverter.ToInt32(bytes, i + 0x3C);
                        if (pePtr > 0 && pePtr < 1024 && i + pePtr + 4 < bytes.Length)
                        {
                            if (bytes[i + pePtr] == 0x50 && bytes[i + pePtr + 1] == 0x45)
                            {
                                mzCount++;
                                if (mzOffset < 0) mzOffset = i;
                            }
                        }
                    }
                }
            }

            if (mzCount > 0)
                reasons.Add($"Embedded executable ({mzCount} MZ headers at offset 0x{mzOffset:X})");
        }

        static string FormatSize(long bytes)
        {
            string[] u = { "B", "KB", "MB", "GB" };
            double v = bytes; int i = 0;
            while (v >= 1024 && i < u.Length - 1) { v /= 1024; i++; }
            return $"{v:0.##} {u[i]}";
        }
    }
}
