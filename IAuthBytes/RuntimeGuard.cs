using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net.NetworkInformation;
using System.Runtime.InteropServices;
using System.Text;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;

namespace IAuthBytes
{
    internal static class RuntimeGuard
    {
        private static CancellationTokenSource? _cts;
        private static Process? _gtProcess;
        private static readonly HashSet<int> _seenPids = new();
        private static readonly HashSet<string> _seenConnections = new();
        private static FileSystemWatcher? _watcher;

        private static readonly HashSet<string> SuspiciousProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell", "pwsh", "cmd", "wscript", "cscript", "mshta",
            "certutil", "bitsadmin", "regsvr32", "rundll32", "msiexec",
            "wmic", "schtasks", "tasklist", "net", "net1", "netsh",
            "bcdedit", "at", "sc", "curl", "wget", "http",
            "nc", "ncat", "plink", "socat", "tclsh"
        };

        private static readonly HashSet<string> SuspiciousChildPatterns = new(StringComparer.OrdinalIgnoreCase)
        {
            "powershell -enc", "powershell -encodedcommand", "powershell -nop",
            "powershell -executionpolicy bypass", "powershell -w hidden",
            "cmd /c echo", "cmd /c start", "cmd /c type",
            "certutil -urlcache", "certutil -decode",
            "bitsadmin /transfer", "bitsadmin /addfile",
            "reg add", "reg query", "reg delete",
            "schtasks /create", "schtasks /run",
            "wmic process call create", "wmic process list",
            "net user", "net localgroup", "net share",
            "bcdedit /set", "bcdedit /enum",
            "taskkill /f", "taskkill /im",
            "curl -o", "curl -O", "wget",
            "nc -e", "ncat -e", "plink",
            "cmd /c powershell", "cmd /c certutil",
            "cmd /c bitsadmin", "cmd /c regsvr32",
            "cmd /c rundll32", "cmd /c mshta",
            "invoke-expression", "iex(", "iex ",
            "downloadstring", "downloadfile", "downloaddata",
            "invoke-webrequest", "invoke-restmethod",
            "start-process", "start-bitstransfer"
        };

        private static readonly HashSet<string> MaliciousDomains = new(StringComparer.OrdinalIgnoreCase)
        {
            "discord.com/api/webhooks", "discordapp.com/api/webhooks",
            "api.telegram.org/bot", "pastebin.com/api",
            "hastebin.com/api", "rentry.co/api",
            "webhook.site", "requestbin.com",
            "pipedream.net", "ngrok.io"
        };

        private static readonly HashSet<string> SuspiciousFileExtensions = new(StringComparer.OrdinalIgnoreCase)
        {
            ".ps1", ".psm1", ".psd1", ".bat", ".cmd", ".vbs", ".vbe",
            ".wsf", ".wsh", ".hta", ".scr", ".pif", ".com", ".msi"
        };

        private static readonly HashSet<string> SuspiciousRegPaths = new(StringComparer.OrdinalIgnoreCase)
        {
            @"Software\Microsoft\Windows\CurrentVersion\Run",
            @"Software\Microsoft\Windows\CurrentVersion\RunOnce",
            @"Software\Microsoft\Windows\CurrentVersion\RunServices",
            @"Software\Microsoft\Windows\CurrentVersion\RunServicesOnce",
            @"Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            @"Software\Microsoft\Windows NT\CurrentVersion\Winlogon",
            @"SYSTEM\CurrentControlSet\Services"
        };

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcess(uint access, bool inherit, int pid);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr handle);

        [DllImport("psapi.dll")]
        private static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded);

        [DllImport("psapi.dll")]
        private static extern int GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, int nSize);

        private const uint PROCESS_QUERY_INFORMATION = 0x0400;
        private const uint PROCESS_VM_READ = 0x0010;

        public static void StartMonitoring(Action<RuntimeEvent>? onEvent, CancellationToken ct = default)
        {
            StopMonitoring();
            _cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            var token = _cts.Token;

            Task.Run(() => MonitorLoop(onEvent, token), token);
        }

        public static void StopMonitoring()
        {
            _cts?.Cancel();
            _cts?.Dispose();
            _cts = null;
            _seenPids.Clear();
            _seenConnections.Clear();
            try { _watcher?.Dispose(); } catch { }
            _watcher = null;
        }

        private static async Task MonitorLoop(Action<RuntimeEvent>? onEvent, CancellationToken ct)
        {
            while (!ct.IsCancellationRequested)
            {
                try
                {
                    var gtProcs = Process.GetProcessesByName("Gorilla Tag");
                    if (gtProcs.Length == 0)
                    {
                        _gtProcess = null;
                        _seenPids.Clear();
                        await Task.Delay(2000, ct);
                        continue;
                    }

                    _gtProcess = gtProcs[0];

                    CheckChildProcesses(onEvent, _gtProcess);
                    CheckNetworkConnections(onEvent, _gtProcess);
                    CheckLoadedModules(onEvent, _gtProcess);

                    await Task.Delay(1500, ct);
                }
                catch (OperationCanceledException) { break; }
                catch { await Task.Delay(3000, ct); }
            }
        }

        public static void StartFileMonitoring(string gtPath, Action<RuntimeEvent>? onEvent)
        {
            StopFileMonitoring();
            if (!Directory.Exists(gtPath)) return;

            try
            {
                _watcher = new FileSystemWatcher(gtPath)
                {
                    IncludeSubdirectories = true,
                    EnableRaisingEvents = true,
                    NotifyFilter = NotifyFilters.FileName | NotifyFilters.LastWrite | NotifyFilters.CreationTime
                };

                _watcher.Created += (s, e) =>
                {
                    string ext = Path.GetExtension(e.FullPath);
                    if (SuspiciousFileExtensions.Contains(ext))
                    {
                        onEvent?.Invoke(new RuntimeEvent
                        {
                            Type = "file",
                            Severity = "warning",
                            Message = $"Suspicious file created: {Path.GetFileName(e.FullPath)} ({ext}) in {Path.GetDirectoryName(e.FullPath)}"
                        });
                    }
                };

                _watcher.Changed += (s, e) =>
                {
                    if (e.FullPath.EndsWith(".dll", StringComparison.OrdinalIgnoreCase) ||
                        e.FullPath.EndsWith(".exe", StringComparison.OrdinalIgnoreCase))
                    {
                        onEvent?.Invoke(new RuntimeEvent
                        {
                            Type = "file",
                            Severity = "info",
                            Message = $"Binary modified: {Path.GetFileName(e.FullPath)}"
                        });
                    }
                };
            }
            catch { }
        }

        public static void StopFileMonitoring()
        {
            try { _watcher?.Dispose(); } catch { }
            _watcher = null;
        }

        private static void CheckChildProcesses(Action<RuntimeEvent>? onEvent, Process gtProcess)
        {
            try
            {
                var childProcs = GetChildProcesses(gtProcess.Id);
                foreach (var child in childProcs)
                {
                    if (_seenPids.Contains(child.Id)) continue;
                    _seenPids.Add(child.Id);

                    string name = child.ProcessName.ToLowerInvariant();
                    string cmdLine = GetCommandLine(child.Id);

                    if (SuspiciousProcesses.Contains(name))
                    {
                        string sev = "warning";
                        string msg = $"Suspicious child process: {child.ProcessName} (PID {child.Id})";

                        if (name is "powershell" or "pwsh")
                        {
                            sev = "critical";
                            if (cmdLine.Contains("-enc", StringComparison.OrdinalIgnoreCase) ||
                                cmdLine.Contains("-encodedcommand", StringComparison.OrdinalIgnoreCase))
                                msg = $"PowerShell encoded command detected (PID {child.Id}): {TruncateCmd(cmdLine)}";
                            else if (cmdLine.Contains("-w hidden", StringComparison.OrdinalIgnoreCase) ||
                                     cmdLine.Contains("-windowstyle hidden", StringComparison.OrdinalIgnoreCase))
                                msg = $"Hidden PowerShell detected (PID {child.Id}): {TruncateCmd(cmdLine)}";
                            else if (cmdLine.Contains("invoke-expression", StringComparison.OrdinalIgnoreCase) ||
                                     cmdLine.Contains("iex", StringComparison.OrdinalIgnoreCase))
                                msg = $"PowerShell IEX/Invoke-Expression detected (PID {child.Id}): {TruncateCmd(cmdLine)}";
                            else if (cmdLine.Contains("downloadstring", StringComparison.OrdinalIgnoreCase) ||
                                     cmdLine.Contains("downloadfile", StringComparison.OrdinalIgnoreCase) ||
                                     cmdLine.Contains("invoke-webrequest", StringComparison.OrdinalIgnoreCase) ||
                                     cmdLine.Contains("invoke-restmethod", StringComparison.OrdinalIgnoreCase))
                                msg = $"PowerShell download cradle detected (PID {child.Id}): {TruncateCmd(cmdLine)}";
                            else if (cmdLine.Contains("bypass", StringComparison.OrdinalIgnoreCase) ||
                                     cmdLine.Contains("executionpolicy", StringComparison.OrdinalIgnoreCase))
                                msg = $"PowerShell bypass execution policy (PID {child.Id}): {TruncateCmd(cmdLine)}";
                            else
                                msg = $"PowerShell spawned by GT (PID {child.Id}): {TruncateCmd(cmdLine)}";
                        }
                        else if (name is "cmd")
                        {
                            if (SuspiciousChildPatterns.Any(p => cmdLine.Contains(p, StringComparison.OrdinalIgnoreCase)))
                            {
                                sev = "critical";
                                msg = $"Suspicious cmd.exe command (PID {child.Id}): {TruncateCmd(cmdLine)}";
                            }
                        }
                        else if (name is "certutil")
                        {
                            sev = "critical";
                            msg = $"CertUtil execution (possible payload download/decode) PID {child.Id}: {TruncateCmd(cmdLine)}";
                        }
                        else if (name is "regsvr32")
                        {
                            sev = "critical";
                            msg = $"RegSvr32 execution (possible DLL sideloading) PID {child.Id}: {TruncateCmd(cmdLine)}";
                        }
                        else if (name is "rundll32")
                        {
                            sev = "critical";
                            msg = $"Rundll32 execution PID {child.Id}: {TruncateCmd(cmdLine)}";
                        }
                        else if (name is "mshta")
                        {
                            sev = "critical";
                            msg = $"MSHTA execution (possible HTA payload) PID {child.Id}: {TruncateCmd(cmdLine)}";
                        }
                        else if (name is "wscript" or "cscript")
                        {
                            sev = "critical";
                            msg = $"Script host execution (possible VBScript/JScript) PID {child.Id}: {TruncateCmd(cmdLine)}";
                        }
                        else if (name is "bitsadmin")
                        {
                            sev = "critical";
                            msg = $"BITSAdmin execution (possible download) PID {child.Id}: {TruncateCmd(cmdLine)}";
                        }
                        else if (name is "wmic")
                        {
                            sev = "warning";
                            msg = $"WMIC execution PID {child.Id}: {TruncateCmd(cmdLine)}";
                        }

                        onEvent?.Invoke(new RuntimeEvent
                        {
                            Type = "process",
                            Severity = sev,
                            Message = msg,
                            Pid = child.Id
                        });
                    }
                }
            }
            catch { }
        }

        private static void CheckNetworkConnections(Action<RuntimeEvent>? onEvent, Process gtProcess)
        {
            try
            {
                var properties = IPGlobalProperties.GetIPGlobalProperties();
                var connections = properties.GetActiveTcpConnections();

                foreach (var conn in connections)
                {
                    if (conn.State != TcpState.Established) continue;

                    string key = $"{conn.RemoteEndPoint.Address}:{conn.RemoteEndPoint.Port}";
                    if (_seenConnections.Contains(key)) continue;
                    _seenConnections.Add(key);

                    string remoteIp = conn.RemoteEndPoint.Address.ToString();
                    int remotePort = conn.RemoteEndPoint.Port;

                    if (IsLocalhost(remoteIp)) continue;

                    if (IsSuspiciousPort(remotePort))
                    {
                        onEvent?.Invoke(new RuntimeEvent
                        {
                            Type = "network",
                            Severity = "warning",
                            Message = $"Suspicious outbound connection to {remoteIp}:{remotePort} (known malware port)"
                        });
                    }
                    else if (IsKnownBadPort(remotePort))
                    {
                        onEvent?.Invoke(new RuntimeEvent
                        {
                            Type = "network",
                            Severity = "critical",
                            Message = $"C2-style connection to {remoteIp}:{remotePort} (high-risk port)"
                        });
                    }
                }
            }
            catch { }
        }

        private static void CheckLoadedModules(Action<RuntimeEvent>? onEvent, Process gtProcess)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, gtProcess.Id);
                if (hProcess == IntPtr.Zero) return;

                try
                {
                    IntPtr[] modules = new IntPtr[512];
                    if (EnumProcessModules(hProcess, modules, modules.Length * IntPtr.Size, out int cbNeeded))
                    {
                        int count = cbNeeded / IntPtr.Size;
                        for (int i = 0; i < count; i++)
                        {
                            if (modules[i] == IntPtr.Zero) continue;

                            var sb = new StringBuilder(512);
                            if (GetModuleFileNameEx(hProcess, modules[i], sb, 512) > 0)
                            {
                                string modPath = sb.ToString();
                                string modName = Path.GetFileName(modPath);

                                if (IsSuspiciousModule(modName, modPath, gtProcess.Id))
                                {
                                    onEvent?.Invoke(new RuntimeEvent
                                    {
                                        Type = "module",
                                        Severity = "warning",
                                        Message = $"Suspicious module loaded: {modName} ({modPath})"
                                    });
                                }
                            }
                        }
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch { }
        }

        private static bool IsSuspiciousModule(string name, string path, int gtPid)
        {
            string lower = name.ToLowerInvariant();
            string lowerPath = path.ToLowerInvariant();

            if (lowerPath.Contains("temp") || lowerPath.Contains("appdata") || lowerPath.Contains("downloads"))
                return true;

            if (lower.StartsWith("test") && lower.EndsWith(".dll"))
                return true;

            if (!lowerPath.Contains("gorilla tag") && !lowerPath.Contains("bepinex") &&
                !lowerPath.Contains("melonloader") && !lowerPath.Contains("monomod") &&
                !lowerPath.Contains("harmony") && !lowerPath.Contains("il2cpp") &&
                !Scanner.IsKnownGoodModule(lower))
                return true;

            string[] proxyDlls = {
                "version.dll", "winhttp.dll", "wtsapi32.dll", "dbghelp.dll",
                "profapi.dll", "msasn1.dll", "cryptsp.dll", "cryptbase.dll",
                "d3d9.dll", "opengl32.dll", "dsound.dll", "dinput8.dll"
            };
            if (proxyDlls.Contains(lower))
            {
                if (!lowerPath.Contains("system32") && !lowerPath.Contains("syswow64"))
                    return true;
            }

            if (lower.Contains("hook") || lower.Contains("inject") || lower.Contains("cheat") ||
                lower.Contains("exploit") || lower.Contains("payload") || lower.Contains("loader") ||
                lower.Contains("injector") || lower.Contains("proxy"))
                return true;

            return false;
        }

        public static void CheckRegistryPersistence(Action<RuntimeEvent>? onEvent)
        {
            foreach (string regPath in SuspiciousRegPaths)
            {
                try
                {
                    using var key = Microsoft.Win32.Registry.LocalMachine.OpenSubKey(regPath);
                    if (key == null) continue;

                    foreach (string valueName in key.GetValueNames())
                    {
                        string? val = key.GetValue(valueName)?.ToString();
                        if (string.IsNullOrEmpty(val)) continue;

                        if (val.Contains("Gorilla", StringComparison.OrdinalIgnoreCase) ||
                            val.Contains("gt-", StringComparison.OrdinalIgnoreCase) ||
                            val.Contains("bepinex", StringComparison.OrdinalIgnoreCase))
                        {
                            onEvent?.Invoke(new RuntimeEvent
                            {
                                Type = "registry",
                                Severity = "critical",
                                Message = $"GT persistence entry found: {regPath}\\{valueName} = {TruncateCmd(val)}"
                            });
                        }

                        if (val.Contains("powershell", StringComparison.OrdinalIgnoreCase) ||
                            val.Contains("cmd.exe", StringComparison.OrdinalIgnoreCase) ||
                            val.Contains("mshta", StringComparison.OrdinalIgnoreCase) ||
                            val.Contains("wscript", StringComparison.OrdinalIgnoreCase))
                        {
                            onEvent?.Invoke(new RuntimeEvent
                            {
                                Type = "registry",
                                Severity = "critical",
                                Message = $"Suspicious registry run key: {regPath}\\{valueName} = {TruncateCmd(val)}"
                            });
                        }
                    }
                }
                catch { }
            }
        }

        public static void ScanMemoryPatterns(int pid, Action<RuntimeEvent>? onEvent)
        {
            try
            {
                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, pid);
                if (hProcess == IntPtr.Zero) return;

                try
                {
                    var sysInfo = new NativeMethods.SYSTEM_INFO();
                    NativeMethods.GetSystemInfo(ref sysInfo);

                    IntPtr currentAddr = sysInfo.lpMinimumApplicationAddress;
                    IntPtr maxAddr = sysInfo.lpMaximumApplicationAddress;

                    byte[] buffer = new byte[4096];
                    var badPatterns = new[]
                    {
                        Encoding.ASCII.GetBytes("discord.com/api/webhooks"),
                        Encoding.ASCII.GetBytes("api.telegram.org"),
                        Encoding.Unicode.GetBytes("discord.com/api/webhooks"),
                        Encoding.Unicode.GetBytes("api.telegram.org"),
                        Encoding.ASCII.GetBytes("Invoke-Expression"),
                        Encoding.ASCII.GetBytes("System.Reflection.Assembly.Load"),
                        Encoding.ASCII.GetBytes("SeedPhrase"),
                        Encoding.ASCII.GetBytes("mnemonic"),
                        Encoding.ASCII.GetBytes("private key"),
                        Encoding.ASCII.GetBytes("wallet.dat"),
                        Encoding.ASCII.GetBytes("exodus"),
                        Encoding.ASCII.GetBytes("metamask"),
                        Encoding.ASCII.GetBytes("phantom"),
                        Encoding.ASCII.GetBytes("Authorization"),
                        Encoding.ASCII.GetBytes("Bearer"),
                        Encoding.ASCII.GetBytes("WLAN_PROFILE"),
                        Encoding.ASCII.GetBytes("keyMaterial"),
                        Encoding.ASCII.GetBytes("Login Data"),
                        Encoding.ASCII.GetBytes("logins.json"),
                        Encoding.ASCII.GetBytes("cmd /c del"),
                        Encoding.ASCII.GetBytes("cmd /c timeout"),
                        Encoding.ASCII.GetBytes("NtCreateSection"),
                        Encoding.ASCII.GetBytes("NtMapViewOfSection"),
                        Encoding.ASCII.GetBytes("CredEnumerate"),
                        Encoding.ASCII.GetBytes("CertOpenStore"),
                        Encoding.ASCII.GetBytes("NetShareEnum"),
                        Encoding.ASCII.GetBytes("WNetEnumResource"),
                        Encoding.Unicode.GetBytes("SeedPhrase"),
                        Encoding.Unicode.GetBytes("mnemonic"),
                        Encoding.Unicode.GetBytes("private key"),
                        Encoding.Unicode.GetBytes("wallet.dat"),
                        Encoding.Unicode.GetBytes("exodus"),
                        Encoding.Unicode.GetBytes("metamask"),
                        Encoding.Unicode.GetBytes("phantom"),
                    };

                    while ((long)currentAddr < (long)maxAddr)
                    {
                        if (NativeMethods.VirtualQueryEx(hProcess, currentAddr, out var memInfo, (uint)Marshal.SizeOf(typeof(NativeMethods.MEMORY_BASIC_INFORMATION))) == 0)
                        {
                            currentAddr = IntPtr.Add(currentAddr, 65536);
                            continue;
                        }

                        if (memInfo.State == 0x1000 && (memInfo.Protect & 0x20) != 0)
                        {
                            int regionSize = Math.Min((int)memInfo.RegionSize, buffer.Length);
                            if (NativeMethods.ReadProcessMemory(hProcess, currentAddr, buffer, regionSize, out int bytesRead) && bytesRead > 0)
                            {
                                foreach (var pattern in badPatterns)
                                {
                                    if (FindPatternInBuffer(buffer, bytesRead, pattern))
                                    {
                                        onEvent?.Invoke(new RuntimeEvent
                                        {
                                            Type = "memory",
                                            Severity = "critical",
                                            Message = $"Malicious string found in GT process memory at 0x{currentAddr.ToInt64():X}: {Encoding.ASCII.GetString(pattern)}"
                                        });
                                    }
                                }
                            }
                        }

                        currentAddr = IntPtr.Add(currentAddr, Math.Max((int)memInfo.RegionSize, 4096));
                    }
                }
                finally
                {
                    CloseHandle(hProcess);
                }
            }
            catch { }
        }

        private static bool FindPatternInBuffer(byte[] buffer, int length, byte[] pattern)
        {
            for (int i = 0; i <= length - pattern.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < pattern.Length; j++)
                {
                    if (buffer[i + j] != pattern[j]) { match = false; break; }
                }
                if (match) return true;
            }
            return false;
        }

        private static List<Process> GetChildProcesses(int parentId)
        {
            var children = new List<Process>();
            try
            {
                foreach (var proc in Process.GetProcesses())
                {
                    try
                    {
                        if (proc.Id == parentId) continue;
                        if (proc.Id == 0 || proc.Id == 4) continue;
                        IntPtr handle = OpenProcess(0x1000, false, proc.Id);
                        if (handle == IntPtr.Zero) continue;

                        int ppid = 0;
                        try
                        {
                            var pbi = new NativeMethods.PROCESS_BASIC_INFORMATION();
                            if (NativeMethods.NtQueryInformationProcess(handle, 0, ref pbi, Marshal.SizeOf(pbi), out int retLen) == 0)
                                ppid = (int)pbi.InheritedFromUniqueProcessId;
                        }
                        catch { }
                        finally
                        {
                            CloseHandle(handle);
                        }

                        if (ppid == parentId)
                            children.Add(proc);
                    }
                    catch { }
                }
            }
            catch { }
            return children;
        }

        private static string GetCommandLine(int pid)
        {
            try
            {
                using var proc = Process.GetProcessById(pid);
                string args = proc.StartInfo?.Arguments ?? "";
                if (!string.IsNullOrEmpty(args)) return args;

                string? modulePath = proc.MainModule?.FileName;
                if (!string.IsNullOrEmpty(modulePath)) return modulePath;
            }
            catch { }
            return "";
        }

        private static bool IsLocalhost(string ip)
        {
            return ip == "127.0.0.1" || ip == "::1" || ip == "0.0.0.0" || ip.StartsWith("192.168.") || ip.StartsWith("10.");
        }

        private static bool IsSuspiciousPort(int port)
        {
            return port is 4444 or 5555 or 1234 or 6666 or 7777 or 8888 or 9999
                or 1337 or 31337 or 44444 or 55555 or 12345 or 54321
                or 8080 or 8443 or 9090 or 4433 or 7070
                or 1080 or 3389 or 5900 or 5901 or 445
                or 135 or 139 or 8443 or 9443 or 2083 or 2087
                or 2096 or 8888 or 2052 or 2082 or 2086 or 2095;
        }

        private static bool IsKnownBadPort(int port)
        {
            return port is 4444 or 5555 or 1337 or 31337 or 44444 or 12345 or 54321
                or 1080 or 445 or 135 or 5900 or 5901;
        }

        private static string TruncateCmd(string s)
        {
            if (s.Length > 120) return s[..120] + "...";
            return s;
        }

        public static string ToJson(RuntimeEvent evt) =>
            JsonSerializer.Serialize(evt, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        private static class NativeMethods
        {
            [StructLayout(LayoutKind.Sequential)]
            public struct SYSTEM_INFO
            {
                public ushort processorArchitecture;
                public ushort reserved;
                public uint pageSize;
                public IntPtr lpMinimumApplicationAddress;
                public IntPtr lpMaximumApplicationAddress;
                public IntPtr ActiveProcessorMask;
                public uint numberOfProcessors;
                public uint processorType;
                public uint allocationGranularity;
                public ushort processorLevel;
                public ushort processorRevision;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct MEMORY_BASIC_INFORMATION
            {
                public IntPtr BaseAddress;
                public IntPtr AllocationBase;
                public uint AllocationProtect;
                public IntPtr RegionSize;
                public uint State;
                public uint Protect;
                public uint Type;
            }

            [StructLayout(LayoutKind.Sequential)]
            public struct PROCESS_BASIC_INFORMATION
            {
                public IntPtr Reserved1;
                public IntPtr PebBaseAddress;
                public IntPtr Reserved2_0;
                public IntPtr Reserved2_1;
                public IntPtr UniqueProcessId;
                public IntPtr InheritedFromUniqueProcessId;
            }

            [DllImport("kernel32.dll")]
            public static extern void GetSystemInfo(ref SYSTEM_INFO lpSystemInfo);

            [DllImport("kernel32.dll")]
            public static extern int VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, uint dwLength);

            [DllImport("kernel32.dll")]
            public static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

            [DllImport("ntdll.dll")]
            public static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref PROCESS_BASIC_INFORMATION processInformation, int processInformationLength, out int returnLength);
        }
    }
}
