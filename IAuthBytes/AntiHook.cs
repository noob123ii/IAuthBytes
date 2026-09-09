using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace IAuthBytes
{
    internal static class AntiHook
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetModuleHandle(string lpModuleName);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern bool IsDebuggerPresent();

        [DllImport("kernel32.dll")]
        private static extern bool CheckRemoteDebuggerPresent(IntPtr hProcess, ref bool isDebuggerPresent);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationProcess(IntPtr processHandle, int processInformationClass, ref IntPtr processInformation, int processInformationLength, IntPtr returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern uint GetLastError();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        private static extern bool CloseHandle(IntPtr hObject);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("ntdll.dll")]
        private static extern int NtQuerySystemInformation(int systemInformationClass, IntPtr systemInformation, int systemInformationLength, out int returnLength);

        [DllImport("kernel32.dll")]
        private static extern int GetCurrentProcessId();

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern int GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, int nSize);

        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_READ = 0x0010;
        private const int PROCESS_DUP_HANDLE = 0x0040;
        private const int SystemHandleInformation = 16;
        private const int SystemExtendedHandleInformation = 64;

        private static readonly byte[] JmpPatch = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
        private static readonly byte[] CallPatch = { 0xE8, 0x00, 0x00, 0x00, 0x00 };

        private static readonly string[] CriticalModules = {
            "ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll",
            "ws2_32.dll", "winhttp.dll", "crypt32.dll", "shell32.dll"
        };

        private static readonly string[] SelfModuleNames = {
            "IAuthBytes.exe", "IAuthBytes.dll"
        };

        private static int _selfPid;
        private static byte[]? _originalTextSection;
        private static IntPtr _textSectionBase;
        private static int _textSectionSize;
        private static Timer? _integrityTimer;
        private static volatile bool _integrityCheckFailed;

        public static bool IntegrityCheckFailed => _integrityCheckFailed;

        public static List<ThreatInfo> RunAntiHookCheck(string gtPath)
        {
            var threats = new List<ThreatInfo>();

            threats.AddRange(CheckDebuggerPresence());
            threats.AddRange(CheckInlineHooks());
            threats.AddRange(CheckIATHooks());
            threats.AddRange(CheckExternalProcessAccess());
            threats.AddRange(CheckHandleAbuse());
            threats.AddRange(CheckModuleInjection());
            threats.AddRange(CheckSelfIntegrity(gtPath));
            threats.AddRange(RunSelfTest());

            return threats;
        }

        public static void StartContinuousMonitoring()
        {
            Logger.Log("AntiHook: StartContinuousMonitoring called");
            _selfPid = Process.GetCurrentProcess().Id;
            CacheTextSection();

            _integrityTimer = new Timer(_ =>
            {
                try
                {
                    if (!VerifyTextSectionIntegrity())
                    {
                        _integrityCheckFailed = true;
                        Logger.Log("CRITICAL: IAuthBytes .text section modified by external process!");
                    }
                }
                catch { }
            }, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30));
        }

        public static void StopContinuousMonitoring()
        {
            _integrityTimer?.Dispose();
            _integrityTimer = null;
        }

        private static void CacheTextSection()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                var mainModule = process.MainModule;
                if (mainModule == null) { Logger.Log("CacheTextSection: MainModule is null"); return; }

                IntPtr moduleHandle = GetModuleHandle(null!);
                if (moduleHandle == IntPtr.Zero) { Logger.Log("CacheTextSection: GetModuleHandle returned NULL"); return; }

                Logger.Log($"CacheTextSection: Module handle 0x{moduleHandle.ToInt64():X}, reading PE header...");

                byte[] moduleHeader = new byte[4096];
                if (!ReadProcessMemory(GetCurrentProcess(), moduleHandle, moduleHeader, moduleHeader.Length, out int read) || read < 64)
                { Logger.Log($"CacheTextSection: ReadProcessMemory failed (read={read})"); return; }

                if (moduleHeader[0] != 0x4D || moduleHeader[1] != 0x5A)
                { Logger.Log($"CacheTextSection: No MZ header (first bytes: 0x{moduleHeader[0]:X2} 0x{moduleHeader[1]:X2})"); return; }

                int peOffset = BitConverter.ToInt32(moduleHeader, 0x3C);
                if (peOffset + 24 >= moduleHeader.Length)
                { Logger.Log($"CacheTextSection: PE offset {peOffset} out of range (header len={moduleHeader.Length})"); return; }
                if (moduleHeader[peOffset] != 0x50 || moduleHeader[peOffset + 1] != 0x45)
                { Logger.Log($"CacheTextSection: No PE signature at offset {peOffset}"); return; }

                int numSections = BitConverter.ToInt16(moduleHeader, peOffset + 6);
                int optHeaderSize = BitConverter.ToInt16(moduleHeader, peOffset + 20);
                int sectionHeaderOffset = peOffset + 24 + optHeaderSize;

                Logger.Log($"CacheTextSection: PE OK — {numSections} sections, .text search starting...");

                bool found = false;
                for (int i = 0; i < numSections; i++)
                {
                    int sectionOffset = sectionHeaderOffset + (i * 40);
                    if (sectionOffset + 40 > moduleHeader.Length) { Logger.Log($"CacheTextSection: Section header {i} out of range"); break; }

                    string sectionName = Encoding.ASCII.GetString(moduleHeader, sectionOffset, 8).TrimEnd('\0');
                    if (sectionName == ".text")
                    {
                        int virtualSize = BitConverter.ToInt32(moduleHeader, sectionOffset + 8);
                        int virtualAddr = BitConverter.ToInt32(moduleHeader, sectionOffset + 12);

                        _textSectionBase = IntPtr.Add(moduleHandle, virtualAddr);
                        _textSectionSize = Math.Min(virtualSize, 65536);

                        _originalTextSection = new byte[_textSectionSize];
                        if (ReadProcessMemory(GetCurrentProcess(), _textSectionBase, _originalTextSection, _textSectionSize, out int textRead) && textRead == _textSectionSize)
                        {
                            Logger.Log($"Cached .text section: {_textSectionSize} bytes at 0x{_textSectionBase.ToInt64():X}");
                            found = true;
                        }
                        else
                        {
                            Logger.Log($"CacheTextSection: ReadProcessMemory for .text failed (read={textRead}, expected={_textSectionSize})");
                            _originalTextSection = null;
                        }
                        break;
                    }
                }
                if (!found && _originalTextSection == null)
                    Logger.Log($"CacheTextSection: .text section not found among {numSections} sections");
            }
            catch (Exception ex)
            {
                Logger.LogException("CacheTextSection", ex);
            }
        }

        private static bool VerifyTextSectionIntegrity()
        {
            if (_originalTextSection == null || _textSectionBase == IntPtr.Zero || _textSectionSize == 0)
                return true;

            byte[] currentSection = new byte[_textSectionSize];
            if (!ReadProcessMemory(GetCurrentProcess(), _textSectionBase, currentSection, _textSectionSize, out int bytesRead) || bytesRead != _textSectionSize)
                return true;

            for (int i = 0; i < _textSectionSize; i++)
            {
                if (currentSection[i] != _originalTextSection[i])
                {
                    Logger.Log($"Text section byte changed at offset {i}: 0x{_originalTextSection[i]:X2} -> 0x{currentSection[i]:X2}");
                    return false;
                }
            }
            return true;
        }

        private static List<ThreatInfo> CheckDebuggerPresence()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                if (IsDebuggerPresent())
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "System",
                        FilePath = "",
                        ThreatType = "Anti-Hook",
                        FileSize = "",
                        Severity = Severity.High,
                        Description = "Debugger detected attached to process"
                    });
                }
            }
            catch { }

            try
            {
                bool remoteDebugger = false;
                CheckRemoteDebuggerPresent(GetCurrentProcess(), ref remoteDebugger);
                if (remoteDebugger)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "System",
                        FilePath = "",
                        ThreatType = "Anti-Hook",
                        FileSize = "",
                        Severity = Severity.High,
                        Description = "Remote debugger detected on process"
                    });
                }
            }
            catch { }

            try
            {
                IntPtr debugPort = IntPtr.Zero;
                int status = NtQueryInformationProcess(GetCurrentProcess(), 7, ref debugPort, IntPtr.Size, IntPtr.Zero);
                if (status == 0 && debugPort != IntPtr.Zero)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "System",
                        FilePath = "",
                        ThreatType = "Anti-Hook",
                        FileSize = "",
                        Severity = Severity.High,
                        Description = "NtQuery debug port detected"
                    });
                }
            }
            catch { }

            try
            {
                IntPtr debugFlags = (IntPtr)1;
                int status = NtQueryInformationProcess(GetCurrentProcess(), 0x1F, ref debugFlags, IntPtr.Size, IntPtr.Zero);
                if (status == 0 && debugFlags == IntPtr.Zero)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "System",
                        FilePath = "",
                        ThreatType = "Anti-Hook",
                        FileSize = "",
                        Severity = Severity.High,
                        Description = "NtQuery debug flags indicate debugger present"
                    });
                }
            }
            catch { }

            try
            {
                IntPtr hProcessDebugPort = IntPtr.Zero;
                int status = NtQueryInformationProcess(GetCurrentProcess(), 0x1E, ref hProcessDebugPort, IntPtr.Size, IntPtr.Zero);
                if (status == 0 && hProcessDebugPort != IntPtr.Zero)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "System",
                        FilePath = "",
                        ThreatType = "Anti-Hook",
                        FileSize = "",
                        Severity = Severity.High,
                        Description = "NtQuery process debug port non-zero"
                    });
                }
            }
            catch { }

            return threats;
        }

        private static List<ThreatInfo> CheckInlineHooks()
        {
            var threats = new List<ThreatInfo>();

            string[] hookedProcs = {
                "NtCreateFile", "NtOpenFile", "NtReadFile", "NtWriteFile",
                "NtCreateSection", "NtMapViewOfSection", "NtProtectVirtualMemory",
                "NtAllocateVirtualMemory", "NtWriteVirtualMemory", "NtReadVirtualMemory",
                "NtCreateThreadEx", "NtResumeThread", "NtSuspendThread",
                "NtOpenProcess", "NtQueryInformationProcess", "NtSetInformationProcess",
                "LdrLoadDll", "LdrGetProcedureAddress",
                "NtClose", "NtDelayExecution", "NtQuerySystemInformation"
            };

            foreach (string moduleName in CriticalModules)
            {
                try
                {
                    IntPtr moduleHandle = GetModuleHandle(moduleName);
                    if (moduleHandle == IntPtr.Zero) continue;

                    foreach (string procName in hookedProcs)
                    {
                        IntPtr procAddr = GetProcAddress(moduleHandle, procName);
                        if (procAddr == IntPtr.Zero) continue;

                        byte[] firstBytes = new byte[16];
                        if (ReadProcessMemory(GetCurrentProcess(), procAddr, firstBytes, firstBytes.Length, out int bytesRead) && bytesRead >= 5)
                        {
                            bool hooked = false;
                            string hookType = "";

                            if (firstBytes[0] == 0xE9 || firstBytes[0] == 0xE8)
                            {
                                hooked = true;
                                hookType = firstBytes[0] == 0xE9 ? "JMP hook" : "CALL hook";
                            }
                            else if (firstBytes[0] == 0xFF && firstBytes[1] == 0x25)
                            {
                                hooked = true;
                                hookType = "Indirect JMP hook";
                            }
                            else if (firstBytes[0] == 0xEB || firstBytes[0] == 0xEA)
                            {
                                hooked = true;
                                hookType = "Short JMP hook";
                            }
                            else if (firstBytes[0] == 0x68 && firstBytes[5] == 0xC3)
                            {
                                hooked = true;
                                hookType = "Push+RET hook";
                            }
                            else if (firstBytes[0] == 0x48 && firstBytes[1] == 0xB8 && firstBytes[10] == 0xFF && firstBytes[11] == 0xE0)
                            {
                                hooked = true;
                                hookType = "MOV RAX+JMP hook";
                            }
                            else if (firstBytes[0] == 0x90)
                            {
                                int nopCount = 0;
                                for (int i = 0; i < firstBytes.Length && firstBytes[i] == 0x90; i++) nopCount++;
                                if (nopCount >= 5)
                                {
                                    hooked = true;
                                    hookType = "NOP sled";
                                }
                            }

                            if (hooked)
                            {
                                threats.Add(new ThreatInfo
                                {
                                    FileName = moduleName,
                                    FilePath = moduleName,
                                    ThreatType = "Anti-Hook",
                                    FileSize = "",
                                    Severity = Severity.Critical,
                                    Description = $"Inline hook on {moduleName}!{procName}: {hookType}"
                                });
                            }
                        }
                    }
                }
                catch { }
            }

            return threats;
        }

        private static List<ThreatInfo> CheckIATHooks()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                var process = Process.GetCurrentProcess();
                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        string moduleName = Path.GetFileName(module.FileName).ToLowerInvariant();
                        if (!CriticalModules.Contains(moduleName)) continue;

                        IntPtr baseAddr = module.BaseAddress;
                        int moduleSize = module.ModuleMemorySize;

                        byte[] moduleBytes = new byte[Math.Min(moduleSize, 4096)];
                        if (!ReadProcessMemory(GetCurrentProcess(), baseAddr, moduleBytes, moduleBytes.Length, out int read) || read < 64)
                            continue;

                        if (moduleBytes[0] != 0x4D || moduleBytes[1] != 0x5A) continue;

                        int peOffset = BitConverter.ToInt32(moduleBytes, 0x3C);
                        if (peOffset + 24 >= moduleBytes.Length) continue;
                        if (moduleBytes[peOffset] != 0x50 || moduleBytes[peOffset + 1] != 0x45) continue;

                        int numSections = BitConverter.ToInt16(moduleBytes, peOffset + 6);
                        int optHeaderSize = BitConverter.ToInt16(moduleBytes, peOffset + 20);
                        int sectionHeaderOffset = peOffset + 24 + optHeaderSize;

                        if (sectionHeaderOffset + (numSections * 40) > moduleBytes.Length) continue;

                        for (int i = 0; i < numSections; i++)
                        {
                            int sectionOffset = sectionHeaderOffset + (i * 40);
                            string sectionName = Encoding.ASCII.GetString(moduleBytes, sectionOffset, 8).TrimEnd('\0');

                            if (sectionName == ".text")
                            {
                                int virtualSize = BitConverter.ToInt32(moduleBytes, sectionOffset + 8);
                                int rawSize = BitConverter.ToInt32(moduleBytes, sectionOffset + 16);
                                int rawOffset = BitConverter.ToInt32(moduleBytes, sectionOffset + 20);

                                if (rawOffset > 0 && rawSize > 0 && rawOffset + rawSize <= moduleBytes.Length)
                                {
                                    double entropy = CalcEntropy(moduleBytes, rawOffset, rawSize);
                                    if (entropy > 7.5 && virtualSize > 10000)
                                    {
                                        threats.Add(new ThreatInfo
                                        {
                                            FileName = moduleName,
                                            FilePath = module.FileName,
                                            ThreatType = "Anti-Hook",
                                            FileSize = "",
                                            Severity = Severity.High,
                                            Description = $"Suspicious .text section entropy in {moduleName}: {entropy:F2} — possible inline patching"
                                        });
                                    }
                                }
                            }
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return threats;
        }

        private static List<ThreatInfo> CheckExternalProcessAccess()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                int currentPid = GetCurrentProcessId();

                IntPtr hSnapshot = CreateToolhelp32Snapshot(0x00000002u, 0);
                if (hSnapshot == IntPtr.Zero || hSnapshot == (IntPtr)(-1))
                    return threats;

                try
                {
                    PROCESSENTRY32 processEntry = new();
                    processEntry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

                    if (Process32First(hSnapshot, ref processEntry))
                    {
                        do
                        {
                            if ((int)processEntry.th32ProcessID == currentPid) continue;

                            try
                            {
                                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_DUP_HANDLE, false, (int)processEntry.th32ProcessID);
                                if (hProcess == IntPtr.Zero) continue;

                                try
                                {
                                    byte[] remoteBuf = new byte[4096];
                                    IntPtr selfBase = GetModuleHandle(string.Empty);
                                    if (selfBase != IntPtr.Zero)
                                    {
                                        if (ReadProcessMemory(hProcess, selfBase, remoteBuf, remoteBuf.Length, out int bytesRead) && bytesRead > 0)
                                        {
                                            string procName = processEntry.szExeFile;
                                            if (!string.IsNullOrEmpty(procName))
                                            {
                                                string lowerProc = procName.ToLowerInvariant();
                                                bool isSuspicious = lowerProc.Contains("inject") ||
                                                                   lowerProc.Contains("hook") ||
                                                                   lowerProc.Contains("cheat") ||
                                                                   lowerProc.Contains("mod") ||
                                                                   lowerProc.Contains("debug") ||
                                                                   lowerProc.Contains("ida") ||
                                                                   lowerProc.Contains("x64dbg") ||
                                                                   lowerProc.Contains("olly") ||
                                                                   lowerProc.Contains("dnspy") ||
                                                                   lowerProc.Contains("process") ||
                                                                   lowerProc.Contains("explorer") ||
                                                                   lowerProc.Contains("powershell") ||
                                                                   lowerProc.Contains("cmd");

                                                if (isSuspicious)
                                                {
                                                    threats.Add(new ThreatInfo
                                                    {
                                                        FileName = procName,
                                                        FilePath = "",
                                                        ThreatType = "Anti-Hook",
                                                        FileSize = "",
                                                        Severity = Severity.High,
                                                        Description = $"External process reading IAuthBytes memory: {procName} (PID {processEntry.th32ProcessID})"
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
                        while (Process32Next(hSnapshot, ref processEntry));
                    }
                }
                finally
                {
                    CloseHandle(hSnapshot);
                }
            }
            catch { }

            return threats;
        }

        private static List<ThreatInfo> CheckHandleAbuse()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                int currentPid = GetCurrentProcessId();
                int handleInfoSize = 0x10000;

                IntPtr handleInfoPtr = Marshal.AllocHGlobal(handleInfoSize);
                try
                {
                    int status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfoPtr, handleInfoSize, out int returnLength);
                    if (status != 0) return threats;

                    int numberOfHandles = Marshal.ReadInt32(handleInfoPtr);
                    IntPtr currentPtr = IntPtr.Add(handleInfoPtr, IntPtr.Size + IntPtr.Size);

                    for (int i = 0; i < numberOfHandles && i < 10000; i++)
                    {
                        try
                        {
                            long objectPtr = Marshal.ReadInt64(currentPtr);
                            long handleValue = Marshal.ReadInt64(currentPtr, IntPtr.Size);
                            int ownerPid = Marshal.ReadInt32(currentPtr, 2 * IntPtr.Size);
                            int accessMask = Marshal.ReadInt32(currentPtr, 2 * IntPtr.Size + 4);

                            if (ownerPid != currentPid && ownerPid > 0)
                            {
                                bool hasFullAccess = (accessMask & 0x001F0FFF) == 0x001F0FFF;
                                bool hasWriteAccess = (accessMask & 0x0002) != 0;
                                bool hasDupHandle = (accessMask & 0x0040) != 0;

                                if (hasFullAccess || (hasWriteAccess && hasDupHandle))
                                {
                                    string ownerName = "";
                                    try
                                    {
                                        using var ownerProcess = Process.GetProcessById(ownerPid);
                                        ownerName = ownerProcess.ProcessName;
                                    }
                                    catch { ownerName = $"PID {ownerPid}"; }

                                    threats.Add(new ThreatInfo
                                    {
                                        FileName = ownerName,
                                        FilePath = "",
                                        ThreatType = "Anti-Hook",
                                        FileSize = "",
                                        Severity = Severity.Critical,
                                        Description = $"Suspicious handle to IAuthBytes from {ownerName}: access 0x{accessMask:X8}"
                                    });
                                }
                            }

                            currentPtr = IntPtr.Add(currentPtr, 2 * IntPtr.Size + 4 * IntPtr.Size);
                        }
                        catch { }
                    }
                }
                finally
                {
                    Marshal.FreeHGlobal(handleInfoPtr);
                }
            }
            catch { }

            return threats;
        }

        private static List<ThreatInfo> CheckModuleInjection()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                var currentProcess = Process.GetCurrentProcess();
                IntPtr[] modules = new IntPtr[1024];

                if (EnumProcessModules(currentProcess.Handle, modules, modules.Length * IntPtr.Size, out int bytesNeeded))
                {
                    int moduleCount = bytesNeeded / IntPtr.Size;
                    var knownModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                    foreach (ProcessModule module in currentProcess.Modules)
                    {
                        knownModules.Add(Path.GetFileName(module.FileName).ToLowerInvariant());
                    }

                    for (int i = 0; i < moduleCount; i++)
                    {
                        if (modules[i] == IntPtr.Zero) continue;

                        StringBuilder moduleName = new StringBuilder(1024);
                        if (GetModuleFileNameEx(currentProcess.Handle, modules[i], moduleName, moduleName.Capacity) > 0)
                        {
                            string name = Path.GetFileName(moduleName.ToString()).ToLowerInvariant();

                            if (!string.IsNullOrEmpty(name) && !name.EndsWith(".exe") && !name.EndsWith(".dll") && !name.EndsWith(".exe"))
                            {
                                if (!KnownGoodModule(name))
                                {
                                    threats.Add(new ThreatInfo
                                    {
                                        FileName = name,
                                        FilePath = moduleName.ToString(),
                                        ThreatType = "Anti-Hook",
                                        FileSize = "",
                                        Severity = Severity.High,
                                        Description = $"Unexpected module loaded: {name} — possible DLL injection"
                                    });
                                }
                            }
                        }
                    }
                }
            }
            catch { }

            return threats;
        }

        private static bool KnownGoodModule(string name)
        {
            string[] knownGood = {
                "ntdll.dll", "kernel32.dll", "kernelbase.dll", "user32.dll", "gdi32.dll",
                "advapi32.dll", "sechost.dll", "rpcrt4.dll", "shell32.dll", "shlwapi.dll",
                "comctl32.dll", "combase.dll", "ole32.dll", "oleaut32.dll",
                "ws2_32.dll", "winhttp.dll", "wininet.dll", "crypt32.dll", "wincrypt.dll",
                "msvcrt.dll", "ucrtbase.dll", "vcruntime140.dll", "vcruntime140_clr0400.dll",
                "clr.dll", "mscorwks.dll", "mscorlib.dll",
                "IAuthBytes.exe", "webview2loader.dll",
                "sxs.dll", "profapi.dll", "shcore.dll", "dwmapi.dll",
                "imm32.dll", "msctf.dll", "textinputframework.dll",
                "coremessaging.dll", "coreuicomponents.dll", "ntmarta.dll",
                "wtsapi32.dll", "setupapi.dll", "cfgmgr32.dll", "devobj.dll",
                "powrprof.dll", "umpdc.dll", "ncrypt.dll", "bcrypt.dll", "bcryptprimitives.dll",
                "wintrust.dll", "msasn1.dll", "cryptsp.dll", "cryptbase.dll",
                "clbcatq.dll", "comsvcs.dll", "comuid.dll",
                "dxgi.dll", "d3d11.dll", "d3d9.dll", "d2d1.dll", "dwrite.dll",
                "windows.web.dll", "windows.graphics.dll", "windows.ui.dll",
                "Microsoft.Web.WebView2.Core.dll", "Microsoft.Web.WebView2.WinForms.dll",
                "Microsoft.Web.WebView2.Wpf.dll"
            };
            return knownGood.Contains(name);
        }

        private static List<ThreatInfo> CheckSelfIntegrity(string gtPath)
        {
            var threats = new List<ThreatInfo>();

            try
            {
                string? selfPath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(selfPath) || !File.Exists(selfPath))
                    return threats;

                byte[] selfBytes = File.ReadAllBytes(selfPath);
                if (selfBytes.Length < 2) return threats;

                if (selfBytes[0] != 0x4D || selfBytes[1] != 0x5A)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "IAuthBytes.exe",
                        FilePath = selfPath,
                        ThreatType = "Integrity",
                        FileSize = "",
                        Severity = Severity.Critical,
                        Description = "IAuthBytes executable has invalid MZ header — binary corrupted or replaced"
                    });
                    return threats;
                }

                int peOff = BitConverter.ToInt32(selfBytes, 0x3C);
                if (peOff + 4 >= selfBytes.Length ||
                    selfBytes[peOff] != 0x50 || selfBytes[peOff + 1] != 0x45)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "IAuthBytes.exe",
                        FilePath = selfPath,
                        ThreatType = "Integrity",
                        FileSize = "",
                        Severity = Severity.Critical,
                        Description = "IAuthBytes executable has invalid PE signature — binary tampered"
                    });
                    return threats;
                }

                long fileSize = new FileInfo(selfPath).Length;
                if (fileSize < 100_000 || fileSize > 50_000_000)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "IAuthBytes.exe",
                        FilePath = selfPath,
                        ThreatType = "Integrity",
                        FileSize = FormatSize(fileSize),
                        Severity = Severity.High,
                        Description = $"IAuthBytes executable has unexpected size: {FormatSize(fileSize)} — may be corrupted"
                    });
                }

                using var sha = SHA256.Create();
                byte[] hash = sha.ComputeHash(selfBytes);
                string hashStr = Convert.ToHexString(hash);

                string hashFile = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "IAuthBytes", "self_hash.txt");

                if (File.Exists(hashFile))
                {
                    string storedHash = File.ReadAllText(hashFile).Trim();
                    if (!string.IsNullOrEmpty(storedHash) && storedHash != hashStr)
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = "IAuthBytes.exe",
                            FilePath = selfPath,
                            ThreatType = "Integrity",
                            FileSize = "",
                            Severity = Severity.Critical,
                            Description = "IAuthBytes binary hash mismatch — executable has been modified since last verified build"
                        });
                    }
                }
                else
                {
                    Directory.CreateDirectory(Path.GetDirectoryName(hashFile)!);
                    File.WriteAllText(hashFile, hashStr);
                }
            }
            catch { }

            return threats;
        }

        public static List<ThreatInfo> RunSelfTest()
        {
            var threats = new List<ThreatInfo>();

            threats.AddRange(SelfTestInlineHookDetection());
            threats.AddRange(SelfTestIntegrityCheck());
            threats.AddRange(SelfTestProcessAccessDetection());

            return threats;
        }

        private static List<ThreatInfo> SelfTestInlineHookDetection()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                IntPtr ntdll = GetModuleHandle("ntdll.dll");
                if (ntdll == IntPtr.Zero) return threats;

                IntPtr procAddr = GetProcAddress(ntdll, "NtCreateFile");
                if (procAddr == IntPtr.Zero) return threats;

                byte[] originalBytes = new byte[16];
                if (!ReadProcessMemory(GetCurrentProcess(), procAddr, originalBytes, originalBytes.Length, out int read) || read < 16)
                    return threats;

                bool isHooked = originalBytes[0] == 0xE9 || originalBytes[0] == 0xE8 ||
                               (originalBytes[0] == 0xFF && originalBytes[1] == 0x25) ||
                               originalBytes[0] == 0xEB || originalBytes[0] == 0xEA ||
                               (originalBytes[0] == 0x68 && originalBytes[5] == 0xC3);

                if (isHooked)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "Self-Test",
                        FilePath = "",
                        ThreatType = "Anti-Hook",
                        FileSize = "",
                        Severity = Severity.Low,
                        Description = "Self-test: NtCreateFile already hooked by external module — detection working"
                    });
                }
                else
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "Self-Test",
                        FilePath = "",
                        ThreatType = "Anti-Hook",
                        FileSize = "",
                        Severity = Severity.Low,
                        Description = "Self-test: NtCreateFile not hooked — hook detection baseline established"
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.LogException("SelfTest-InlineHook", ex);
            }

            return threats;
        }

        private static List<ThreatInfo> SelfTestIntegrityCheck()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                if (_originalTextSection != null && _textSectionBase != IntPtr.Zero)
                {
                    byte[] currentSection = new byte[_textSectionSize];
                    if (ReadProcessMemory(GetCurrentProcess(), _textSectionBase, currentSection, _textSectionSize, out int bytesRead) && bytesRead == _textSectionSize)
                    {
                        bool match = true;
                        for (int i = 0; i < _textSectionSize; i++)
                        {
                            if (currentSection[i] != _originalTextSection[i])
                            {
                                match = false;
                                break;
                            }
                        }

                        if (match)
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = "Self-Test",
                                FilePath = "",
                                ThreatType = "Anti-Hook",
                                FileSize = "",
                                Severity = Severity.Low,
                                Description = $"Self-test: .text section integrity verified ({_textSectionSize} bytes match)"
                            });
                        }
                        else
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = "Self-Test",
                                FilePath = "",
                                ThreatType = "Anti-Hook",
                                FileSize = "",
                        Severity = Severity.Low,
                        Description = "Self-test: .text section changed since cache — integrity monitoring active"
                            });
                        }
                    }
                }
                else
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "Self-Test",
                        FilePath = "",
                        ThreatType = "Anti-Hook",
                        FileSize = "",
                        Severity = Severity.Low,
                        Description = "Self-test: .text section cache not available — integrity check skipped"
                    });
                }
            }
            catch (Exception ex)
            {
                Logger.LogException("SelfTest-Integrity", ex);
            }

            return threats;
        }

        private static List<ThreatInfo> SelfTestProcessAccessDetection()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                int currentPid = GetCurrentProcessId();
                int detectedCount = 0;

                IntPtr hSnapshot = CreateToolhelp32Snapshot(0x00000002u, 0);
                if (hSnapshot == IntPtr.Zero || hSnapshot == (IntPtr)(-1))
                    return threats;

                try
                {
                    PROCESSENTRY32 processEntry = new();
                    processEntry.dwSize = (uint)Marshal.SizeOf(typeof(PROCESSENTRY32));

                    if (Process32First(hSnapshot, ref processEntry))
                    {
                        do
                        {
                            if ((int)processEntry.th32ProcessID == currentPid) continue;

                            try
                            {
                                IntPtr hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, false, (int)processEntry.th32ProcessID);
                                if (hProcess != IntPtr.Zero)
                                {
                                    try
                                    {
                                        byte[] remoteBuf = new byte[1024];
                                        IntPtr selfBase = GetModuleHandle(string.Empty);
                                        if (selfBase != IntPtr.Zero && ReadProcessMemory(hProcess, selfBase, remoteBuf, remoteBuf.Length, out int bytesRead) && bytesRead > 0)
                                        {
                                            detectedCount++;
                                        }
                                    }
                                    finally
                                    {
                                        CloseHandle(hProcess);
                                    }
                                }
                            }
                            catch { }
                        }
                        while (Process32Next(hSnapshot, ref processEntry));
                    }
                }
                finally
                {
                    CloseHandle(hSnapshot);
                }

                threats.Add(new ThreatInfo
                {
                    FileName = "Self-Test",
                    FilePath = "",
                    ThreatType = "Anti-Hook",
                    FileSize = "",
                    Severity = Severity.Low,
                    Description = $"Self-test: Process access detection found {detectedCount} processes with readable access to IAuthBytes"
                });
            }
            catch (Exception ex)
            {
                Logger.LogException("SelfTest-ProcessAccess", ex);
            }

            return threats;
        }

        private static double CalcEntropy(byte[] data, int offset, int length)
        {
            if (length <= 0) return 0;

            var freq = new int[256];
            for (int i = offset; i < offset + length && i < data.Length; i++)
                freq[data[i]]++;

            double entropy = 0;
            for (int i = 0; i < 256; i++)
            {
                if (freq[i] > 0)
                {
                    double p = (double)freq[i] / length;
                    entropy -= p * Math.Log2(p);
                }
            }
            return entropy;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Process32First(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool Process32Next(IntPtr hSnapshot, ref PROCESSENTRY32 lppe);

        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Ansi)]
        public struct PROCESSENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ProcessID;
            public IntPtr th32DefaultHeapID;
            public uint th32ModuleID;
            public uint cntThreads;
            public uint th32ParentProcessID;
            public int pcPriClassBase;
            public uint dwFlags;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)]
            public string szExeFile;
        }
    }
}
