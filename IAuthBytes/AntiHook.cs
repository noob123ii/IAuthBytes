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

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentThread();

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

        [DllImport("kernel32.dll")]
        private static extern bool Thread32First(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        private static extern bool Thread32Next(IntPtr hSnapshot, ref THREADENTRY32 lpte);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateToolhelp32Snapshot(uint dwFlags, uint th32ProcessID);

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT64 lpContext);

        [DllImport("kernel32.dll")]
        private static extern bool GetThreadContext(IntPtr hThread, ref CONTEXT32 lpContext);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenThread(int dwDesiredAccess, bool bInheritHandle, uint dwThreadId);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryInformationThread(IntPtr threadHandle, int threadInformationClass, ref IntPtr threadInformation, int threadInformationLength, IntPtr returnLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool VirtualQuery(IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr VirtualAlloc(IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualFree(IntPtr lpAddress, uint dwSize, uint dwFreeType);

        [DllImport("ntdll.dll")]
        private static extern int NtProtectVirtualMemory(IntPtr processHandle, ref IntPtr baseAddress, ref uint regionSize, uint newProtect, out uint oldProtect);

        [DllImport("ntdll.dll")]
        private static extern int NtQueryVirtualMemory(IntPtr processHandle, IntPtr baseAddress, int memoryInformationClass, out MEMORY_BASIC_INFORMATION memoryInformation, int memoryInformationLength, out int returnLength);

        [DllImport("ntdll.dll")]
        private static extern IntPtr NtCurrentTeb();

        [DllImport("ntdll.dll")]
        private static extern int NtSetInformationThread(IntPtr threadHandle, int threadInformationClass, IntPtr threadInformation, int threadInformationLength);

        [DllImport("kernel32.dll")]
        private static extern bool TerminateProcess(IntPtr hProcess, uint uExitCode);

        [DllImport("kernel32.dll")]
        private static extern bool SetProcessMitigationPolicy(int policy, IntPtr lpBuffer, int dwLength);

        [DllImport("kernel32.dll")]
        private static extern bool GetProcessMitigationPolicy(IntPtr hProcess, int policy, IntPtr lpBuffer, int dwLength);

        [DllImport("kernel32.dll")]
        private static extern bool SetKernelObjectSecurity(IntPtr handle, int securityInformation, [In] byte[] pSecurityDescriptor);

        [DllImport("advapi32.dll")]
        private static extern bool GetKernelObjectSecurity(IntPtr handle, int securityInformation, [Out] byte[] pSecurityDescriptor, int nLength, out int lpnLengthNeeded);

        [DllImport("kernel32.dll")]
        private static extern IntPtr OpenProcessToken(IntPtr processHandle, int desiredAccess, out IntPtr tokenHandle);

        [DllImport("advapi32.dll")]
        private static extern bool LookupPrivilegeValue(string? lpSystemName, string lpName, out LUID lpLuid);

        [DllImport("advapi32.dll")]
        private static extern bool AdjustTokenPrivileges(IntPtr tokenHandle, bool disableAllPrivileges, ref TOKEN_PRIVILEGES newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcessToken();

        [DllImport("kernel32.dll")]
        private static extern bool GetProcessTimes(IntPtr hProcess, out FILETIME lpCreationTime, out FILETIME lpExitTime, out FILETIME lpKernelTime, out FILETIME lpUserTime);

        [DllImport("kernel32.dll")]
        private static extern bool IsProcessCritical(IntPtr hProcess, ref bool isCritical);

        [DllImport("ntdll.dll")]
        private static extern int RtlGetVersion(ref RTL_OSVERSIONINFOEX lpVersionInformation);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualQueryEx(IntPtr hProcess, IntPtr lpAddress, out MEMORY_BASIC_INFORMATION lpBuffer, int dwLength);

        [DllImport("kernel32.dll")]
        private static extern uint GetProcessIdOfThread(IntPtr thread);

        [DllImport("kernel32.dll")]
        private static extern int SuspendThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern int ResumeThread(IntPtr hThread);

        [DllImport("kernel32.dll")]
        private static extern bool WriteFile(IntPtr hFile, byte[] lpBuffer, int nNumberOfBytesToWrite, out int lpNumberOfBytesWritten, IntPtr lpOverlapped);

        [DllImport("kernel32.dll")]
        private static extern IntPtr CreateFile(string lpFileName, uint dwDesiredAccess, uint dwShareMode, IntPtr lpSecurityAttributes, uint dwCreationDisposition, uint dwFlagsAndAttributes, IntPtr hTemplateFile);

        [DllImport("kernel32.dll")]
        private static extern bool GetVersionExA(ref RTL_OSVERSIONINFOEX lpVersionInfo);

        private const int THREAD_SET_INFORMATION = 0x0020;
        private const int ThreadHideFromDebugger = 0x11;
        private const int ThreadBreakOnTermination = 0x12;

        private const int PROCESS_TERMINATE = 0x0001;
        private const int PROCESS_SET_QUOTA = 0x0100;
        private const int PROCESS_SET_INFORMATION = 0x0200;
        private const int PROCESS_QUERY_LIMITED_INFORMATION = 0x1000;

        private const int DACL_SECURITY_INFORMATION = 0x00000001;

        private const uint TOKEN_QUERY = 0x0008;
        private const uint TOKEN_ADJUST_PRIVILEGES = 0x0020;

        private const int ProcessDynamicCodePolicy = 2;
        private const int ProcessSignaturePolicy = 7;
        private const int ProcessChildProcessPolicy = 11;

        [StructLayout(LayoutKind.Sequential)]
        private struct LUID
        {
            public uint LowPart;
            public int HighPart;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct TOKEN_PRIVILEGES
        {
            public int PrivilegeCount;
            public LUID Luid;
            public int Attributes;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct RTL_OSVERSIONINFOEX
        {
            public uint dwOSVersionInfoSize;
            public uint dwMajorVersion;
            public uint dwMinorVersion;
            public uint dwBuildNumber;
            public uint dwPlatformId;
            [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 128)]
            public string szCSDVersion;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct FILETIME
        {
            public uint dwLowDateTime;
            public uint dwHighDateTime;
        }

        [StructLayout(LayoutKind.Sequential)]
        private struct MEMORY_BASIC_INFORMATION
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
        private struct THREADENTRY32
        {
            public uint dwSize;
            public uint cntUsage;
            public uint th32ThreadID;
            public uint th32OwnerProcessID;
            public int tpBasePri;
            public int tpDeltaPri;
            public uint dwFlags;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct CONTEXT64
        {
            [FieldOffset(0x0)] public uint P1Home;
            [FieldOffset(0x8)] public uint P2Home;
            [FieldOffset(0x10)] public uint P3Home;
            [FieldOffset(0x18)] public uint P4Home;
            [FieldOffset(0x20)] public uint P5Home;
            [FieldOffset(0x28)] public uint P6Home;
            [FieldOffset(0x30)] public uint ContextFlags;
            [FieldOffset(0x34)] public uint MxCsr;
            [FieldOffset(0x38)] public short Cs;
            [FieldOffset(0x3A)] public short Ds;
            [FieldOffset(0x3C)] public short Es;
            [FieldOffset(0x3E)] public short Fs;
            [FieldOffset(0x40)] public short Gs;
            [FieldOffset(0x42)] public short Ss;
            [FieldOffset(0x44)] public uint EFlags;
            [FieldOffset(0x48)] public ulong Dr0;
            [FieldOffset(0x50)] public ulong Dr1;
            [FieldOffset(0x58)] public ulong Dr2;
            [FieldOffset(0x60)] public ulong Dr3;
            [FieldOffset(0x68)] public ulong Dr6;
            [FieldOffset(0x70)] public ulong Dr7;
        }

        [StructLayout(LayoutKind.Explicit)]
        private struct CONTEXT32
        {
            [FieldOffset(0x0)] public uint ContextFlags;
            [FieldOffset(0x1C)] public uint Dr0;
            [FieldOffset(0x20)] public uint Dr1;
            [FieldOffset(0x24)] public uint Dr2;
            [FieldOffset(0x28)] public uint Dr3;
            [FieldOffset(0x2C)] public uint Dr6;
            [FieldOffset(0x30)] public uint Dr7;
        }

        private const int THREAD_QUERY_INFORMATION = 0x0040;
        private const int THREAD_GET_CONTEXT = 0x0008;
        private const int THREAD_SUSPEND_RESUME = 0x0002;
        private const int THREAD_QUERY_LIMITED_INFORMATION = 0x0800;
        private const int CONTEXT_DEBUG_REGISTERS = 0x00100010;
        private const int CONTEXT_AMD64 = 0x00100000;

        private const int PROCESS_QUERY_INFORMATION = 0x0400;
        private const int PROCESS_VM_READ = 0x0010;
        private const int PROCESS_DUP_HANDLE = 0x0040;
        private const int SystemHandleInformation = 16;
        private const int SystemExtendedHandleInformation = 64;

        private const uint PAGE_EXECUTE_READ = 0x20;
        private const uint PAGE_EXECUTE_READWRITE = 0x40;
        private const uint PAGE_READWRITE = 0x04;
        private const uint PAGE_EXECUTE = 0x10;
        private const uint MEM_COMMIT = 0x1000;
        private const uint MEM_RESERVE = 0x2000;
        private const uint MEM_IMAGE = 0x1000000;
        private const uint MEM_MAPPED = 0x40000;
        private const uint MEM_PRIVATE = 0x20000;

        private static readonly byte[] JmpPatch = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
        private static readonly byte[] CallPatch = { 0xE8, 0x00, 0x00, 0x00, 0x00 };

        private static readonly string[] CriticalModules = {
            "ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll",
            "ws2_32.dll", "winhttp.dll", "crypt32.dll", "shell32.dll"
        };

        private static readonly string[] SelfModuleNames = {
            "IAuthBytes.exe", "IAuthBytes.dll"
        };

        private static readonly HashSet<string> SuspiciousParentProcesses = new(StringComparer.OrdinalIgnoreCase)
        {
            "cmd", "powershell", "pwsh", "wscript", "cscript", "mshta",
            "rundll32", "regsvr32", "certutil", "msiexec", "wmic",
            "services", "svchost", "winlogon", "smss", "csrss"
        };

        private static int _selfPid;
        private static byte[]? _originalTextSection;
        private static IntPtr _textSectionBase;
        private static int _textSectionSize;
        private static Timer? _integrityTimer;
        private static volatile bool _integrityCheckFailed;

        private static FileSystemWatcher? _selfFileWatcher;
        private static byte[]? _iatSnapshot;
        private static string? _selfDirectory;
        private static Timer? _dllMonitorTimer;
        private static readonly HashSet<string> _knownModules = new(StringComparer.OrdinalIgnoreCase);
        private static Timer? _memoryProtectionTimer;
        private static Timer? _antiKillTimer;

        public static bool IntegrityCheckFailed => _integrityCheckFailed;

        public static List<ThreatInfo> RunAntiHookCheck(string gtPath)
        {
            var threats = new List<ThreatInfo>();

            threats.AddRange(CheckDebuggerPresence());
            threats.AddRange(CheckPEBDebuggerFlags());
            threats.AddRange(CheckInlineHooks());
            threats.AddRange(CheckIATHooks());
            threats.AddRange(CheckExternalProcessAccess());
            threats.AddRange(CheckHandleAbuse());
            threats.AddRange(CheckModuleInjection());
            threats.AddRange(CheckSelfIntegrity(gtPath));
            threats.AddRange(CheckThreadHijacking());
            threats.AddRange(CheckHardwareBreakpoints());
            threats.AddRange(CheckEATHooks());
            threats.AddRange(CheckHookEngineSignatures());
            threats.AddRange(CheckParentProcess());
            threats.AddRange(CheckAPCInjection());
            threats.AddRange(CheckInjectedPE());
            threats.AddRange(CheckSyscallIntegrity());
            threats.AddRange(RunSelfTest());

            return threats;
        }

        public static void StartContinuousMonitoring()
        {
            Logger.Log("AntiHook: StartContinuousMonitoring called");
            _selfPid = Process.GetCurrentProcess().Id;
            CacheTextSection();
            ProtectTextSection();
            SnapshotIAT();
            SnapshotKnownModules();
            HideThreadsFromDebugger();

            _integrityTimer = new Timer(_ =>
            {
                try
                {
                    if (!VerifyTextSectionIntegrity())
                    {
                        _integrityCheckFailed = true;
                        Logger.Log("CRITICAL: IAuthBytes .text section modified by external process!");
                    }

                    if (!VerifyIATIntegrity())
                    {
                        _integrityCheckFailed = true;
                        Logger.Log("CRITICAL: IAuthBytes IAT modified by external process!");
                    }

                    DetectMemoryTampering();
                    DetectInjectedPE();
                    DetectShellcodeRegions();

                    if (_integrityCheckFailed)
                    {
                        Logger.Log("CRITICAL: Integrity check failed — self-terminating to prevent compromise");
                        try { TerminateProcess(GetCurrentProcess(), 0xC0DE); } catch { }
                    }
                }
                catch { }
            }, null, TimeSpan.FromSeconds(5), TimeSpan.FromSeconds(30));

            _dllMonitorTimer = new Timer(_ =>
            {
                try
                {
                    DetectNewModules();
                }
                catch { }
            }, null, TimeSpan.FromSeconds(30), TimeSpan.FromSeconds(15));

            _antiKillTimer = new Timer(_ =>
            {
                try
                {
                    CheckProcessAlive();
                }
                catch { }
            }, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(20));

            StartSelfFileWatcher();
        }

        public static void StopContinuousMonitoring()
        {
            _integrityTimer?.Dispose();
            _integrityTimer = null;
            _dllMonitorTimer?.Dispose();
            _dllMonitorTimer = null;
            _memoryProtectionTimer?.Dispose();
            _memoryProtectionTimer = null;
            _antiKillTimer?.Dispose();
            _antiKillTimer = null;
            _selfFileWatcher?.Dispose();
            _selfFileWatcher = null;
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

        private static void ProtectTextSection()
        {
            try
            {
                if (_textSectionBase == IntPtr.Zero || _textSectionSize == 0) return;

                uint oldProtect;
                bool ok = VirtualProtect(_textSectionBase, (uint)_textSectionSize, PAGE_EXECUTE_READ, out oldProtect);
                if (ok)
                    Logger.Log($"ProtectTextSection: .text locked as PAGE_EXECUTE_READ (was 0x{oldProtect:X})");
                else
                    Logger.Log($"ProtectTextSection: VirtualProtect failed (error {GetLastError()})");
            }
            catch (Exception ex)
            {
                Logger.LogException("ProtectTextSection", ex);
            }
        }

        private static void SnapshotIAT()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                IntPtr selfBase = GetModuleHandle(string.Empty);
                if (selfBase == IntPtr.Zero) return;

                byte[] peHeader = new byte[4096];
                if (!ReadProcessMemory(GetCurrentProcess(), selfBase, peHeader, peHeader.Length, out int read) || read < 64)
                    return;

                if (peHeader[0] != 0x4D || peHeader[1] != 0x5A) return;
                int peOff = BitConverter.ToInt32(peHeader, 0x3C);
                if (peOff + 24 >= peHeader.Length) return;
                if (peHeader[peOff] != 0x50 || peHeader[peOff + 1] != 0x45) return;

                int numSections = BitConverter.ToInt16(peHeader, peOff + 6);
                int optHeaderSize = BitConverter.ToInt16(peHeader, peOff + 20);
                int sectionHeaderOff = peOff + 24 + optHeaderSize;

                for (int i = 0; i < numSections; i++)
                {
                    int secOff = sectionHeaderOff + (i * 40);
                    if (secOff + 40 > peHeader.Length) break;

                    string name = Encoding.ASCII.GetString(peHeader, secOff, 8).TrimEnd('\0');
                    if (name == ".idata")
                    {
                        int virtualSize = BitConverter.ToInt32(peHeader, secOff + 8);
                        int virtualAddr = BitConverter.ToInt32(peHeader, secOff + 12);
                        IntPtr idataBase = IntPtr.Add(selfBase, virtualAddr);
                        int idataSize = Math.Min(virtualSize, 65536);

                        _iatSnapshot = new byte[idataSize];
                        if (ReadProcessMemory(GetCurrentProcess(), idataBase, _iatSnapshot, idataSize, out int iatRead) && iatRead == idataSize)
                        {
                            Logger.Log($"SnapshotIAT: Cached .idata section: {idataSize} bytes");
                        }
                        else
                        {
                            _iatSnapshot = null;
                            Logger.Log("SnapshotIAT: Failed to read .idata section");
                        }
                        return;
                    }
                }

                Logger.Log("SnapshotIAT: .idata section not found, using import directory fallback");
                SnapshotIATViaImportDir(selfBase, peHeader, peOff);
            }
            catch (Exception ex)
            {
                Logger.LogException("SnapshotIAT", ex);
            }
        }

        private static void SnapshotIATViaImportDir(IntPtr selfBase, byte[] peHeader, int peOff)
        {
            try
            {
                int importDirRva = BitConverter.ToInt32(peHeader, peOff + 24 + 120 + 16);
                int importDirSize = BitConverter.ToInt32(peHeader, peOff + 24 + 120 + 20);
                if (importDirRva == 0 || importDirSize == 0) return;

                IntPtr importDirAddr = IntPtr.Add(selfBase, importDirRva);
                byte[] importDir = new byte[Math.Min(importDirSize, 8192)];
                if (!ReadProcessMemory(GetCurrentProcess(), importDirAddr, importDir, importDir.Length, out int dirRead) || dirRead < 20)
                    return;

                var iatEntries = new List<byte[]>();
                int entryOff = 0;

                while (entryOff + 20 <= importDir.Length)
                {
                    int lookupRva = BitConverter.ToInt32(importDir, entryOff);
                    int nameRva = BitConverter.ToInt32(importDir, entryOff + 12);
                    int iatRva = BitConverter.ToInt32(importDir, entryOff + 16);
                    if (lookupRva == 0 && nameRva == 0 && iatRva == 0) break;

                    IntPtr iatAddr = IntPtr.Add(selfBase, iatRva);
                    byte[] iatEntriesBytes = new byte[2048];
                    if (ReadProcessMemory(GetCurrentProcess(), iatAddr, iatEntriesBytes, iatEntriesBytes.Length, out int iatRead) && iatRead >= 8)
                    {
                        iatEntries.Add(iatEntriesBytes[..iatRead]);
                    }
                    entryOff += 20;
                }

                if (iatEntries.Count > 0)
                {
                    int totalSize = iatEntries.Sum(e => e.Length);
                    _iatSnapshot = new byte[totalSize];
                    int pos = 0;
                    foreach (var entry in iatEntries)
                    {
                        Buffer.BlockCopy(entry, 0, _iatSnapshot, pos, entry.Length);
                        pos += entry.Length;
                    }
                    Logger.Log($"SnapshotIAT: Cached import directory: {iatEntries.Count} entries, {_iatSnapshot.Length} bytes");
                }
            }
            catch { }
        }

        private static bool VerifyIATIntegrity()
        {
            if (_iatSnapshot == null) return true;

            try
            {
                IntPtr selfBase = GetModuleHandle(string.Empty);
                if (selfBase == IntPtr.Zero) return true;

                byte[] peHeader = new byte[4096];
                if (!ReadProcessMemory(GetCurrentProcess(), selfBase, peHeader, peHeader.Length, out int read) || read < 64)
                    return true;

                if (peHeader[0] != 0x4D || peHeader[1] != 0x5A) return true;
                int peOff = BitConverter.ToInt32(peHeader, 0x3C);
                if (peOff + 24 >= peHeader.Length) return true;
                if (peHeader[peOff] != 0x50 || peHeader[peOff + 1] != 0x45) return true;

                int numSections = BitConverter.ToInt16(peHeader, peOff + 6);
                int optHeaderSize = BitConverter.ToInt16(peHeader, peOff + 20);
                int sectionHeaderOff = peOff + 24 + optHeaderSize;

                for (int i = 0; i < numSections; i++)
                {
                    int secOff = sectionHeaderOff + (i * 40);
                    if (secOff + 40 > peHeader.Length) break;

                    string name = Encoding.ASCII.GetString(peHeader, secOff, 8).TrimEnd('\0');
                    if (name == ".idata")
                    {
                        int virtualAddr = BitConverter.ToInt32(peHeader, secOff + 12);
                        int virtualSize = BitConverter.ToInt32(peHeader, secOff + 8);
                        IntPtr idataBase = IntPtr.Add(selfBase, virtualAddr);
                        int idataSize = Math.Min(virtualSize, 65536);

                        byte[] currentIAT = new byte[idataSize];
                        if (!ReadProcessMemory(GetCurrentProcess(), idataBase, currentIAT, currentIAT.Length, out int iatRead) || iatRead != _iatSnapshot.Length)
                            return true;

                        for (int j = 0; j < _iatSnapshot.Length; j++)
                        {
                            if (currentIAT[j] != _iatSnapshot[j])
                            {
                                Logger.Log($"IAT byte changed at offset {j}: 0x{_iatSnapshot[j]:X2} -> 0x{currentIAT[j]:X2}");
                                return false;
                            }
                        }
                        return true;
                    }
                }
            }
            catch { }
            return true;
        }

        private static void SnapshotKnownModules()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        string name = Path.GetFileName(module.FileName).ToLowerInvariant();
                        _knownModules.Add(name);
                    }
                    catch { }
                }
                Logger.Log($"SnapshotKnownModules: Cached {_knownModules.Count} modules");
            }
            catch (Exception ex)
            {
                Logger.LogException("SnapshotKnownModules", ex);
            }
        }

        private static void DetectNewModules()
        {
            try
            {
                var process = Process.GetCurrentProcess();
                var currentModules = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        string name = Path.GetFileName(module.FileName).ToLowerInvariant();
                        currentModules.Add(name);

                        if (!_knownModules.Contains(name) && !KnownGoodModule(name))
                        {
                            string modulePath = module.FileName.ToLowerInvariant();
                            bool fromTrustedPath = modulePath.Contains(@"\windows\") ||
                                                    modulePath.Contains(@"\windows\system32") ||
                                                    modulePath.Contains(@"\windows\syswow64") ||
                                                    modulePath.Contains(@"\windows\winsxs") ||
                                                    modulePath.Contains(@"\dotnet\") ||
                                                    modulePath.Contains(@"\microsoft.net\") ||
                                                    modulePath.Contains(@"\program files\") ||
                                                    modulePath.Contains(@"\program files (x86)\") ||
                                                    modulePath.Contains(@"\programdata\") ||
                                                    modulePath.Contains(@"\appdata\") ||
                                                    modulePath.Contains(@"\modulepath") ||
                                                    modulePath.Contains(@"\packages\");

                            if (!fromTrustedPath)
                            {
                                Logger.Log($"CRITICAL: New DLL loaded from untrusted path: {name} at {module.FileName} — possible injection");
                                _integrityCheckFailed = true;
                            }
                        }
                    }
                    catch { }
                }

                _knownModules.Clear();
                foreach (string m in currentModules)
                    _knownModules.Add(m);
            }
            catch { }
        }

        private static void DetectMemoryTampering()
        {
            try
            {
                IntPtr selfBase = GetModuleHandle(string.Empty);
                if (selfBase == IntPtr.Zero) return;

                IntPtr queryAddr = selfBase;
                int checkedRegions = 0;

                while (checkedRegions < 50)
                {
                    MEMORY_BASIC_INFORMATION mbi;
                    int status = NtQueryVirtualMemory(GetCurrentProcess(), queryAddr, 0, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>(), out _);
                    if (status != 0) break;
                    if (mbi.BaseAddress == IntPtr.Zero) break;

                    if (mbi.AllocationBase == selfBase && mbi.State == MEM_COMMIT)
                    {
                        if (mbi.Protect == PAGE_EXECUTE_READWRITE)
                        {
                            Logger.Log($"CRITICAL: RWX memory region at 0x{mbi.BaseAddress.ToInt64():X} size 0x{mbi.RegionSize.ToInt64():X} — unauthorized code modification");
                            _integrityCheckFailed = true;
                        }

                        if (mbi.Protect == PAGE_READWRITE && (mbi.Type & 0x10000000) != 0)
                        {
                            Logger.Log($"WARNING: Writable code memory region at 0x{mbi.BaseAddress.ToInt64():X} — possible patching");
                        }
                    }

                    long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                    if (nextAddr <= queryAddr.ToInt64()) break;
                    queryAddr = new IntPtr(nextAddr);
                    checkedRegions++;
                }
            }
            catch { }
        }

        private static void StartSelfFileWatcher()
        {
            try
            {
                string? exePath = Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath)) return;

                _selfDirectory = Path.GetDirectoryName(exePath);
                if (string.IsNullOrEmpty(_selfDirectory) || !Directory.Exists(_selfDirectory)) return;

                _selfFileWatcher = new FileSystemWatcher(_selfDirectory)
                {
                    Filter = "*.*",
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = false
                };

                _selfFileWatcher.Created += (s, e) =>
                {
                    string ext = Path.GetExtension(e.Name ?? "").ToLowerInvariant();
                    if (ext == ".dll" || ext == ".exe")
                    {
                        Logger.Log($"CRITICAL: New file created in app directory: {e.FullPath} — possible DLL hijacking attempt");
                        _integrityCheckFailed = true;
                    }
                };

                _selfFileWatcher.Changed += (s, e) =>
                {
                    string name = Path.GetFileName(e.FullPath ?? "").ToLowerInvariant();
                    if (name == "iauthbytes.exe" || name == "index.html" || name == "iauthbytes.dll")
                    {
                        Logger.Log($"CRITICAL: Core file modified on disk: {e.FullPath}");
                        _integrityCheckFailed = true;
                    }
                };

                _selfFileWatcher.EnableRaisingEvents = true;
                Logger.Log($"StartSelfFileWatcher: Monitoring {_selfDirectory} for file changes");
            }
            catch (Exception ex)
            {
                Logger.LogException("StartSelfFileWatcher", ex);
            }
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
                            else if (firstBytes[0] == 0xB8 && firstBytes[5] == 0xFF && firstBytes[6] == 0xE0)
                            {
                                hooked = true;
                                hookType = "MOV EAX+JMP hook";
                            }
                            else if (firstBytes[0] == 0x48 && firstBytes[1] == 0xB9 && firstBytes[10] == 0xFF && firstBytes[11] == 0xE1)
                            {
                                hooked = true;
                                hookType = "MOV RCX+JMP hook";
                            }
                            else if (firstBytes[0] == 0x48 && firstBytes[1] == 0xBA && firstBytes[10] == 0xFF && firstBytes[11] == 0xE2)
                            {
                                hooked = true;
                                hookType = "MOV RDX+JMP hook";
                            }
                            else if (firstBytes[0] == 0x48 && firstBytes[1] == 0xB8 && firstBytes[10] == 0xFF && firstBytes[11] == 0xD0)
                            {
                                hooked = true;
                                hookType = "MOV RAX+CALL hook";
                            }
                            else if (firstBytes[0] == 0xC2 && firstBytes[3] == 0xC3)
                            {
                                hooked = true;
                                hookType = "RET imm hook";
                            }
                            else if (firstBytes[0] == 0xC3 && firstBytes.Length > 1 && firstBytes[1] != 0x00)
                            {
                                // suspicious: RET followed by non-zero byte suggests trampoline
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
                                                bool isExcluded = lowerProc == "explorer.exe" ||
                                                                   lowerProc == "cmd.exe" ||
                                                                   lowerProc == "powershell.exe" ||
                                                                   lowerProc == "pwsh.exe" ||
                                                                   lowerProc == "conhost.exe" ||
                                                                   lowerProc == "sihost.exe" ||
                                                                   lowerProc == "taskhostw.exe" ||
                                                                   lowerProc == "searchindexer.exe" ||
                                                                   lowerProc == "searchprotocolhost.exe" ||
                                                                   lowerProc == "ctfmon.exe" ||
                                                                   lowerProc == "dwm.exe" ||
                                                                   lowerProc == "csrss.exe" ||
                                                                   lowerProc == "lsass.exe" ||
                                                                   lowerProc == "services.exe" ||
                                                                   lowerProc == "svchost.exe" ||
                                                                   lowerProc == "winlogon.exe" ||
                                                                   lowerProc == "wininit.exe" ||
                                                                   lowerProc == "smss.exe";

                                                bool isSuspicious = !isExcluded && (
                                                                   lowerProc.Contains("inject") ||
                                                                   lowerProc.Contains("hook") ||
                                                                   lowerProc.Contains("cheat") ||
                                                                   lowerProc.Contains("mod") ||
                                                                   lowerProc.Contains("debug") ||
                                                                   lowerProc.Contains("ida") ||
                                                                   lowerProc.Contains("x64dbg") ||
                                                                   lowerProc.Contains("olly") ||
                                                                   lowerProc.Contains("dnspy") ||
                                                                   lowerProc.Contains("ce") ||
                                                                   lowerProc.Contains("trainer") ||
                                                                   lowerProc.Contains("memory") ||
                                                                   lowerProc.Contains("scan"));

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

        private static List<ThreatInfo> CheckThreadHijacking()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                int currentPid = GetCurrentProcessId();
                IntPtr hSnapshot = CreateToolhelp32Snapshot(0x00000004u, 0);
                if (hSnapshot == IntPtr.Zero || hSnapshot == (IntPtr)(-1))
                    return threats;

                try
                {
                    THREADENTRY32 te = new();
                    te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));

                    if (Thread32First(hSnapshot, ref te))
                    {
                        do
                        {
                            if ((int)te.th32OwnerProcessID == currentPid) continue;

                            try
                            {
                                IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT, false, te.th32ThreadID);
                                if (hThread == IntPtr.Zero) continue;

                                try
                                {
                                    // Check if thread is suspended in our process (potential hijack)
                                    if (te.tpBasePri == 0 && te.tpDeltaPri == 0)
                                    {
                                        // Thread with zero priority in external process targeting ours is suspicious
                                        // Try to read its start address via NtQueryInformationThread
                                        IntPtr startAddr = IntPtr.Zero;
                                        int status = NtQueryInformationThread(hThread, 9 /* ThreadQuerySetWin32StartAddress */, ref startAddr, IntPtr.Size, IntPtr.Zero);
                                        if (status == 0 && startAddr != IntPtr.Zero)
                                        {
                                            // Check if start address is in a known module range or executable memory
                                            IntPtr selfBase = GetModuleHandle(string.Empty);
                                            if (selfBase != IntPtr.Zero)
                                            {
                                                long addrLong = startAddr.ToInt64();
                                                long baseLong = selfBase.ToInt64();
                                                if (addrLong >= baseLong && addrLong < baseLong + 0x10000000)
                                                {
                                                    threats.Add(new ThreatInfo
                                                    {
                                                        FileName = "Thread Hijack",
                                                        FilePath = "",
                                                        ThreatType = "Anti-Hook",
                                                        FileSize = "",
                                                        Severity = Severity.Critical,
                                                        Description = $"Remote thread in PID {te.th32OwnerProcessID} with start address in IAuthBytes memory range (possible thread hijack)"
                                                    });
                                                }
                                            }
                                        }
                                    }
                                }
                                finally
                                {
                                    CloseHandle(hThread);
                                }
                            }
                            catch { }
                        }
                        while (Thread32Next(hSnapshot, ref te));
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

        private static List<ThreatInfo> CheckHardwareBreakpoints()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                int currentPid = GetCurrentProcessId();
                bool is64Bit = IntPtr.Size == 8;

                IntPtr hSnapshot = CreateToolhelp32Snapshot(0x00000004u, 0);
                if (hSnapshot == IntPtr.Zero || hSnapshot == (IntPtr)(-1))
                    return threats;

                try
                {
                    THREADENTRY32 te = new();
                    te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));

                    if (Thread32First(hSnapshot, ref te))
                    {
                        do
                        {
                            if ((int)te.th32OwnerProcessID != currentPid) continue;

                            try
                            {
                                IntPtr hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_LIMITED_INFORMATION, false, te.th32ThreadID);
                                if (hThread == IntPtr.Zero) continue;

                                try
                                {
                                    if (is64Bit)
                                    {
                                        CONTEXT64 ctx = new();
                                        ctx.ContextFlags = CONTEXT_AMD64 | 0x10; // CONTEXT_DEBUG_REGISTERS
                                        if (GetThreadContext(hThread, ref ctx))
                                        {
                                            if (ctx.Dr0 != 0) threats.Add(new ThreatInfo { FileName = "HW Breakpoint", FilePath = "", ThreatType = "Anti-Hook", FileSize = "", Severity = Severity.High, Description = $"Thread {te.th32ThreadID}: DR0 = 0x{ctx.Dr0:X16}" });
                                            if (ctx.Dr1 != 0) threats.Add(new ThreatInfo { FileName = "HW Breakpoint", FilePath = "", ThreatType = "Anti-Hook", FileSize = "", Severity = Severity.High, Description = $"Thread {te.th32ThreadID}: DR1 = 0x{ctx.Dr1:X16}" });
                                            if (ctx.Dr2 != 0) threats.Add(new ThreatInfo { FileName = "HW Breakpoint", FilePath = "", ThreatType = "Anti-Hook", FileSize = "", Severity = Severity.High, Description = $"Thread {te.th32ThreadID}: DR2 = 0x{ctx.Dr2:X16}" });
                                            if (ctx.Dr3 != 0) threats.Add(new ThreatInfo { FileName = "HW Breakpoint", FilePath = "", ThreatType = "Anti-Hook", FileSize = "", Severity = Severity.High, Description = $"Thread {te.th32ThreadID}: DR3 = 0x{ctx.Dr3:X16}" });
                                        }
                                    }
                                    else
                                    {
                                        CONTEXT32 ctx = new();
                                        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
                                        if (GetThreadContext(hThread, ref ctx))
                                        {
                                            if (ctx.Dr0 != 0) threats.Add(new ThreatInfo { FileName = "HW Breakpoint", FilePath = "", ThreatType = "Anti-Hook", FileSize = "", Severity = Severity.High, Description = $"Thread {te.th32ThreadID}: DR0 = 0x{ctx.Dr0:X8}" });
                                            if (ctx.Dr1 != 0) threats.Add(new ThreatInfo { FileName = "HW Breakpoint", FilePath = "", ThreatType = "Anti-Hook", FileSize = "", Severity = Severity.High, Description = $"Thread {te.th32ThreadID}: DR1 = 0x{ctx.Dr1:X8}" });
                                            if (ctx.Dr2 != 0) threats.Add(new ThreatInfo { FileName = "HW Breakpoint", FilePath = "", ThreatType = "Anti-Hook", FileSize = "", Severity = Severity.High, Description = $"Thread {te.th32ThreadID}: DR2 = 0x{ctx.Dr2:X8}" });
                                            if (ctx.Dr3 != 0) threats.Add(new ThreatInfo { FileName = "HW Breakpoint", FilePath = "", ThreatType = "Anti-Hook", FileSize = "", Severity = Severity.High, Description = $"Thread {te.th32ThreadID}: DR3 = 0x{ctx.Dr3:X8}" });
                                        }
                                    }
                                }
                                finally
                                {
                                    CloseHandle(hThread);
                                }
                            }
                            catch { }
                        }
                        while (Thread32Next(hSnapshot, ref te));
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

        private static List<ThreatInfo> CheckEATHooks()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                var process = Process.GetCurrentProcess();
                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        if (module.FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                            module.FileName.Contains("IAuthBytes"))
                            continue;

                        IntPtr modBase = module.BaseAddress;
                        byte[] peHeader = new byte[4096];
                        if (!ReadProcessMemory(GetCurrentProcess(), modBase, peHeader, peHeader.Length, out int hdrRead) || hdrRead < 64)
                            continue;

                        if (peHeader[0] != 0x4D || peHeader[1] != 0x5A) continue;

                        int peOffset = BitConverter.ToInt32(peHeader, 0x3C);
                        if (peOffset + 24 >= peHeader.Length) continue;
                        if (peHeader[peOffset] != 0x50 || peHeader[peOffset + 1] != 0x45) continue;

                        // Parse export directory
                        int exportDirRva = BitConverter.ToInt32(peHeader, peOffset + 24 + 96 + 20);
                        int exportDirSize = BitConverter.ToInt32(peHeader, peOffset + 24 + 96 + 24);
                        int numFunctions = BitConverter.ToInt32(peHeader, peOffset + 24 + 96 + 20 + 4);

                        if (exportDirRva == 0 || exportDirSize == 0 || numFunctions == 0) continue;

                        // Read export section
                        byte[] exportBytes = new byte[exportDirSize + 256];
                        IntPtr exportAddr = IntPtr.Add(modBase, exportDirRva);
                        if (!ReadProcessMemory(GetCurrentProcess(), exportAddr, exportBytes, exportBytes.Length, out int expRead) || expRead < 40)
                            continue;

                        int functionsRva = BitConverter.ToInt32(exportBytes, 20);
                        int numNames = BitConverter.ToInt32(exportBytes, 24);
                        int nameOrdinalRva = BitConverter.ToInt32(exportBytes, 28);

                        if (functionsRva == 0) continue;

                        // Read function RVAs
                        byte[] funcBytes = new byte[numFunctions * 4];
                        IntPtr funcAddr = IntPtr.Add(modBase, functionsRva);
                        if (!ReadProcessMemory(GetCurrentProcess(), funcAddr, funcBytes, funcBytes.Length, out int funcRead) || funcRead < numFunctions * 4)
                            continue;

                        long modBaseLong = modBase.ToInt64();
                        long modEndLong = modBaseLong + module.ModuleMemorySize;

                        int hookedCount = 0;
                        for (int i = 0; i < numFunctions && i < 1000; i++)
                        {
                            int funcRva = BitConverter.ToInt32(funcBytes, i * 4);
                            if (funcRva == 0) continue;

                            long funcAddrLong = modBaseLong + funcRva;
                            if (funcAddrLong < modBaseLong || funcAddrLong > modEndLong)
                            {
                                hookedCount++;
                            }
                        }

                        if (hookedCount > 0)
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = Path.GetFileName(module.FileName),
                                FilePath = module.FileName,
                                ThreatType = "Anti-Hook",
                                FileSize = "",
                                Severity = Severity.Critical,
                                Description = $"EAT hook detected: {hookedCount} export(s) point outside module memory range"
                            });
                        }
                    }
                    catch { }
                }
            }
            catch { }

            return threats;
        }

        private static List<ThreatInfo> CheckHookEngineSignatures()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                var process = Process.GetCurrentProcess();
                foreach (ProcessModule module in process.Modules)
                {
                    try
                    {
                        if (module.FileName.EndsWith(".exe", StringComparison.OrdinalIgnoreCase) &&
                            module.FileName.Contains("IAuthBytes"))
                            continue;

                        IntPtr modBase = module.BaseAddress;
                        int modSize = module.ModuleMemorySize;
                        if (modSize < 1024) continue;

                        byte[] textSection = new byte[Math.Min(modSize, 0x100000)];
                        if (!ReadProcessMemory(GetCurrentProcess(), modBase, textSection, textSection.Length, out int bytesRead) || bytesRead < 100)
                            continue;

                        // EasyHook trampoline signature: push addr; mov eax, addr; jmp eax; nop...
                        byte[] easyHookSig = { 0x68, 0x00, 0x00, 0x00, 0x00, 0xB8, 0x00, 0x00, 0x00, 0x00, 0xFF, 0xE0 };
                        // MinHook: jmp [rip+offset] pattern 0xFF 0x25 followed by relative offset
                        // Detours: typically uses 0xE9 JMP with trampoline

                        for (int i = 0; i < bytesRead - 12; i++)
                        {
                            // EasyHook signature
                            if (textSection[i] == 0x68 && textSection[i + 5] == 0xB8 && textSection[i + 10] == 0xFF && textSection[i + 11] == 0xE0)
                            {
                                uint pushAddr = BitConverter.ToUInt32(textSection, i + 1);
                                uint movAddr = BitConverter.ToUInt32(textSection, i + 6);
                                if (pushAddr == movAddr && movAddr != 0)
                                {
                                    threats.Add(new ThreatInfo
                                    {
                                        FileName = Path.GetFileName(module.FileName),
                                        FilePath = module.FileName,
                                        ThreatType = "Anti-Hook",
                                        FileSize = "",
                                        Severity = Severity.Critical,
                                        Description = $"Hook engine trampoline (EasyHook pattern) at offset 0x{i:X}"
                                    });
                                    break;
                                }
                            }

                            // Detours-style: FF 25 with relative offset to IAT
                            if (textSection[i] == 0xFF && textSection[i + 1] == 0x25)
                            {
                                int relOffset = BitConverter.ToInt32(textSection, i + 2);
                                long targetAddr = (long)i + 6 + relOffset;
                                if (targetAddr < 0 || targetAddr > textSection.Length)
                                {
                                    // Target is outside .text — likely a detour trampoline
                                    if (i > 0 && textSection[i - 1] == 0xCC) // preceded by INT3
                                    {
                                        threats.Add(new ThreatInfo
                                        {
                                            FileName = Path.GetFileName(module.FileName),
                                            FilePath = module.FileName,
                                            ThreatType = "Anti-Hook",
                                            FileSize = "",
                                            Severity = Severity.High,
                                            Description = $"Possible Detours trampoline at offset 0x{i:X} (indirect JMP past INT3)"
                                        });
                                        break;
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

        // =====================================================================
        // PEB DEBUGGER FLAGS (direct — bypasses hooked IsDebuggerPresent)
        // =====================================================================
        private static List<ThreatInfo> CheckPEBDebuggerFlags()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                IntPtr teb = NtCurrentTeb();
                if (teb != IntPtr.Zero)
                {
                    IntPtr peb = Marshal.ReadIntPtr(teb, 0x60); // PEB at TEB+0x60 (x64)
                    if (peb != IntPtr.Zero)
                    {
                        // BeingDebugged at PEB+0x2
                        byte beingDebugged = Marshal.ReadByte(peb, 0x2);
                        if (beingDebugged != 0)
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = "System", FilePath = "", ThreatType = "Anti-Hook", FileSize = "",
                                Severity = Severity.High,
                                Description = "PEB.BeingDebugged flag is set — debugger present (direct PEB check)"
                            });
                        }

                        // NtGlobalFlag at PEB+0xBC (x64) or PEB+0x68 (x86)
                        int ntfOffset = IntPtr.Size == 8 ? 0xBC : 0x68;
                        int ntGlobalFlag = Marshal.ReadInt32(peb, ntfOffset);
                        int debugFlags = 0x70; // FLG_HEAP_ENABLE_TAIL_CHECK | FREE_CHECK | VALIDATE_PARAMETERS
                        if ((ntGlobalFlag & debugFlags) != 0)
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = "System", FilePath = "", ThreatType = "Anti-Hook", FileSize = "",
                                Severity = Severity.High,
                                Description = $"PEB.NtGlobalFlag = 0x{ntGlobalFlag:X} — debug heap flags detected"
                            });
                        }

                        // ProcessHeap flags at PEB+0x18 -> Heap+0x40 (Flags) and Heap+0x70 (ForceFlags)
                        IntPtr processHeap = Marshal.ReadIntPtr(peb, 0x18);
                        if (processHeap != IntPtr.Zero)
                        {
                            int heapFlags = Marshal.ReadInt32(processHeap, 0x40);
                            int heapForceFlags = Marshal.ReadInt32(processHeap, 0x70);
                            if (heapForceFlags != 0)
                            {
                                threats.Add(new ThreatInfo
                                {
                                    FileName = "System", FilePath = "", ThreatType = "Anti-Hook", FileSize = "",
                                    Severity = Severity.High,
                                    Description = $"ProcessHeap.ForceFlags = 0x{heapForceFlags:X} — debug heap manipulation detected"
                                });
                            }
                        }
                    }
                }
            }
            catch { }

            return threats;
        }

        // =====================================================================
        // PARENT PROCESS VALIDATION
        // =====================================================================
        private static List<ThreatInfo> CheckParentProcess()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                IntPtr parentPid = IntPtr.Zero;
                int status = NtQueryInformationProcess(GetCurrentProcess(), 0, ref parentPid, IntPtr.Size, IntPtr.Zero);
                if (status == 0 && parentPid != IntPtr.Zero)
                {
                    int ppid = parentPid.ToInt32();
                    try
                    {
                        using var parentProc = Process.GetProcessById(ppid);
                        string parentName = parentProc.ProcessName.ToLowerInvariant();

                        bool isSuspicious = SuspiciousParentProcesses.Contains(parentName);
                        if (isSuspicious)
                        {
                            threats.Add(new ThreatInfo
                            {
                                FileName = parentName, FilePath = "", ThreatType = "Anti-Hook", FileSize = "",
                                Severity = Severity.Critical,
                                Description = $"Suspicious parent process: {parentName} (PID {ppid}) spawned IAuthBytes — possible process hollowing"
                            });
                        }
                    }
                    catch
                    {
                        // Parent process not found — could be PPID spoofing
                    }
                }
            }
            catch { }

            return threats;
        }

        // =====================================================================
        // APC INJECTION DETECTION
        // =====================================================================
        private static List<ThreatInfo> CheckAPCInjection()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                int currentPid = GetCurrentProcessId();
                IntPtr hSnapshot = CreateToolhelp32Snapshot(0x00000004u, 0);
                if (hSnapshot == IntPtr.Zero || hSnapshot == (IntPtr)(-1))
                    return threats;

                try
                {
                    THREADENTRY32 te = new();
                    te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));

                    if (Thread32First(hSnapshot, ref te))
                    {
                        do
                        {
                            if ((int)te.th32OwnerProcessID != currentPid) continue;

                            try
                            {
                                IntPtr hThread = OpenThread(THREAD_QUERY_INFORMATION, false, te.th32ThreadID);
                                if (hThread == IntPtr.Zero) continue;

                                try
                                {
                                    // Check thread state — alertable threads can receive APCs
                                    IntPtr threadState = IntPtr.Zero;
                                    int stateStatus = NtQueryInformationThread(hThread, 0 /* ThreadBasicInformation */, ref threadState, IntPtr.Size, IntPtr.Zero);
                                    if (stateStatus == 0)
                                    {
                                        // ThreadState is at offset 0 of THREAD_BASIC_INFORMATION
                                        int state = Marshal.ReadInt32(threadState, 0);
                                        if (state == 5) // Waiting state — potentially alertable
                                        {
                                            // Check alertable flag at offset 8 of THREAD_BASIC_INFORMATION
                                            byte alertable = Marshal.ReadByte(threadState, 8);
                                            if (alertable != 0)
                                            {
                                                threats.Add(new ThreatInfo
                                                {
                                                    FileName = "APC", FilePath = "", ThreatType = "Anti-Hook", FileSize = "",
                                                    Severity = Severity.High,
                                                    Description = $"Thread {te.th32ThreadID} is alertable — can receive APC injection"
                                                });
                                            }
                                        }
                                    }
                                }
                                finally
                                {
                                    CloseHandle(hThread);
                                }
                            }
                            catch { }
                        }
                        while (Thread32Next(hSnapshot, ref te));
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

        // =====================================================================
        // INJECTED PE DETECTION (memory-resident DLLs)
        // =====================================================================
        private static List<ThreatInfo> CheckInjectedPE()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                IntPtr selfBase = GetModuleHandle(string.Empty);
                if (selfBase == IntPtr.Zero) return threats;

                IntPtr queryAddr = IntPtr.Zero;
                int checkedRegions = 0;
                int injectedCount = 0;

                while (checkedRegions < 200)
                {
                    MEMORY_BASIC_INFORMATION mbi;
                    int status = NtQueryVirtualMemory(GetCurrentProcess(), queryAddr, 0, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>(), out _);
                    if (status != 0) break;
                    if (mbi.BaseAddress == IntPtr.Zero) break;

                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                        (mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ))
                    {
                        int regionSize = mbi.RegionSize.ToInt32();
                        if (regionSize > 4096 && regionSize < 0x10000000)
                        {
                            byte[] header = new byte[Math.Min(regionSize, 1024)];
                            if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, header, header.Length, out int read) && read >= 2)
                            {
                                if (header[0] == 0x4D && header[1] == 0x5A)
                                {
                                    long headerLong = BitConverter.ToInt32(header, 0x3C);
                                    if (headerLong > 0 && headerLong < read - 4)
                                    {
                                        if (header[(int)headerLong] == 0x50 && header[(int)headerLong + 1] == 0x45)
                                        {
                                            injectedCount++;
                                            if (injectedCount <= 5)
                                            {
                                                threats.Add(new ThreatInfo
                                                {
                                                    FileName = "Injected PE", FilePath = "",
                                                    ThreatType = "Anti-Hook", FileSize = FormatSize(regionSize),
                                                    Severity = Severity.Critical,
                                                    Description = $"PE header found in private executable memory at 0x{mbi.BaseAddress.ToInt64():X} — possible process hollowing or reflective DLL injection"
                                                });
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }

                    long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                    if (nextAddr <= queryAddr.ToInt64()) break;
                    queryAddr = new IntPtr(nextAddr);
                    checkedRegions++;
                }

                if (injectedCount > 5)
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = "Injected PE", FilePath = "", ThreatType = "Anti-Hook", FileSize = "",
                        Severity = Severity.Critical,
                        Description = $"Total: {injectedCount} injected PE(s) detected in memory"
                    });
                }
            }
            catch { }

            return threats;
        }

        // =====================================================================
        // SYSCALL INTEGRITY (ntdll stub validation)
        // =====================================================================
        private static List<ThreatInfo> CheckSyscallIntegrity()
        {
            var threats = new List<ThreatInfo>();

            try
            {
                IntPtr hNtdll = GetModuleHandle("ntdll.dll");
                if (hNtdll == IntPtr.Zero) return threats;

                string[] syscallFuncs = { "NtCreateFile", "NtReadFile", "NtWriteFile", "NtProtectVirtualMemory", "NtAllocateVirtualMemory" };

                foreach (string funcName in syscallFuncs)
                {
                    IntPtr funcAddr = GetProcAddress(hNtdll, funcName);
                    if (funcAddr == IntPtr.Zero) continue;

                    byte[] stub = new byte[32];
                    if (!ReadProcessMemory(GetCurrentProcess(), funcAddr, stub, stub.Length, out int read) || read < 16)
                        continue;

                    // x64 syscall stub: 4C 8B D1 (MOV R10, RCX) followed by B8 XX XX 00 00 (MOV EAX, SSN)
                    // Then 0F 05 (SYSCALL) followed by C3 (RET)
                    bool hasMovR10 = stub[0] == 0x4C && stub[1] == 0x8B && stub[2] == 0xD1;
                    bool hasMovEax = stub[3] == 0xB8;
                    bool hasSyscall = false;

                    for (int i = 0; i < read - 1; i++)
                    {
                        if (stub[i] == 0x0F && stub[i + 1] == 0x05)
                        {
                            hasSyscall = true;
                            break;
                        }
                    }

                    if (!hasMovR10 || !hasMovEax || !hasSyscall)
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = "ntdll.dll", FilePath = "", ThreatType = "Anti-Hook", FileSize = "",
                            Severity = Severity.Critical,
                            Description = $"Syscall stub for {funcName} is malformed — possible Hell's Gate or direct syscall hook (bytes: {BitConverter.ToString(stub, 0, 8)})"
                        });
                    }
                }
            }
            catch { }

            return threats;
        }

        // =====================================================================
        // ANTI-KILL: Apply process mitigation policies
        // =====================================================================
        private static void ApplyProcessProtections()
        {
            try
            {
                // Restrict dynamic code generation — blocks VirtualAlloc + EXECUTE in child processes
                try
                {
                    IntPtr hProcess = GetCurrentProcess();
                    int enable = 1;
                    IntPtr buf = Marshal.AllocHGlobal(4);
                    Marshal.WriteInt32(buf, enable);
                    bool ok = SetProcessMitigationPolicy(ProcessDynamicCodePolicy, buf, 4);
                    Marshal.FreeHGlobal(buf);
                    if (ok) Logger.Log("ApplyProcessProtections: Dynamic code policy applied");
                }
                catch { }

                Logger.Log("ApplyProcessProtections: Process protections initialized");
            }
            catch (Exception ex)
            {
                Logger.LogException("ApplyProcessProtections", ex);
            }
        }

        // =====================================================================
        // HIDE THREADS FROM DEBUGGER
        // =====================================================================
        private static void HideThreadsFromDebugger()
        {
            try
            {
                int currentPid = GetCurrentProcessId();
                int hiddenCount = 0;

                IntPtr hSnapshot = CreateToolhelp32Snapshot(0x00000004u, 0);
                if (hSnapshot == IntPtr.Zero || hSnapshot == (IntPtr)(-1))
                    return;

                try
                {
                    THREADENTRY32 te = new();
                    te.dwSize = (uint)Marshal.SizeOf(typeof(THREADENTRY32));

                    if (Thread32First(hSnapshot, ref te))
                    {
                        do
                        {
                            if ((int)te.th32OwnerProcessID != currentPid) continue;

                            try
                            {
                                IntPtr hThread = OpenThread(THREAD_SET_INFORMATION, false, te.th32ThreadID);
                                if (hThread != IntPtr.Zero)
                                {
                                    try
                                    {
                                        int result = NtSetInformationThread(hThread, ThreadHideFromDebugger, IntPtr.Zero, 0);
                                        if (result == 0) hiddenCount++;
                                    }
                                    finally
                                    {
                                        CloseHandle(hThread);
                                    }
                                }
                            }
                            catch { }
                        }
                        while (Thread32Next(hSnapshot, ref te));
                    }
                }
                finally
                {
                    CloseHandle(hSnapshot);
                }

                Logger.Log($"HideThreadsFromDebugger: Hidden {hiddenCount} threads from debugger");
            }
            catch (Exception ex)
            {
                Logger.LogException("HideThreadsFromDebugger", ex);
            }
        }

        // =====================================================================
        // ANTI-KILL: Monitor own liveness
        // =====================================================================
        private static void CheckProcessAlive()
        {
            try
            {
                // Check if any external process has PROCESS_TERMINATE handle to us
                int currentPid = GetCurrentProcessId();
                int handleInfoSize = 0x10000;

                IntPtr handleInfoPtr = Marshal.AllocHGlobal(handleInfoSize);
                try
                {
                    int status = NtQuerySystemInformation(SystemExtendedHandleInformation, handleInfoPtr, handleInfoSize, out _);
                    if (status != 0) return;

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
                                bool hasTerminate = (accessMask & 0x0001) != 0; // PROCESS_TERMINATE
                                bool hasSuspend = (accessMask & 0x0800) != 0; // PROCESS_SUSPEND_RESUME

                                if (hasTerminate || hasSuspend)
                                {
                                    string ownerName = "";
                                    try
                                    {
                                        using var ownerProcess = Process.GetProcessById(ownerPid);
                                        ownerName = ownerProcess.ProcessName;
                                    }
                                    catch { ownerName = $"PID {ownerPid}"; }

                                    Logger.Log($"CRITICAL: {ownerName} holds PROCESS_TERMINATE/SUSPEND handle to IAuthBytes — possible kill/suspend attempt");
                                    _integrityCheckFailed = true;
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
        }

        // =====================================================================
        // DETECT INJECTED PE (continuous monitoring)
        // =====================================================================
        private static void DetectInjectedPE()
        {
            try
            {
                IntPtr selfBase = GetModuleHandle(string.Empty);
                if (selfBase == IntPtr.Zero) return;

                IntPtr queryAddr = IntPtr.Zero;
                int checkedRegions = 0;

                while (checkedRegions < 100)
                {
                    MEMORY_BASIC_INFORMATION mbi;
                    int status = NtQueryVirtualMemory(GetCurrentProcess(), queryAddr, 0, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>(), out _);
                    if (status != 0) break;
                    if (mbi.BaseAddress == IntPtr.Zero) break;

                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                        (mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ))
                    {
                        int regionSize = mbi.RegionSize.ToInt32();
                        if (regionSize > 4096 && regionSize < 0x10000000)
                        {
                            byte[] header = new byte[Math.Min(regionSize, 1024)];
                            if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, header, header.Length, out int read) && read >= 2)
                            {
                                if (header[0] == 0x4D && header[1] == 0x5A)
                                {
                                    int peOff = BitConverter.ToInt32(header, 0x3C);
                                    if (peOff > 0 && peOff < read - 4 && header[peOff] == 0x50 && header[peOff + 1] == 0x45)
                                    {
                                        Logger.Log($"CRITICAL: Injected PE detected at 0x{mbi.BaseAddress.ToInt64():X} (size: {FormatSize(regionSize)})");
                                        _integrityCheckFailed = true;
                                        return;
                                    }
                                }
                            }
                        }
                    }

                    long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                    if (nextAddr <= queryAddr.ToInt64()) break;
                    queryAddr = new IntPtr(nextAddr);
                    checkedRegions++;
                }
            }
            catch { }
        }

        // =====================================================================
        // DETECT SHELLCODE REGIONS (executable memory without module backing)
        // =====================================================================
        private static void DetectShellcodeRegions()
        {
            try
            {
                IntPtr selfBase = GetModuleHandle(string.Empty);
                if (selfBase == IntPtr.Zero) return;

                var process = Process.GetCurrentProcess();
                IntPtr queryAddr = IntPtr.Zero;
                int checkedRegions = 0;
                int suspiciousCount = 0;

                while (checkedRegions < 100)
                {
                    MEMORY_BASIC_INFORMATION mbi;
                    int status = NtQueryVirtualMemory(GetCurrentProcess(), queryAddr, 0, out mbi, Marshal.SizeOf<MEMORY_BASIC_INFORMATION>(), out _);
                    if (status != 0) break;
                    if (mbi.BaseAddress == IntPtr.Zero) break;

                    if (mbi.State == MEM_COMMIT && mbi.Type == MEM_PRIVATE &&
                        (mbi.Protect == PAGE_EXECUTE || mbi.Protect == PAGE_EXECUTE_READ))
                    {
                        int regionSize = mbi.RegionSize.ToInt32();
                        if (regionSize > 256 && regionSize < 0x1000000)
                        {
                            // Check if this region contains shellcode patterns
                            byte[] buf = new byte[Math.Min(regionSize, 4096)];
                            if (ReadProcessMemory(GetCurrentProcess(), mbi.BaseAddress, buf, buf.Length, out int read) && read > 0)
                            {
                                double entropy = CalcEntropy(buf, 0, read);
                                if (entropy > 6.0 && regionSize > 1024)
                                {
                                    suspiciousCount++;
                                }
                            }
                        }
                    }

                    long nextAddr = mbi.BaseAddress.ToInt64() + mbi.RegionSize.ToInt64();
                    if (nextAddr <= queryAddr.ToInt64()) break;
                    queryAddr = new IntPtr(nextAddr);
                    checkedRegions++;
                }

                if (suspiciousCount > 10)
                {
                    Logger.Log($"WARNING: {suspiciousCount} high-entropy executable memory regions detected — possible shellcode");
                }
            }
            catch { }
        }

        // =====================================================================
        // FIX: CheckHardwareBreakpoints — scan ALL threads, not just current
        // =====================================================================
        // The existing CheckHardwareBreakpoints only checks GetCurrentThread().
        // This override scans every thread in the process.

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
