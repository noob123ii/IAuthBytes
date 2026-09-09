using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;

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

        private static readonly byte[] JmpPatch = { 0xE9, 0x00, 0x00, 0x00, 0x00 };
        private static readonly byte[] CallPatch = { 0xE8, 0x00, 0x00, 0x00, 0x00 };
        private static readonly byte[] RetPatch = { 0xC3 };
        private static readonly byte[] NopPatch = { 0x90 };

        private static readonly string[] CriticalModules = {
            "ntdll.dll", "kernel32.dll", "user32.dll", "advapi32.dll",
            "ws2_32.dll", "winhttp.dll", "crypt32.dll", "shell32.dll"
        };

        public static List<ThreatInfo> RunAntiHookCheck(string gtPath)
        {
            var threats = new List<ThreatInfo>();

            threats.AddRange(CheckDebuggerPresence());
            threats.AddRange(CheckInlineHooks());
            threats.AddRange(CheckIATHooks());
            threats.AddRange(CheckProcessInjection());
            threats.AddRange(CheckSelfIntegrity(gtPath));

            return threats;
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

            return threats;
        }

        private static List<ThreatInfo> CheckInlineHooks()
        {
            var threats = new List<ThreatInfo>();

            foreach (string moduleName in CriticalModules)
            {
                try
                {
                    IntPtr moduleHandle = GetModuleHandle(moduleName);
                    if (moduleHandle == IntPtr.Zero) continue;

                    IntPtr procAddr = GetProcAddress(moduleHandle, "NtCreateFile");
                    if (procAddr == IntPtr.Zero) continue;

                    byte[] firstBytes = new byte[16];
                    IntPtr readBase = procAddr;

                    if (ReadProcessMemory(GetCurrentProcess(), readBase, firstBytes, firstBytes.Length, out int bytesRead) && bytesRead >= 5)
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
                                Description = $"Inline hook on {moduleName}: {hookType} at entry point"
                            });
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
                                int virtualAddr = BitConverter.ToInt32(moduleBytes, sectionOffset + 12);
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

        private static List<ThreatInfo> CheckProcessInjection()
        {
            return new List<ThreatInfo>();
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
    }
}
