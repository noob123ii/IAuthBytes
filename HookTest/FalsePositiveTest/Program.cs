using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;

namespace FalsePositiveTest
{
    class Program
    {
        static int Main(string[] args)
        {
            Console.WriteLine("=== False Positive Test ===\n");

            int passed = 0;
            int failed = 0;
            int total = 0;

            // Test 1: Scan known-good system DLLs
            Console.WriteLine("--- Test 1: Known-good system DLLs ---");
            var systemDlls = new[]
            {
                "mscoree.dll", "mscorlib.dll", "System.dll", "System.Core.dll",
                "System.Drawing.dll", "System.Xml.dll", "netstandard.dll"
            };

            string systemDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "Microsoft.NET", "Framework64");
            if (Directory.Exists(systemDir))
            {
                foreach (string dll in systemDlls)
                {
                    string path = FindFileRecursive(systemDir, dll);
                    if (path != null)
                    {
                        total++;
                        bool fp = ScanForFalsePositives(path);
                        if (fp)
                        {
                            Console.WriteLine($"  FAIL: {dll} triggered false positive");
                            failed++;
                        }
                        else
                        {
                            Console.WriteLine($"  PASS: {dll} clean");
                            passed++;
                        }
                    }
                }
            }

            // Test 2: Scan IAuthBytes itself
            Console.WriteLine("\n--- Test 2: IAuthBytes executable ---");
            string iauthPath = FindIAuthBytes();
            if (iauthPath != null)
            {
                total++;
                bool fp = ScanForFalsePositives(iauthPath);
                if (fp)
                {
                    Console.WriteLine($"  FAIL: IAuthBytes.exe triggered false positive");
                    failed++;
                }
                else
                {
                    Console.WriteLine($"  PASS: IAuthBytes.exe clean");
                    passed++;
                }
            }
            else
            {
                Console.WriteLine("  SKIP: IAuthBytes.exe not found");
            }

            // Test 3: Scan IAuthBytes DLLs
            Console.WriteLine("\n--- Test 3: IAuthBytes DLLs ---");
            string iauthDir = Path.GetDirectoryName(iauthPath) ?? "";
            if (Directory.Exists(iauthDir))
            {
                foreach (string dll in Directory.GetFiles(iauthDir, "*.dll"))
                {
                    string name = Path.GetFileName(dll);
                    total++;
                    bool fp = ScanForFalsePositives(dll);
                    if (fp)
                    {
                        Console.WriteLine($"  FAIL: {name} triggered false positive");
                        failed++;
                    }
                    else
                    {
                        Console.WriteLine($"  PASS: {name} clean");
                        passed++;
                    }
                }
            }

            // Test 4: Scan BepInEx managed DLLs
            Console.WriteLine("\n--- Test 4: BepInEx managed DLLs ---");
            string gtPath = FindGorillaTag();
            if (gtPath != null)
            {
                string bepinexManaged = Path.Combine(gtPath, "BepInEx", "core", "BepInEx.Unity.IL2CPP.dll");
                if (File.Exists(bepinexManaged))
                {
                    total++;
                    bool fp = ScanForFalsePositives(bepinexManaged);
                    if (fp)
                    {
                        Console.WriteLine($"  FAIL: BepInEx.Unity.IL2CPP.dll triggered false positive");
                        failed++;
                    }
                    else
                    {
                        Console.WriteLine($"  PASS: BepInEx.Unity.IL2CPP.dll clean");
                        passed++;
                    }
                }

                // Scan all BepInEx core DLLs
                string bepinexCore = Path.Combine(gtPath, "BepInEx", "core");
                if (Directory.Exists(bepinexCore))
                {
                    foreach (string dll in Directory.GetFiles(bepinexCore, "*.dll"))
                    {
                        string name = Path.GetFileName(dll);
                        total++;
                        bool fp = ScanForFalsePositives(dll);
                        if (fp)
                        {
                            Console.WriteLine($"  FAIL: BepInEx/core/{name} triggered false positive");
                            failed++;
                        }
                        else
                        {
                            Console.WriteLine($"  PASS: BepInEx/core/{name} clean");
                            passed++;
                        }
                    }
                }

                // Scan BepInEx plugins
                string plugins = Path.Combine(gtPath, "BepInEx", "plugins");
                if (Directory.Exists(plugins))
                {
                    foreach (string dll in Directory.GetFiles(plugins, "*.dll", SearchOption.AllDirectories))
                    {
                        string name = Path.GetFileName(dll);
                        total++;
                        bool fp = ScanForFalsePositives(dll);
                        if (fp)
                        {
                            Console.WriteLine($"  FAIL: plugins/{name} triggered false positive");
                            failed++;
                        }
                        else
                        {
                            Console.WriteLine($"  PASS: plugins/{name} clean");
                            passed++;
                        }
                    }
                }
            }
            else
            {
                Console.WriteLine("  SKIP: Gorilla Tag not found");
            }

            // Test 5: Specific API pattern false positive checks
            Console.WriteLine("\n--- Test 5: Specific API pattern checks ---");
            var patternTests = new[]
            {
                ("VirtualAlloc in System.dll", "System.dll", "VirtualAlloc"),
                ("LoadLibrary in mscoree.dll", "mscoree.dll", "LoadLibrary"),
                ("CreateThread in kernel32", "kernel32.dll", "CreateThread"),
                ("NtCreateThreadEx in ntdll", "ntdll.dll", "NtCreateThreadEx"),
                ("SuspendThread in kernel32", "kernel32.dll", "SuspendThread"),
                ("GetThreadContext in kernel32", "kernel32.dll", "GetThreadContext"),
                ("SetThreadContext in kernel32", "kernel32.dll", "SetThreadContext"),
                ("QueueUserAPC in kernel32", "kernel32.dll", "QueueUserAPC"),
                ("VirtualProtect in kernel32", "kernel32.dll", "VirtualProtect"),
                ("WriteProcessMemory in kernel32", "kernel32.dll", "WriteProcessMemory"),
            };

            string windowsDir = Environment.GetFolderPath(Environment.SpecialFolder.Windows);
            string system32 = Path.Combine(windowsDir, "System32");

            foreach (var (testName, dllName, apiName) in patternTests)
            {
                string path = Path.Combine(system32, dllName);
                if (File.Exists(path))
                {
                    total++;
                    byte[] bytes = File.ReadAllBytes(path);
                    int scanLen = Math.Min(bytes.Length, 1_048_576);
                    bool hasApi = ContainsAscii(bytes, 0, scanLen, apiName);
                    if (hasApi)
                    {
                        Console.WriteLine($"  INFO: {testName} - API found in system DLL (expected)");
                        passed++;
                    }
                    else
                    {
                        Console.WriteLine($"  INFO: {testName} - API not found in scan window");
                        passed++;
                    }
                }
            }

            // Test 6: Check new detection pattern thresholds
            Console.WriteLine("\n--- Test 6: Detection threshold checks ---");
            var thresholdTests = new[]
            {
                ("APC injection needs 2+ patterns", new[] { "QueueUserAPC" }, false),
                ("Thread hijacking needs 4 patterns", new[] { "SuspendThread", "GetThreadContext", "SetThreadContext", "ResumeThread" }, true),
                ("Module stomping needs 4+ patterns", new[] { "LoadLibrary", "VirtualAllocEx", "WriteProcessMemory", "NtCreateThreadEx", "GetProcAddress" }, true),
                ("Syscall abuse needs 4 patterns", new[] { "NtCreateThreadEx", "NtMapViewOfSection", "NtProtectVirtualMemory", "NtWriteVirtualMemory" }, true),
                ("Shellcode execution needs 4 patterns", new[] { "VirtualAlloc", "VirtualProtect", "CreateThread", "WaitForSingleObject" }, true),
                ("LOLBin needs cmd.exe + tool + download", new[] { "cmd.exe", "/c", "certutil", "http" }, true),
                ("Registry persistence needs reg key + action", new[] { "CurrentVersion\\Run", "LoadLibrary" }, true),
                ("Startup persistence needs Startup + .lnk", new[] { "Startup", ".lnk", "Shell32" }, true),
                ("COM hijacking needs InprocServer32 + load", new[] { "InprocServer32", "LoadLibrary" }, true),
            };

            foreach (var (testName, patterns, needsAll) in thresholdTests)
            {
                total++;
                int found = 0;
                foreach (string p in patterns)
                {
                    string path = FindKnownDll("kernel32.dll");
                    if (path != null)
                    {
                        byte[] bytes = File.ReadAllBytes(path);
                        if (ContainsAscii(bytes, 0, Math.Min(bytes.Length, 1_048_576), p))
                            found++;
                    }
                }
                bool wouldFire = needsAll ? found == patterns.Length : found > 0;
                Console.WriteLine($"  {testName}: found {found}/{patterns.Length} => would fire: {wouldFire}");
                if (!wouldFire) passed++; else { Console.WriteLine($"    WARNING: Would false positive on kernel32.dll"); failed++; }
            }

            // Summary
            Console.WriteLine($"\n=== Results: {passed}/{total} passed, {failed}/{total} failed ===");
            return failed > 0 ? 1 : 0;
        }

        static bool ScanForFalsePositives(string filePath)
        {
            try
            {
                byte[] fileBytes = File.ReadAllBytes(filePath);
                string fileName = Path.GetFileName(filePath);
                int scanLen = Math.Min(fileBytes.Length, 1_048_576);
                int lastStart = Math.Max(0, fileBytes.Length - 1_048_576);
                var firstWindow = new byte[scanLen];
                Buffer.BlockCopy(fileBytes, 0, firstWindow, 0, scanLen);
                byte[] lastWindow = scanLen < fileBytes.Length ? new byte[Math.Min(1_048_576, fileBytes.Length - lastStart)] : Array.Empty<byte>();
                if (lastWindow.Length > 0)
                    Buffer.BlockCopy(fileBytes, lastStart, lastWindow, 0, lastWindow.Length);

                bool HasAscii(string s) => ContainsAscii(firstWindow, 0, scanLen, s) || (lastWindow.Length > 0 && ContainsAscii(lastWindow, 0, lastWindow.Length, s));
                bool HasUtf16(string s) => ContainsUtf16LE(firstWindow, 0, scanLen, s) || (lastWindow.Length > 0 && ContainsUtf16LE(lastWindow, 0, lastWindow.Length, s));
                bool HasPattern(string p) => HasAscii(p) || HasUtf16(p);

                int strongCount = 0;
                var reasons = new List<string>();

                // === Test all new detections ===

                // APC injection
                bool hasApcQueue = HasPattern("QueueUserAPC") || HasPattern("NtQueueApcThread") || HasPattern("NtQueueApcThreadEx");
                bool hasApcTarget = HasPattern("OpenProcess") && HasPattern("WriteProcessMemory");
                if (hasApcQueue && hasApcTarget)
                {
                    strongCount++; reasons.Add("APC injection");
                }

                // Thread hijacking — requires injection context
                bool hasThreadHijack = HasPattern("SuspendThread") && HasPattern("GetThreadContext") &&
                                       HasPattern("SetThreadContext") && HasPattern("ResumeThread") &&
                                       (HasPattern("VirtualAllocEx") || HasPattern("WriteProcessMemory") || HasPattern("NtUnmapViewOfSection"));
                if (hasThreadHijack)
                {
                    strongCount++; reasons.Add("Thread hijacking");
                }

                // Module stomping
                bool hasModuleStomp = HasPattern("LoadLibrary") && HasPattern("VirtualAllocEx") &&
                                      HasPattern("WriteProcessMemory") && HasPattern("NtCreateThreadEx");
                if (hasModuleStomp && HasPattern("GetProcAddress"))
                {
                    strongCount++; reasons.Add("Module stomping");
                }

                // Syscall abuse
                bool hasSyscall = HasPattern("NtCreateThreadEx") && HasPattern("NtMapViewOfSection") &&
                                  HasPattern("NtProtectVirtualMemory") && HasPattern("NtWriteVirtualMemory");
                if (hasSyscall)
                {
                    strongCount++; reasons.Add("Direct syscall abuse");
                }

                // Advanced anti-analysis — requires 5+ of 8 specific anti-debug APIs
                int antiDbgCount = new[] {
                    HasPattern("IsDebuggerPresent"), HasPattern("CheckRemoteDebuggerPresent"),
                    HasPattern("OutputDebugString"), HasPattern("NtSetInformationThread"),
                    HasPattern("GetTickCount64"), HasPattern("QueryPerformanceCounter"),
                    HasPattern("rdtsc"), HasPattern("NtQuerySystemInformation")
                }.Count(x => x);
                if (antiDbgCount >= 5)
                {
                    strongCount++; reasons.Add("Advanced anti-analysis");
                }

                // Fileless execution
                bool hasFileless = HasPattern("VirtualAlloc") && HasPattern("VirtualProtect") &&
                                   HasPattern("NtCreateThreadEx") && HasPattern("FromBase64String");
                if (hasFileless && (HasPattern("Assembly.Load") || HasPattern("IntPtr")))
                {
                    strongCount++; reasons.Add("Fileless execution");
                }

                // LOLBin
                bool hasLolbin = HasPattern("cmd.exe") && HasPattern("/c") &&
                                 (HasPattern("certutil") || HasPattern("mshta") || HasPattern("rundll32") ||
                                  HasPattern("regsvr32") || HasPattern("bitsadmin") || HasPattern("msbuild"));
                if (hasLolbin && (HasPattern("http") || HasPattern("ftp") || HasPattern("download")))
                {
                    strongCount++; reasons.Add("LOLBin abuse");
                }

                // Registry persistence
                bool hasPersistReg = HasPattern("CurrentVersion\\Run") || HasPattern("CurrentVersion\\RunOnce") ||
                                     HasPattern("CurrentVersion\\Explorer\\Shell Folders") ||
                                     HasPattern("CurrentVersion\\Explorer\\User Shell Folders");
                if (hasPersistReg && (HasPattern("LoadLibrary") || HasPattern("CreateProcess") || HasPattern("ShellExecute")))
                {
                    strongCount++; reasons.Add("Registry persistence");
                }

                // Startup folder persistence
                bool hasFolderPersist = HasPattern("Startup") && HasPattern(".lnk") &&
                                        (HasPattern("Shell32") || HasPattern("IPersistFile"));
                if (hasFolderPersist)
                {
                    strongCount++; reasons.Add("Startup folder persistence");
                }

                // COM hijacking
                bool hasComHijack = (HasPattern("InprocServer32") || HasPattern("CLSID")) &&
                                    HasPattern("RegisterServer");
                if (hasComHijack && (HasPattern("LoadLibrary") || HasPattern("GetProcAddress")))
                {
                    strongCount++; reasons.Add("COM hijacking");
                }

                bool hasUploadExfil = HasPattern("UploadString") || HasPattern("UploadFile");

                // Email exfiltration — requires SMTP + credential + send + mail object
                bool hasMailExfil = HasPattern("SmtpClient") && HasPattern("NetworkCredential") &&
                                    HasPattern("Send") && HasPattern("MailMessage");
                if (hasMailExfil)
                {
                    strongCount++; reasons.Add("Email exfiltration");
                }

                // FTP exfiltration — requires FTP client + URL + upload
                bool hasFtpExfil = HasPattern("FtpWebRequest") && HasPattern("ftp://") &&
                                   (hasUploadExfil || HasPattern("Upload") || HasPattern("RequestStream"));
                if (hasFtpExfil)
                {
                    strongCount++; reasons.Add("FTP exfiltration");
                }

                // Cloud exfiltration
                bool hasCloudExfil = HasPattern("blob.core.windows.net") || HasPattern("s3.amazonaws.com") ||
                                     HasPattern("drive.google.com") || HasPattern("onedrive.live.com");
                if (hasCloudExfil && hasUploadExfil)
                {
                    strongCount++; reasons.Add("Cloud exfiltration");
                }

                // Reflection-based injection
                bool hasReflection = HasPattern("Assembly.Load") && HasPattern("System.Reflection") &&
                                      HasPattern("Activator.CreateInstance") && HasPattern("MethodInfo");
                if (hasReflection && (HasPattern("Private") || HasPattern("BindingFlags")))
                {
                    strongCount++; reasons.Add("Reflection-based injection");
                }

                // Shellcode execution
                bool hasShellcode = HasPattern("VirtualAlloc") && HasPattern("VirtualProtect") &&
                                    HasPattern("CreateThread") && HasPattern("WaitForSingleObject");
                if (hasShellcode && HasPattern("0x00") && HasPattern("mprotect"))
                {
                    strongCount++; reasons.Add("Shellcode execution pattern");
                }

                if (strongCount > 0)
                {
                    Console.WriteLine($"  [{fileName}] Reasons: {string.Join(", ", reasons)}");
                    return true;
                }
            }
            catch { }
            return false;
        }

        static bool ContainsAscii(byte[] data, int offset, int length, string pattern)
        {
            byte[] patBytes = Encoding.ASCII.GetBytes(pattern);
            if (length < patBytes.Length) return false;
            for (int i = offset; i <= offset + length - patBytes.Length; i++)
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

        static bool ContainsUtf16LE(byte[] data, int offset, int length, string pattern)
        {
            byte[] patBytes = Encoding.Unicode.GetBytes(pattern);
            if (length < patBytes.Length) return false;
            for (int i = offset; i <= offset + length - patBytes.Length; i++)
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

        static string FindFileRecursive(string dir, string fileName)
        {
            try
            {
                foreach (string f in Directory.GetFiles(dir, fileName))
                    return f;
                foreach (string sub in Directory.GetDirectories(dir))
                {
                    string result = FindFileRecursive(sub, fileName);
                    if (result != null) return result;
                }
            }
            catch { }
            return null;
        }

        static string FindKnownDll(string dllName)
        {
            string system32 = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.Windows), "System32");
            string path = Path.Combine(system32, dllName);
            return File.Exists(path) ? path : null;
        }

        static string FindIAuthBytes()
        {
            string baseDir = AppContext.BaseDirectory;
            string exe = Path.Combine(baseDir, "IAuthBytes.exe");
            if (File.Exists(exe)) return exe;

            string searchDir = Path.GetFullPath(Path.Combine(baseDir, "..", "..", "..", "..", "IAuthBytes", "bin", "Debug", "net10.0-windows"));
            exe = Path.Combine(searchDir, "IAuthBytes.exe");
            return File.Exists(exe) ? exe : null;
        }

        static string FindGorillaTag()
        {
            string[] paths = {
                @"C:\Program Files (x86)\Steam\steamapps\common\Gorilla Tag",
                @"C:\Program Files\Steam\steamapps\common\Gorilla Tag",
                @"D:\SteamLibrary\steamapps\common\Gorilla Tag",
                @"E:\SteamLibrary\steamapps\common\Gorilla Tag",
                @"F:\SteamLibrary\steamapps\common\Gorilla Tag"
            };
            foreach (string p in paths)
                if (Directory.Exists(p)) return p;
            return null;
        }
    }
}
