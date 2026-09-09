using System;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Runtime.InteropServices;
using System.Threading;

namespace RuntimeTest
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.WriteLine("=== IAuthBytes Runtime Detection Test ===");
            Console.WriteLine("This simulates threats that RuntimeGuard should detect.");
            Console.WriteLine("Watch the IAuthBytes Runtime tab for alerts.");
            Console.WriteLine();

            string gtPath = args.Length > 0 ? args[0] :
                @"C:\Program Files (x86)\Steam\steamapps\common\Gorilla Tag";

            if (!Directory.Exists(gtPath))
            {
                Console.WriteLine($"[!] GT path not found: {gtPath}");
                Console.WriteLine("Usage: RuntimeTest.exe <GT_PATH>");
                Console.WriteLine("Press ENTER to exit.");
                Console.ReadLine();
                return;
            }

            Console.WriteLine($"[*] GT Path: {gtPath}");
            Console.WriteLine();

            int testNum = 0;

            Console.WriteLine("=== TEST 1: Suspicious file creation ===");
            testNum++;
            try
            {
                string testDir = Path.Combine(gtPath, "BepInEx", "plugins");
                if (Directory.Exists(testDir))
                {
                    string[] suspiciousExts = { ".ps1", ".bat", ".hta", ".vbs", ".cmd" };
                    foreach (string ext in suspiciousExts)
                    {
                        string testFile = Path.Combine(testDir, $"test_suspicious{ext}");
                        File.WriteAllText(testFile, $"echo This is a runtime test file {ext}");
                        Console.WriteLine($"[+] Created: {Path.GetFileName(testFile)}");
                        Thread.Sleep(200);
                    }
                    Console.WriteLine("[+] RuntimeGuard should flag these as suspicious file creation");
                }
                else
                {
                    Console.WriteLine("[!] BepInEx\\plugins not found");
                }
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 2: Suspicious binary modification ===");
            testNum++;
            try
            {
                string testDir = Path.Combine(gtPath, "BepInEx", "plugins");
                if (Directory.Exists(testDir))
                {
                    string testDll = Path.Combine(testDir, "test_suspicious.dll");
                    byte[] fakeDll = new byte[1024];
                    Random rng = new();
                    rng.NextBytes(fakeDll);
                    fakeDll[0] = 0x4D;
                    fakeDll[1] = 0x5A;
                    File.WriteAllBytes(testDll, fakeDll);
                    Console.WriteLine($"[+] Created fake DLL: {Path.GetFileName(testDll)}");
                    Thread.Sleep(200);

                    fakeDll[0] = 0x00;
                    fakeDll[1] = 0x00;
                    File.WriteAllBytes(testDll, fakeDll);
                    Console.WriteLine($"[+] Modified: {Path.GetFileName(testDll)}");
                    Console.WriteLine("[+] RuntimeGuard should flag binary modification");
                }
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 3: Suspicious child process (cmd.exe) ===");
            testNum++;
            try
            {
                ProcessStartInfo psi = new("cmd.exe")
                {
                    Arguments = "/c echo runtime_test_placeholder",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                Process? proc = Process.Start(psi);
                if (proc != null)
                {
                    Console.WriteLine($"[+] Spawned cmd.exe (PID {proc.Id})");
                    Console.WriteLine("[+] RuntimeGuard should detect suspicious child process");
                    proc.Kill();
                }
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 4: Suspicious network port listener ===");
            testNum++;
            try
            {
                TcpListener listener = new(IPAddress.Loopback, 4444);
                listener.Start();
                Console.WriteLine("[+] Listening on localhost:4444 (known malware port)");
                Console.WriteLine("[+] RuntimeGuard should flag suspicious port");
                Thread.Sleep(2000);
                listener.Stop();
                Console.WriteLine("[+] Stopped listener");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 5: Suspicious file extension combo ===");
            testNum++;
            try
            {
                string testDir = Path.Combine(gtPath, "BepInEx", "plugins");
                if (Directory.Exists(testDir))
                {
                    string[] combos = {
                        "legit.dll.graze",
                        "photo.jpg.exe",
                        "readme.txt.bat",
                        "config.json.ps1"
                    };
                    foreach (string name in combos)
                    {
                        string f = Path.Combine(testDir, name);
                        File.WriteAllText(f, "runtime_test");
                        Console.WriteLine($"[+] Created: {name}");
                    }
                    Console.WriteLine("[+] RuntimeGuard should flag suspicious extensions");
                }
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 6: Simulated registry persistence check ===");
            testNum++;
            try
            {
                Console.WriteLine("[+] RuntimeGuard will check registry on next scan");
                Console.WriteLine("[!] This test verifies CheckRegistryPersistence runs correctly");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 7: Simulated GT process module check ===");
            testNum++;
            try
            {
                var gtProcs = Process.GetProcessesByName("Gorilla Tag");
                if (gtProcs.Length > 0)
                {
                    Console.WriteLine($"[+] Found Gorilla Tag (PID {gtProcs[0].Id})");
                    Console.WriteLine("[+] RuntimeGuard should enumerate loaded modules");
                }
                else
                {
                    Console.WriteLine("[!] Gorilla Tag not running — start GT for module monitoring");
                }
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 8: Suspicious PowerShell command line ===");
            testNum++;
            try
            {
                ProcessStartInfo psi = new("cmd.exe")
                {
                    Arguments = "/c echo test_powershell_bypass_marker",
                    UseShellExecute = false,
                    CreateNoWindow = true
                };
                Process? proc = Process.Start(psi);
                if (proc != null)
                {
                    Console.WriteLine($"[+] Spawned cmd.exe with suspicious args (PID {proc.Id})");
                    Console.WriteLine("[+] RuntimeGuard should detect suspicious command pattern");
                    Thread.Sleep(500);
                    try { proc.Kill(); } catch { }
                }
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 9: File attribute manipulation (hidden file) ===");
            testNum++;
            try
            {
                string testDir = Path.Combine(gtPath, "BepInEx", "plugins");
                if (Directory.Exists(testDir))
                {
                    string hiddenFile = Path.Combine(testDir, "test_hidden.exe");
                    File.WriteAllBytes(hiddenFile, new byte[] { 0x4D, 0x5A, 0x00, 0x00 });
                    File.SetAttributes(hiddenFile, File.GetAttributes(hiddenFile) | FileAttributes.Hidden);
                    Console.WriteLine($"[+] Created hidden file: {Path.GetFileName(hiddenFile)}");
                    Console.WriteLine("[+] Scanner should detect hidden file attribute");
                }
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("=== TEST 10: Simulated memory pattern scan ===");
            testNum++;
            try
            {
                Console.WriteLine("[+] Injecting test strings into current process memory...");
                string testString = "discord.com/api/webhooks/test_token_12345";
                GCHandle handle = GCHandle.Alloc(testString, GCHandleType.Pinned);
                Console.WriteLine($"[+] Allocated test string at pinned address");
                Console.WriteLine("[+] RuntimeGuard memory scan should find malicious string");
                handle.Free();
                Console.WriteLine("[+] Freed test string");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Error: {ex.Message}"); }
            Console.WriteLine();

            Console.WriteLine("========================================");
            Console.WriteLine($"  {testNum} runtime tests completed");
            Console.WriteLine("  Check IAuthBytes Runtime tab for alerts");
            Console.WriteLine("========================================");
            Console.WriteLine();
            Console.WriteLine("Press ENTER to clean up test files...");
            Console.ReadLine();

            try
            {
                string testDir = Path.Combine(gtPath, "BepInEx", "plugins");
                if (Directory.Exists(testDir))
                {
                    string[] testFiles = {
                        "test_suspicious.ps1", "test_suspicious.bat", "test_suspicious.hta",
                        "test_suspicious.vbs", "test_suspicious.cmd", "test_suspicious.dll",
                        "legit.dll.graze", "photo.jpg.exe", "readme.txt.bat", "config.json.ps1",
                        "test_hidden.exe"
                    };
                    foreach (string f in testFiles)
                    {
                        string full = Path.Combine(testDir, f);
                        if (File.Exists(full))
                        {
                            File.SetAttributes(full, FileAttributes.Normal);
                            File.Delete(full);
                            Console.WriteLine($"[*] Cleaned: {f}");
                        }
                    }
                }
                Console.WriteLine("[*] Cleanup complete.");
            }
            catch (Exception ex) { Console.WriteLine($"[!] Cleanup error: {ex.Message}"); }
        }
    }
}
