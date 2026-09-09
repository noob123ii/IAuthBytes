using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.InteropServices;
using System.Text;

namespace Injector
{
    class Program
    {
        [DllImport("kernel32.dll")]
        static extern IntPtr OpenProcess(int dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll")]
        static extern bool VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);

        [DllImport("kernel32.dll")]
        static extern bool CloseHandle(IntPtr hObject);

        [DllImport("psapi.dll")]
        static extern bool EnumProcessModules(IntPtr hProcess, [Out] IntPtr[] lphModule, int cb, out int lpcbNeeded);

        [DllImport("psapi.dll")]
        static extern int GetModuleFileNameEx(IntPtr hProcess, IntPtr hModule, [Out] StringBuilder lpBaseName, int nSize);

        [DllImport("kernel32.dll")]
        static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        const int PROCESS_ALL_ACCESS = 0x1F0FFF;
        const uint PAGE_EXECUTE_READWRITE = 0x40;

        static StreamWriter? _log;

        static void Log(string msg)
        {
            string line = $"[{DateTime.Now:HH:mm:ss}] {msg}";
            Console.WriteLine(msg);
            _log?.WriteLine(line);
            _log?.Flush();
        }

        static IntPtr FindRemoteModuleBase(IntPtr hProcess, string moduleName)
        {
            IntPtr[] modules = new IntPtr[1024];
            if (!EnumProcessModules(hProcess, modules, modules.Length * IntPtr.Size, out int needed))
                return IntPtr.Zero;

            int count = needed / IntPtr.Size;
            StringBuilder nameBuf = new StringBuilder(1024);

            for (int i = 0; i < count; i++)
            {
                if (GetModuleFileNameEx(hProcess, modules[i], nameBuf, nameBuf.Capacity) > 0)
                {
                    string name = Path.GetFileName(nameBuf.ToString());
                    if (string.Equals(name, moduleName, StringComparison.OrdinalIgnoreCase))
                        return modules[i];
                }
            }
            return IntPtr.Zero;
        }

        static int Main(string[] args)
        {
            string logPath = Path.Combine(AppContext.BaseDirectory, "injector_log.txt");
            _log = new StreamWriter(logPath);

            try
            {
                Log("=== IAuthBytes Hook Injection Test ===");

                if (args.Length < 1)
                {
                    Log("Usage: Injector.exe <PID>     — patch existing process");
                    Log("       Injector.exe <path>    — launch and patch");
                    return 1;
                }

                int pid;
                if (!int.TryParse(args[0], out pid))
                {
                    string path = Path.GetFullPath(args[0]);
                    if (!File.Exists(path)) { Log($"[!] Not found: {path}"); return 1; }
                    Log($"[*] Launching: {path}");
                    var p = Process.Start(new ProcessStartInfo(path) { UseShellExecute = false, CreateNoWindow = true });
                    if (p == null) { Log("[!] Failed"); return 1; }
                    pid = p.Id;
                    Log($"[*] PID: {pid}, waiting 3s...");
                    System.Threading.Thread.Sleep(3000);
                }
                else
                {
                    Log($"[*] Attaching to PID: {pid}");
                }

                IntPtr hProcess = OpenProcess(PROCESS_ALL_ACCESS, false, pid);
                if (hProcess == IntPtr.Zero) { Log($"[!] OpenProcess failed: {Marshal.GetLastWin32Error()}"); return 1; }
                Log("[*] Got handle");

                // Find ntdll base in remote process
                IntPtr remoteNtdll = FindRemoteModuleBase(hProcess, "ntdll.dll");
                if (remoteNtdll == IntPtr.Zero) { Log("[!] Could not find ntdll.dll in remote process"); CloseHandle(hProcess); return 1; }
                Log($"[*] Remote ntdll.dll base: 0x{remoteNtdll.ToInt64():X}");

                // Get NtCreateFile offset from local ntdll
                IntPtr localNtdll = GetProcAddress(IntPtr.Zero, "ntdll.dll");
                if (localNtdll == IntPtr.Zero)
                {
                    // Fallback: load it ourselves
                    IntPtr hNtdll = LoadLibrary("ntdll.dll");
                    localNtdll = hNtdll;
                }

                // Use GetProcAddress on a loaded copy to get the RVA
                // Actually, GetProcAddress(hModule, name) needs a module handle, not IntPtr.Zero
                // We need to get the offset. Let's use a different approach:
                // Read local ntdll base + NtCreateFile offset
                IntPtr hLocalNtdll = LoadLibrary("ntdll.dll");
                IntPtr localNtCreateFile = GetProcAddress(hLocalNtdll, "NtCreateFile");
                long localOffset = localNtCreateFile.ToInt64() - hLocalNtdll.ToInt64();
                Log($"[*] Local ntdll: 0x{hLocalNtdll.ToInt64():X}, NtCreateFile: 0x{localNtCreateFile.ToInt64():X}");
                Log($"[*] NtCreateFile RVA: 0x{localOffset:X}");

                long remoteNtCreateFile = remoteNtdll.ToInt64() + localOffset;
                Log($"[*] Remote NtCreateFile: 0x{remoteNtCreateFile:X}");

                byte[] originalBytes = new byte[16];
                ReadProcessMemory(hProcess, (IntPtr)remoteNtCreateFile, originalBytes, originalBytes.Length, out int bytesRead);
                Log($"[*] Remote bytes ({bytesRead} read): {BitConverter.ToString(originalBytes)}");

                bool isHooked = originalBytes[0] == 0xE9 || originalBytes[0] == 0xE8 ||
                               (originalBytes[0] == 0xFF && originalBytes[1] == 0x25) ||
                               originalBytes[0] == 0xEB || originalBytes[0] == 0xEA ||
                               (originalBytes[0] == 0x68 && originalBytes[5] == 0xC3);

                if (isHooked) Log("[!] Already hooked!");

                // Save original 5 bytes for restore
                byte[] saveBytes = new byte[5];
                Array.Copy(originalBytes, saveBytes, 5);

                byte[] jmpHook = new byte[5];
                jmpHook[0] = 0xE9;
                long offset = (remoteNtCreateFile + 0x1000) - (remoteNtCreateFile + 5);
                byte[] offsetBytes = BitConverter.GetBytes((int)offset);
                Array.Copy(offsetBytes, 0, jmpHook, 1, 4);

                Log($"[*] Patch: {BitConverter.ToString(jmpHook)}");

                if (!VirtualProtectEx(hProcess, (IntPtr)remoteNtCreateFile, 5, PAGE_EXECUTE_READWRITE, out uint oldProt))
                {
                    Log($"[!] VirtualProtectEx failed: {Marshal.GetLastWin32Error()}");
                    CloseHandle(hProcess);
                    return 1;
                }
                Log($"[*] VirtualProtectEx OK (old: 0x{oldProt:X})");

                if (!WriteProcessMemory(hProcess, (IntPtr)remoteNtCreateFile, jmpHook, 5, out int written))
                {
                    Log($"[!] WriteProcessMemory failed: {Marshal.GetLastWin32Error()}");
                    VirtualProtectEx(hProcess, (IntPtr)remoteNtCreateFile, 5, oldProt, out _);
                    CloseHandle(hProcess);
                    return 1;
                }
                Log($"[*] Wrote {written} bytes");
                FlushInstructionCache(hProcess, (IntPtr)remoteNtCreateFile, 5);

                byte[] verify = new byte[16];
                ReadProcessMemory(hProcess, (IntPtr)remoteNtCreateFile, verify, verify.Length, out _);
                Log($"[*] Verify: {BitConverter.ToString(verify)}");
                Log("");
                Log("=============================================");
                Log("  HOOK ACTIVE on NtCreateFile (0xE9 JMP)    ");
                Log("  Go click SCAN in IAuthBytes now!           ");
                Log("  Hook stays for 30 seconds.                ");
                Log("=============================================");
                Log("");
                Log("[*] Waiting 30 seconds...");
                System.Threading.Thread.Sleep(30000);

                Log("[*] Restoring...");
                VirtualProtectEx(hProcess, (IntPtr)remoteNtCreateFile, 5, PAGE_EXECUTE_READWRITE, out _);
                WriteProcessMemory(hProcess, (IntPtr)remoteNtCreateFile, saveBytes, 5, out _);
                FlushInstructionCache(hProcess, (IntPtr)remoteNtCreateFile, 5);

                byte[] finalBytes = new byte[16];
                ReadProcessMemory(hProcess, (IntPtr)remoteNtCreateFile, finalBytes, finalBytes.Length, out _);
                Log($"[*] Restored: {BitConverter.ToString(finalBytes)}");

                VirtualProtectEx(hProcess, (IntPtr)remoteNtCreateFile, 5, oldProt, out _);
                CloseHandle(hProcess);
                Log("[*] Done.");
                return 0;
            }
            catch (Exception ex)
            {
                Log($"[!] Exception: {ex}");
                return 1;
            }
            finally
            {
                _log?.Dispose();
            }
        }

        [DllImport("kernel32.dll")]
        static extern IntPtr LoadLibrary(string lpFileName);
    }
}
