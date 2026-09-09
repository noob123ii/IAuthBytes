using System;
using System.IO;
using System.Runtime.InteropServices;

namespace HookDll
{
    public static class HookDllEntry
    {
        private static IntPtr _originalBytesPtr = IntPtr.Zero;
        private static int _patchSize = 5;
        private static bool _patched = false;

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetModuleHandle(string? lpModuleName);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetProcAddress(IntPtr hModule, string lpProcName);

        [DllImport("kernel32.dll")]
        private static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, uint flNewProtect, out uint lpflOldProtect);

        [DllImport("kernel32.dll")]
        private static extern bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int dwSize, out int lpNumberOfBytesRead);

        [DllImport("kernel32.dll")]
        private static extern bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, int nSize, out int lpNumberOfBytesWritten);

        [DllImport("kernel32.dll")]
        private static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll")]
        private static extern bool FlushInstructionCache(IntPtr hProcess, IntPtr lpBaseAddress, uint dwSize);

        private const uint PAGE_EXECUTE_READWRITE = 0x40;

        public static void Initialize()
        {
            try
            {
                string logDir = Path.Combine(AppContext.BaseDirectory, "Logs");
                Directory.CreateDirectory(logDir);
                string logFile = Path.Combine(logDir, $"hook_test_{DateTime.Now:yyyyMMdd_HHmmss}.log");

                File.WriteAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] HookDll loaded into IAuthBytes process\n");

                IntPtr ntdll = GetModuleHandle("ntdll.dll");
                if (ntdll == IntPtr.Zero)
                {
                    File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] FAILED: ntdll.dll not found\n");
                    return;
                }

                File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] ntdll.dll base: 0x{ntdll.ToInt64():X}\n");

                IntPtr ntCreateFile = GetProcAddress(ntdll, "NtCreateFile");
                if (ntCreateFile == IntPtr.Zero)
                {
                    File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] FAILED: NtCreateFile not found\n");
                    return;
                }

                File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] NtCreateFile address: 0x{ntCreateFile.ToInt64():X}\n");

                byte[] originalBytes = new byte[16];
                ReadProcessMemory(GetCurrentProcess(), ntCreateFile, originalBytes, originalBytes.Length, out _);

                File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] Original bytes: {BitConverter.ToString(originalBytes)}\n");

                _originalBytesPtr = Marshal.AllocHGlobal(16);
                Marshal.Copy(originalBytes, 0, _originalBytesPtr, 16);

                if (!VirtualProtect(ntCreateFile, (uint)_patchSize, PAGE_EXECUTE_READWRITE, out uint oldProtect))
                {
                    File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] FAILED: VirtualProtect error {Marshal.GetLastWin32Error()}\n");
                    return;
                }

                File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] VirtualProtect OK, old protect: 0x{oldProtect:X}\n");

                byte[] jmpHook = new byte[5];
                jmpHook[0] = 0xE9;

                long relativeAddr = ntCreateFile.ToInt64() + 5;
                long targetAddr = ntCreateFile.ToInt64() + 0x100;
                long offset = targetAddr - relativeAddr;
                byte[] offsetBytes = BitConverter.GetBytes((int)offset);
                Array.Copy(offsetBytes, 0, jmpHook, 1, 4);

                bool success = WriteProcessMemory(GetCurrentProcess(), ntCreateFile, jmpHook, jmpHook.Length, out int written);
                FlushInstructionCache(GetCurrentProcess(), ntCreateFile, (uint)_patchSize);

                _patched = success && written == 5;

                File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] JMP hook written: success={success}, bytes={written}\n");

                byte[] verifyBytes = new byte[16];
                ReadProcessMemory(GetCurrentProcess(), ntCreateFile, verifyBytes, verifyBytes.Length, out _);
                File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] Verify bytes: {BitConverter.ToString(verifyBytes)}\n");

                File.AppendAllText(logFile, $"[{DateTime.Now:HH:mm:ss}] HOOK ACTIVE — IAuthBytes anti-hook should detect this!\n");
            }
            catch (Exception ex)
            {
                try
                {
                    string logDir2 = Path.Combine(AppContext.BaseDirectory, "Logs");
                    Directory.CreateDirectory(logDir2);
                    File.AppendAllText(Path.Combine(logDir2, "hook_error.log"),
                        $"[{DateTime.Now:HH:mm:ss}] Exception: {ex}\n");
                }
                catch { }
            }
        }

        public static void Shutdown()
        {
            if (_patched && _originalBytesPtr != IntPtr.Zero)
            {
                try
                {
                    IntPtr ntdll = GetModuleHandle("ntdll.dll");
                    IntPtr ntCreateFile = GetProcAddress(ntdll, "NtCreateFile");
                    if (ntCreateFile != IntPtr.Zero)
                    {
                        VirtualProtect(ntCreateFile, (uint)_patchSize, PAGE_EXECUTE_READWRITE, out _);

                        byte[] originalBytes = new byte[_patchSize];
                        Marshal.Copy(_originalBytesPtr, originalBytes, 0, _patchSize);

                        WriteProcessMemory(GetCurrentProcess(), ntCreateFile, originalBytes, originalBytes.Length, out _);
                        FlushInstructionCache(GetCurrentProcess(), ntCreateFile, (uint)_patchSize);
                    }
                    Marshal.FreeHGlobal(_originalBytesPtr);
                }
                catch { }
            }
        }
    }
}
