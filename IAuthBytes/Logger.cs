using System;
using System.IO;
using System.Reflection;

namespace IAuthBytes
{
    public static class Logger
    {
        private static readonly string AppDir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location)
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IAuthBytes");

        private static readonly string LogDir = Path.Combine(AppDir, "Logs");
        private static readonly string CrashDir = Path.Combine(AppDir, "Crashes");

        private static readonly string LogFile = Path.Combine(LogDir, $"log_{DateTime.Now:yyyy-MM-dd}.log");
        private static readonly string CrashFile = Path.Combine(CrashDir, $"crash_{DateTime.Now:yyyy-MM-dd_HHmmss}.log");

        private static readonly object _lock = new();

        static Logger()
        {
            try { Directory.CreateDirectory(LogDir); } catch { }
            try { Directory.CreateDirectory(CrashDir); } catch { }
        }

        public static void Log(string message)
        {
            try
            {
                lock (_lock)
                {
                    string line = $"[{DateTime.Now:yyyy-MM-dd HH:mm:ss}] {message}{Environment.NewLine}";
                    File.AppendAllText(LogFile, line);
                }
            }
            catch { }
        }

        public static void LogException(string context, Exception ex)
        {
            Log($"[ERROR] {context}: {ex.GetType().Name} - {ex.Message}");
            Log($"  StackTrace: {ex.StackTrace}");
            if (ex.InnerException != null)
                Log($"  Inner: {ex.InnerException.GetType().Name} - {ex.InnerException.Message}");
        }

        public static void LogCrash(string context, Exception ex)
        {
            try
            {
                string crashLog = Path.Combine(CrashDir, $"crash_{DateTime.Now:yyyy-MM-dd_HHmmss}.log");
                var sb = new System.Text.StringBuilder();
                sb.AppendLine("========== IAuthBytes CRASH REPORT ==========");
                sb.AppendLine($"Time: {DateTime.Now:yyyy-MM-dd HH:mm:ss.fff}");
                sb.AppendLine($"OS: {Environment.OSVersion}");
                sb.AppendLine($"CLR: {Environment.Version}");
                sb.AppendLine($"64-bit: {Environment.Is64BitProcess}");
                sb.AppendLine($"Context: {context}");
                sb.AppendLine();
                sb.AppendLine($"Exception: {ex.GetType().Name}");
                sb.AppendLine($"Message: {ex.Message}");
                sb.AppendLine();
                sb.AppendLine($"StackTrace:{Environment.NewLine}{ex.StackTrace}");
                if (ex.InnerException != null)
                {
                    sb.AppendLine();
                    sb.AppendLine($"Inner Exception: {ex.InnerException.GetType().Name}");
                    sb.AppendLine($"Inner Message: {ex.InnerException.Message}");
                    sb.AppendLine($"Inner StackTrace:{Environment.NewLine}{ex.InnerException.StackTrace}");
                }
                sb.AppendLine("==============================================");

                File.WriteAllText(crashLog, sb.ToString());
            }
            catch { }

            LogException(context, ex);
        }
    }
}
