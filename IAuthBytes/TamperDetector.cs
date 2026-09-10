using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using System.Threading;

namespace IAuthBytes
{
    internal class TamperBaseline
    {
        public string BuildId { get; set; } = "";
        public string Version { get; set; } = "";
        public DateTime CapturedAt { get; set; }
        public Dictionary<string, FileBaseline> Files { get; set; } = new(StringComparer.OrdinalIgnoreCase);
    }

    internal class FileBaseline
    {
        public long Size { get; set; }
        public string Hash { get; set; } = "";
        public DateTime CapturedAt { get; set; }
    }

    internal static class TamperDetector
    {
        private static readonly string AppDataDir = Path.Combine(
            Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "IAuthBytes");
        private static readonly string BaselineFile = Path.Combine(AppDataDir, "tamper_baseline.json");

        private static FileSystemWatcher? _selfWatcher;
        private static Timer? _selfIntegrityTimer;
        private static byte[]? _selfExeHash;
        private static long _selfExeSize;
        private static readonly object _tamperLock = new();

        private static readonly HashSet<string> CriticalFiles = new(StringComparer.OrdinalIgnoreCase)
        {
            "Gorilla Tag.exe",
            "UnityPlayer.dll",
            "mono-2.0-bdwgc.dll",
            "mono-2.0.dll",
            "winhttp.dll",
            "version.dll",
            "dsound.dll",
            "dinput8.dll",
            "d3d9.dll",
            "opengl32.dll",
            "steam_api64.dll",
            "ogg.dll",
            "vorbis.dll",
            "vorbisfile.dll"
        };

        public static string? FindSteamManifest(string gtPath)
        {
            string? steamDir = FindSteamDir();
            if (steamDir == null) return null;

            string manifest = Path.Combine(steamDir, "steamapps", "appmanifest_1533390.acf");
            if (File.Exists(manifest)) return manifest;

            string[] driveRoots = { @"C:\", @"D:\", @"E:\", @"F:\" };
            foreach (string drive in driveRoots)
            {
                string libPath = Path.Combine(drive, "SteamLibrary", "steamapps", "appmanifest_1533390.acf");
                if (File.Exists(libPath)) return libPath;
            }

            return null;
        }

        private static string? FindSteamDir()
        {
            string defaultPath = @"C:\Program Files (x86)\Steam";
            if (Directory.Exists(defaultPath)) return defaultPath;

            string altPath = @"C:\Program Files\Steam";
            if (Directory.Exists(altPath)) return altPath;

            try
            {
                using var key = Microsoft.Win32.Registry.CurrentUser.OpenSubKey(@"Software\Valve\Steam");
                if (key?.GetValue("SteamPath") is string steamPath)
                {
                    string normalized = steamPath.Replace('/', '\\');
                    if (Directory.Exists(normalized)) return normalized;
                }
            }
            catch { }

            return null;
        }

        public static (string buildId, string version) ParseSteamManifest(string manifestPath)
        {
            string buildId = "";
            string version = "";
            try
            {
                string[] lines = File.ReadAllLines(manifestPath);
                for (int i = 0; i < lines.Length; i++)
                {
                    string line = lines[i].Trim();
                    if (line.StartsWith("\"BuildId\""))
                        buildId = ExtractValue(line);
                    else if (line.StartsWith("\"VersionConfigOsArch\""))
                        version = ExtractValue(line);
                    else if (line.StartsWith("\"LastUpdated\""))
                        version = ExtractValue(line);
                }
            }
            catch { }
            return (buildId, version);
        }

        private static string ExtractValue(string line)
        {
            int first = line.IndexOf('"');
            int second = line.IndexOf('"', first + 1);
            int third = line.IndexOf('"', second + 1);
            int fourth = line.IndexOf('"', third + 1);
            if (third >= 0 && fourth >= 0)
                return line.Substring(third + 1, fourth - third - 1);
            return "";
        }

        public static TamperBaseline? LoadBaseline()
        {
            try
            {
                if (!File.Exists(BaselineFile)) return null;
                string json = File.ReadAllText(BaselineFile);
                return JsonSerializer.Deserialize<TamperBaseline>(json);
            }
            catch { return null; }
        }

        public static void SaveBaseline(TamperBaseline baseline)
        {
            try
            {
                Directory.CreateDirectory(AppDataDir);
                string json = JsonSerializer.Serialize(baseline, new JsonSerializerOptions
                {
                    WriteIndented = true,
                    PropertyNamingPolicy = JsonNamingPolicy.CamelCase
                });
                File.WriteAllText(BaselineFile, json);
            }
            catch { }
        }

        public static string ComputeQuickHash(byte[] data)
        {
            int len = Math.Min(data.Length, 65536);
            using var sha = SHA256.Create();
            byte[] sample = new byte[len];
            Buffer.BlockCopy(data, 0, sample, 0, len);
            byte[] hash = sha.ComputeHash(sample);
            return Convert.ToHexString(hash).Substring(0, 16);
        }

        public static List<ThreatInfo> RunTamperCheck(string gtPath, string buildId, string version)
        {
            var threats = new List<ThreatInfo>();
            var baseline = LoadBaseline();

            if (baseline == null || baseline.BuildId != buildId)
            {
                if (baseline != null && baseline.BuildId != buildId)
                {
                    Logger.Log($"GT update detected: build {baseline.BuildId} -> {buildId}. Updating tamper baseline.");
                }

                var newBaseline = new TamperBaseline
                {
                    BuildId = buildId,
                    Version = version,
                    CapturedAt = DateTime.Now
                };

                foreach (string fileName in CriticalFiles)
                {
                    string filePath = Path.Combine(gtPath, fileName);
                    if (!File.Exists(filePath)) continue;
                    try
                    {
                        byte[] bytes = File.ReadAllBytes(filePath);
                        newBaseline.Files[fileName] = new FileBaseline
                        {
                            Size = bytes.Length,
                            Hash = ComputeQuickHash(bytes),
                            CapturedAt = DateTime.Now
                        };
                    }
                    catch { }
                }

                SaveBaseline(newBaseline);
                Logger.Log($"Tamper baseline captured: {newBaseline.Files.Count} files, build {buildId}");
                return threats;
            }

            foreach (var kvp in baseline.Files)
            {
                string filePath = Path.Combine(gtPath, kvp.Key);
                if (!File.Exists(filePath))
                {
                    threats.Add(new ThreatInfo
                    {
                        FileName = kvp.Key,
                        FilePath = filePath,
                        ThreatType = "Tamper",
                        FileSize = "",
                        Severity = Severity.High,
                        Description = $"Critical file missing: {kvp.Key}"
                    });
                    continue;
                }

                try
                {
                    byte[] bytes = File.ReadAllBytes(filePath);
                    long currentSize = bytes.Length;
                    string currentHash = ComputeQuickHash(bytes);
                    var expected = kvp.Value;

                    if (currentSize != expected.Size)
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = kvp.Key,
                            FilePath = filePath,
                            ThreatType = "Tamper",
                            FileSize = FormatSize(currentSize),
                            Severity = Severity.Critical,
                            Description = $"Size mismatch: {FormatSize(currentSize)} (expected {FormatSize(expected.Size)}) — file may be tampered"
                        });
                    }
                    else if (currentHash != expected.Hash)
                    {
                        threats.Add(new ThreatInfo
                        {
                            FileName = kvp.Key,
                            FilePath = filePath,
                            ThreatType = "Tamper",
                            FileSize = FormatSize(currentSize),
                            Severity = Severity.Critical,
                            Description = $"Hash mismatch — file content modified since last verified build"
                        });
                    }
                }
                catch { }
            }

            return threats;
        }

        private static string FormatSize(long bytes)
        {
            if (bytes < 1024) return $"{bytes} B";
            if (bytes < 1024 * 1024) return $"{bytes / 1024.0:F1} KB";
            return $"{bytes / (1024.0 * 1024.0):F1} MB";
        }

        public static void StartSelfProtection()
        {
            try
            {
                string? exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) return;

                _selfExeSize = new FileInfo(exePath).Length;
                byte[] exeBytes = File.ReadAllBytes(exePath);
                using var sha = SHA256.Create();
                _selfExeHash = sha.ComputeHash(exeBytes);

                string? dir = Path.GetDirectoryName(exePath);
                if (string.IsNullOrEmpty(dir) || !Directory.Exists(dir)) return;

                _selfWatcher = new FileSystemWatcher(dir)
                {
                    Filter = "*.*",
                    NotifyFilter = NotifyFilters.LastWrite | NotifyFilters.Size | NotifyFilters.FileName,
                    IncludeSubdirectories = false,
                    EnableRaisingEvents = false
                };

                _selfWatcher.Created += (s, e) =>
                {
                    string ext = Path.GetExtension(e.Name ?? "").ToLowerInvariant();
                    if (ext is ".dll" or ".exe")
                    {
                        Logger.Log($"TAMPER: Suspicious file created in install dir: {e.Name}");
                        OnTamperDetected($"New executable created: {e.Name}");
                    }
                };

                _selfWatcher.Changed += (s, e) =>
                {
                    string name = Path.GetFileName(e.FullPath ?? "").ToLowerInvariant();
                    if (name == "iauthbytes.exe")
                    {
                        Logger.Log($"TAMPER: IAuthBytes.exe modified on disk!");
                        OnTamperDetected("IAuthBytes executable modified on disk");
                    }
                    else if (name == "index.html")
                    {
                        Logger.Log($"TAMPER: index.html modified on disk!");
                        OnTamperDetected("UI source modified on disk");
                    }
                    else if (name is "tamper_baseline.json" or "self_hash.txt")
                    {
                        Logger.Log($"TAMPER: Security file modified: {name}");
                        OnTamperDetected($"Security file modified: {name}");
                    }
                };

                _selfWatcher.EnableRaisingEvents = true;

                _selfIntegrityTimer = new Timer(_ =>
                {
                    try
                    {
                        VerifySelfExeIntegrity();
                    }
                    catch { }
                }, null, TimeSpan.FromSeconds(10), TimeSpan.FromSeconds(30));

                Logger.Log("TamperDetector: Self-protection started");
            }
            catch (Exception ex)
            {
                Logger.LogException("TamperDetector-StartSelfProtection", ex);
            }
        }

        public static void StopSelfProtection()
        {
            _selfWatcher?.Dispose();
            _selfWatcher = null;
            _selfIntegrityTimer?.Dispose();
            _selfIntegrityTimer = null;
        }

        private static void VerifySelfExeIntegrity()
        {
            try
            {
                string? exePath = System.Diagnostics.Process.GetCurrentProcess().MainModule?.FileName;
                if (string.IsNullOrEmpty(exePath) || !File.Exists(exePath)) return;

                long currentSize = new FileInfo(exePath).Length;
                if (currentSize != _selfExeSize)
                {
                    Logger.Log($"TAMPER: IAuthBytes.exe size changed: {_selfExeSize} -> {currentSize}");
                    OnTamperDetected($"Executable size changed: {currentSize} bytes (was {_selfExeSize})");
                    return;
                }

                byte[] currentBytes = File.ReadAllBytes(exePath);
                using var sha = SHA256.Create();
                byte[] currentHash = sha.ComputeHash(currentBytes);

                if (_selfExeHash != null && !currentHash.SequenceEqual(_selfExeHash))
                {
                    Logger.Log("TAMPER: IAuthBytes.exe hash changed!");
                    OnTamperDetected("Executable content hash mismatch — binary modified");
                }
            }
            catch { }
        }

        private static void OnTamperDetected(string description)
        {
            try
            {
                Logger.Log($"TAMPER ALERT: {description}");
            }
            catch { }
        }
    }
}
