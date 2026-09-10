using System;
using System.Diagnostics;
using System.IO;
using System.Net.Http;
using System.Security.Cryptography;
using System.Text.Json;
using System.Threading.Tasks;

namespace IAuthBytes
{
    internal class UpdateInfo
    {
        public bool UpdateAvailable { get; set; }
        public string CurrentVersion { get; set; } = "";
        public string LatestVersion { get; set; } = "";
        public string DownloadUrl { get; set; } = "";
        public string ReleaseNotes { get; set; } = "";
        public string Error { get; set; } = "";
    }

    internal static class UpdateChecker
    {
        private const string UpdateUrl = "https://raw.githubusercontent.com/noob123ii/IAuthBytes/main/UpdateDetection/LatestUpdate.txt";
        private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(10) };

        public static string GetCurrentVersion()
        {
            var asm = System.Reflection.Assembly.GetExecutingAssembly();
            var ver = asm.GetName().Version;
            return ver != null ? $"{ver.Major}.{ver.Minor}.{ver.Build}" : "1.0.0";
        }

        public static async Task<UpdateInfo> CheckForUpdateAsync()
        {
            var info = new UpdateInfo { CurrentVersion = GetCurrentVersion() };

            try
            {
                string raw = await _http.GetStringAsync(UpdateUrl);
                string[] lines = raw.Split(new[] { '\n', '\r' }, StringSplitOptions.RemoveEmptyEntries);

                string version = "";
                string downloadUrl = "";
                string releaseNotes = "";
                string integrity = "";

                foreach (string line in lines)
                {
                    if (line.StartsWith("Version:"))
                        version = line.Substring("Version:".Length).Trim();
                    else if (line.StartsWith("DownloadUrl:"))
                        downloadUrl = line.Substring("DownloadUrl:".Length).Trim();
                    else if (line.StartsWith("ReleaseNotes:"))
                        releaseNotes = line.Substring("ReleaseNotes:".Length).Trim();
                    else if (line.StartsWith("Integrity:"))
                        integrity = line.Substring("Integrity:".Length).Trim();
                }

                if (string.IsNullOrEmpty(version))
                {
                    info.Error = "Invalid update file format";
                    return info;
                }

                // Verify integrity
                if (!string.IsNullOrEmpty(integrity) && integrity != "placeholder")
                {
                    string contentBeforeIntegrity = raw;
                    int integrityIdx = raw.IndexOf("Integrity:");
                    if (integrityIdx >= 0)
                    {
                        contentBeforeIntegrity = raw.Substring(0, integrityIdx).TrimEnd();
                        using var sha = SHA256.Create();
                        string computedHash = Convert.ToHexString(sha.ComputeHash(System.Text.Encoding.UTF8.GetBytes(contentBeforeIntegrity)));
                        if (!computedHash.Equals(integrity, StringComparison.OrdinalIgnoreCase))
                        {
                            info.Error = "Update file integrity check failed — possible tampering";
                            Logger.Log($"UpdateChecker: Integrity mismatch! Expected={integrity}, Got={computedHash}");
                            return info;
                        }
                        Logger.Log($"UpdateChecker: Integrity verified OK");
                    }
                }

                info.LatestVersion = version;
                info.DownloadUrl = downloadUrl;
                info.ReleaseNotes = releaseNotes;

                if (IsNewerVersion(version, info.CurrentVersion))
                {
                    info.UpdateAvailable = true;
                    Logger.Log($"UpdateChecker: Update available! {info.CurrentVersion} -> {version}");
                }
                else
                {
                    Logger.Log($"UpdateChecker: Already up to date ({info.CurrentVersion})");
                }
            }
            catch (Exception ex)
            {
                info.Error = $"Update check failed: {ex.Message}";
                Logger.LogException("UpdateChecker", ex);
            }

            return info;
        }

        private static bool IsNewerVersion(string latest, string current)
        {
            try
            {
                var latestParts = latest.Split('.');
                var currentParts = current.Split('.');
                int majorL = int.Parse(latestParts[0]);
                int minorL = latestParts.Length > 1 ? int.Parse(latestParts[1]) : 0;
                int patchL = latestParts.Length > 2 ? int.Parse(latestParts[2]) : 0;
                int majorC = int.Parse(currentParts[0]);
                int minorC = currentParts.Length > 1 ? int.Parse(currentParts[1]) : 0;
                int patchC = currentParts.Length > 2 ? int.Parse(currentParts[2]) : 0;

                if (majorL > majorC) return true;
                if (majorL == majorC && minorL > minorC) return true;
                if (majorL == majorC && minorL == minorC && patchL > patchC) return true;
                return false;
            }
            catch { return false; }
        }

        public static void OpenDownloadPage(string url)
        {
            try
            {
                if (!string.IsNullOrEmpty(url))
                    Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                Logger.LogException("UpdateChecker", ex);
            }
        }
    }
}
