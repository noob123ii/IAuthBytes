using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
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
        public string ZipUrl { get; set; } = "";
        public string ReleaseNotes { get; set; } = "";
        public string Error { get; set; } = "";
    }

    internal static class UpdateChecker
    {
        private const string UpdateUrl = "https://raw.githubusercontent.com/noob123ii/IAuthBytes/main/UpdateDetection/LatestUpdate.txt";
        private const string ReleasesApi = "https://api.github.com/repos/noob123ii/IAuthBytes/releases/latest";
        private static readonly HttpClient _http = new() { Timeout = TimeSpan.FromSeconds(30) };

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
                string zipUrl = "";
                string releaseNotes = "";
                string integrity = "";

                foreach (string line in lines)
                {
                    if (line.StartsWith("Version:"))
                        version = line.Substring("Version:".Length).Trim();
                    else if (line.StartsWith("DownloadUrl:"))
                        downloadUrl = line.Substring("DownloadUrl:".Length).Trim();
                    else if (line.StartsWith("ZipUrl:"))
                        zipUrl = line.Substring("ZipUrl:".Length).Trim();
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
                info.ZipUrl = zipUrl;
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

        private static async Task<string> ResolveZipUrlAsync(string explicitZipUrl)
        {
            if (!string.IsNullOrEmpty(explicitZipUrl))
                return explicitZipUrl;

            try
            {
                _http.DefaultRequestHeaders.UserAgent.Clear();
                _http.DefaultRequestHeaders.UserAgent.ParseAdd("IAuthBytes-Updater");
                string json = await _http.GetStringAsync(ReleasesApi);
                using var doc = JsonDocument.Parse(json);
                var assets = doc.RootElement.GetProperty("assets");
                foreach (var asset in assets.EnumerateArray())
                {
                    string name = asset.GetProperty("name").GetString() ?? "";
                    if (name.EndsWith(".zip", StringComparison.OrdinalIgnoreCase))
                        return asset.GetProperty("browser_download_url").GetString() ?? "";
                }
            }
            catch (Exception ex)
            {
                Logger.LogException("UpdateChecker: Failed to resolve zip URL from GitHub API", ex);
            }

            return "";
        }

        public static async Task DownloadAndInstallAsync(string zipUrl, Action<string>? onProgress = null)
        {
            string resolvedUrl = await ResolveZipUrlAsync(zipUrl);
            if (string.IsNullOrEmpty(resolvedUrl))
            {
                onProgress?.Invoke("No download URL found");
                Logger.Log("UpdateChecker: No zip download URL available");
                return;
            }

            string tempDir = Path.Combine(Path.GetTempPath(), "IAuthBytes_Update_" + Guid.NewGuid().ToString("N")[..8]);
            string zipPath = Path.Combine(tempDir, "update.zip");
            string extractDir = Path.Combine(tempDir, "extracted");
            string appDir = AppContext.BaseDirectory;

            try
            {
                Directory.CreateDirectory(tempDir);

                onProgress?.Invoke("Downloading update...");
                Logger.Log($"UpdateChecker: Downloading from {resolvedUrl}");

                using (var response = await _http.GetAsync(resolvedUrl, HttpCompletionOption.ResponseHeadersRead))
                {
                    response.EnsureSuccessStatusCode();
                    long? totalBytes = response.Content.Headers.ContentLength;

                    await using var contentStream = await response.Content.ReadAsStreamAsync();
                    await using var fileStream = new FileStream(zipPath, FileMode.Create, FileAccess.Write, FileShare.None, 81920);

                    byte[] buffer = new byte[81920];
                    long downloaded = 0;
                    int bytesRead;
                    while ((bytesRead = await contentStream.ReadAsync(buffer)) > 0)
                    {
                        await fileStream.WriteAsync(buffer.AsMemory(0, bytesRead));
                        downloaded += bytesRead;
                        if (totalBytes > 0)
                        {
                            int pct = (int)(downloaded * 100 / totalBytes.Value);
                            onProgress?.Invoke($"Downloading... {pct}%");
                        }
                    }
                }

                onProgress?.Invoke("Extracting...");
                Logger.Log($"UpdateChecker: Extracting zip ({new FileInfo(zipPath).Length} bytes)");

                // Manual extraction with Zip Slip prevention
                string fullExtractDir = Path.GetFullPath(extractDir);
                using (var archive = ZipFile.OpenRead(zipPath))
                {
                    foreach (var entry in archive.Entries)
                    {
                        if (string.IsNullOrEmpty(entry.Name) && string.IsNullOrEmpty(entry.FullName))
                            continue;

                        string destPath = Path.GetFullPath(Path.Combine(fullExtractDir, entry.FullName));
                        if (!destPath.StartsWith(fullExtractDir, StringComparison.OrdinalIgnoreCase))
                        {
                            Logger.Log($"UpdateChecker: Zip Slip attempt blocked: {entry.FullName}");
                            throw new InvalidOperationException($"Zip entry attempts path traversal: {entry.FullName}");
                        }

                        if (entry.Name.Length == 0)
                        {
                            // Directory entry
                            Directory.CreateDirectory(destPath);
                        }
                        else
                        {
                            Directory.CreateDirectory(Path.GetDirectoryName(destPath)!);
                            entry.ExtractToFile(destPath, overwrite: true);
                        }
                    }
                }

                // Find the actual app files in the extracted content
                // They may be nested in a subfolder (e.g. IAuthBytes-1.1.0/)
                string srcDir = extractDir;
                var extractedDirs = Directory.GetDirectories(extractDir);
                if (extractedDirs.Length == 1 && Directory.GetFiles(extractedDirs[0]).Length == 0)
                {
                    // Single subfolder with no files at root — the content is inside
                    var innerFiles = Directory.GetFiles(extractedDirs[0]);
                    var innerDirs = Directory.GetDirectories(extractedDirs[0]);
                    if (innerFiles.Length > 0 || innerDirs.Length > 0)
                        srcDir = extractedDirs[0];
                }

                onProgress?.Invoke("Installing...");

                // Files to preserve (never overwrite these)
                var preserveDirs = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "Logs", "Crashes", "IAuthBytes.exe.WebView2",
                    "Baseline", "runtimes"
                };
                var preserveFiles = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
                {
                    "appsettings.json", "appsettings.Development.json"
                };

                // Copy new files over existing, skipping preserved items
                foreach (string srcFile in Directory.GetFiles(srcDir, "*", SearchOption.AllDirectories))
                {
                    string relativePath = Path.GetRelativePath(srcDir, srcFile);
                    string destFile = Path.Combine(appDir, relativePath);

                    // Check if this file is in a preserved directory
                    string? dirPart = Path.GetDirectoryName(relativePath);
                    string rootDir = dirPart?.Split(Path.DirectorySeparatorChar, Path.AltDirectorySeparatorChar)[0] ?? "";

                    if (preserveDirs.Contains(rootDir))
                    {
                        Logger.Log($"UpdateChecker: Skipped preserved dir: {rootDir}");
                        continue;
                    }

                    string fileName = Path.GetFileName(srcFile);
                    if (preserveFiles.Contains(fileName))
                    {
                        Logger.Log($"UpdateChecker: Skipped preserved file: {fileName}");
                        continue;
                    }

                    // Skip the updater script itself
                    if (fileName.EndsWith(".ps1", StringComparison.OrdinalIgnoreCase))
                        continue;

                    Directory.CreateDirectory(Path.GetDirectoryName(destFile)!);

                    try
                    {
                        File.Copy(srcFile, destFile, true);
                    }
                    catch (IOException)
                    {
                        // File may be locked — write to a staging location and use batch replace
                        string stagingFile = destFile + ".new";
                        File.Copy(srcFile, stagingFile, true);
                    }
                }

                onProgress?.Invoke("Update installed. Restarting...");

                // Write a PowerShell script that waits for us to exit, then relaunches
                string psScript = Path.Combine(tempDir, "update_restart.ps1");
                string psContent = $@"
# Wait for current process to fully exit
Start-Sleep -Seconds 3

# Remove the old temp zip
Remove-Item -LiteralPath '{zipPath}' -Force -ErrorAction SilentlyContinue

# Remove the extracted folder
Remove-Item -LiteralPath '{tempDir}' -Recurse -Force -ErrorAction SilentlyContinue

# Relaunch the app
Start-Process -FilePath '{Path.Combine(appDir, "IAuthBytes.exe")}'
";
                await File.WriteAllTextAsync(psScript, psContent);

                // Launch the PowerShell script detached
                Process.Start(new ProcessStartInfo
                {
                    FileName = "powershell.exe",
                    Arguments = $"-ExecutionPolicy Bypass -WindowStyle Hidden -File \"{psScript}\"",
                    CreateNoWindow = true,
                    UseShellExecute = false
                });

                Logger.Log("UpdateChecker: Update installed, restarting app");

                // Exit the app
                Environment.Exit(0);
            }
            catch (Exception ex)
            {
                onProgress?.Invoke($"Update failed: {ex.Message}");
                Logger.LogException("UpdateChecker: Install failed", ex);

                // Clean up temp dir
                try { Directory.Delete(tempDir, true); } catch { }
            }
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
