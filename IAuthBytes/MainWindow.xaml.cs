using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Threading;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Input;
using System.Windows.Interop;
using Microsoft.Web.WebView2.Core;

namespace IAuthBytes
{
    public partial class MainWindow : Window
    {
        private CancellationTokenSource? _scanCts;
        private CancellationTokenSource? _guardCts;
        private string? _gtPath;

        public MainWindow()
        {
            Logger.Log("MainWindow constructor...");
            InitializeComponent();
            Logger.Log("MainWindow constructor finished.");
        }

        private async void Window_Loaded(object sender, RoutedEventArgs e)
        {
            try
            {
                await Browser.EnsureCoreWebView2Async(null);
                Browser.CoreWebView2.WebMessageReceived += CoreWebView2_WebMessageReceived;

                string html = LoadEmbeddedHtml();
                Browser.CoreWebView2.NavigateToString(html);
            }
            catch (Exception ex)
            {
                Logger.LogException("WebView2 init", ex);
            }
        }

        private static string LoadEmbeddedHtml()
        {
            var asm = Assembly.GetExecutingAssembly();
            string resName = asm.GetName().Name + ".index.html";
            using var stream = asm.GetManifestResourceStream(resName);
            if (stream == null) throw new Exception($"Embedded resource '{resName}' not found");
            using var reader = new StreamReader(stream);
            return reader.ReadToEnd();
        }

        private void CoreWebView2_WebMessageReceived(object? sender, CoreWebView2WebMessageReceivedEventArgs e)
        {
            var raw = e.TryGetWebMessageAsString();
            JsonDocument json;
            try { json = JsonDocument.Parse(raw); }
            catch { return; }

            string action = json.RootElement.GetProperty("action").GetString() ?? "";

            switch (action)
            {
                case "drag":
                    ReleaseCapture();
                    SendMessage(new WindowInteropHelper(this).Handle, WM_NCLBUTTONDOWN, (IntPtr)HTCAPTION, IntPtr.Zero);
                    break;
                case "minimize":
                    Dispatcher.BeginInvoke(() => WindowState = WindowState.Minimized);
                    break;
                case "maximize":
                    Dispatcher.BeginInvoke(() => WindowState = WindowState == WindowState.Maximized ? WindowState.Normal : WindowState.Maximized);
                    break;
                case "close":
                    Dispatcher.BeginInvoke(() => Close());
                    break;
                case "startScan":
                    string scanPath = json.RootElement.TryGetProperty("path", out var sp) ? sp.GetString() ?? "" : "";
                    StartScan(scanPath);
                    break;
                case "findGt":
                    FindGorillaTag();
                    break;
                case "cancelScan":
                    _scanCts?.Cancel();
                    break;
                case "quarantine":
                    string qPath = json.RootElement.TryGetProperty("path", out var qp) ? qp.GetString() ?? "" : "";
                    QuarantineFile(qPath);
                    break;
                case "launchGt":
                    string lPath = json.RootElement.TryGetProperty("path", out var lp) ? lp.GetString() ?? "" : "";
                    LaunchGt(lPath);
                    break;
                case "startGuard":
                    string gPath = json.RootElement.TryGetProperty("path", out var gp) ? gp.GetString() ?? "" : "";
                    StartGuard(gPath);
                    break;
                case "stopGuard":
                    StopGuard();
                    break;
                case "scanMemory":
                    int pid = json.RootElement.TryGetProperty("pid", out var pidEl) ? pidEl.GetInt32() : 0;
                    if (pid > 0) ScanMemory(pid);
                    break;
            }
        }

        private void FindGorillaTag()
        {
            string? path = Scanner.FindGorillaTagPath();
            _gtPath = path;
            string js = path != null
                ? $"onGtFound('{EscapeJs(path)}')"
                : "onGtNotFound()";
            Dispatcher.BeginInvoke(() => Browser.CoreWebView2.ExecuteScriptAsync(js));
        }

        private void StartScan(string gtPath)
        {
            if (_scanCts != null) return;

            _scanCts = new CancellationTokenSource();
            var token = _scanCts.Token;

            Task.Run(() =>
            {
                var result = Scanner.RunScan(gtPath, progress =>
                {
                    string progressJson = Scanner.ToJson(progress);
                    Dispatcher.BeginInvoke(() =>
                        Browser.CoreWebView2.ExecuteScriptAsync($"onScanProgress({progressJson})"));
                }, token);

                string resultJson = Scanner.ToJson(result);
                Dispatcher.BeginInvoke(() =>
                {
                    Browser.CoreWebView2.ExecuteScriptAsync($"onScanComplete({resultJson})");
                    _scanCts?.Dispose();
                    _scanCts = null;
                });
            });
        }

        private void StartGuard(string gtPath)
        {
            if (_guardCts != null) return;

            _guardCts = new CancellationTokenSource();
            var token = _guardCts.Token;
            _gtPath = gtPath;

            RuntimeGuard.StartMonitoring(evt =>
            {
                string json = RuntimeGuard.ToJson(evt);
                Dispatcher.BeginInvoke(() =>
                    Browser.CoreWebView2.ExecuteScriptAsync($"onRuntimeEvent({json})"));
            }, token);

            RuntimeGuard.StartFileMonitoring(gtPath, evt =>
            {
                string json = RuntimeGuard.ToJson(evt);
                Dispatcher.BeginInvoke(() =>
                    Browser.CoreWebView2.ExecuteScriptAsync($"onRuntimeEvent({json})"));
            });

            RuntimeGuard.CheckRegistryPersistence(evt =>
            {
                string json = RuntimeGuard.ToJson(evt);
                Dispatcher.BeginInvoke(() =>
                    Browser.CoreWebView2.ExecuteScriptAsync($"onRuntimeEvent({json})"));
            });

            Dispatcher.BeginInvoke(() =>
                Browser.CoreWebView2.ExecuteScriptAsync("onGuardStarted()"));
        }

        private void StopGuard()
        {
            RuntimeGuard.StopMonitoring();
            RuntimeGuard.StopFileMonitoring();
            _guardCts?.Dispose();
            _guardCts = null;
            Dispatcher.BeginInvoke(() =>
                Browser.CoreWebView2.ExecuteScriptAsync("onGuardStopped()"));
        }

        private void ScanMemory(int pid)
        {
            Task.Run(() =>
            {
                RuntimeGuard.ScanMemoryPatterns(pid, evt =>
                {
                    string json = RuntimeGuard.ToJson(evt);
                    Dispatcher.BeginInvoke(() =>
                        Browser.CoreWebView2.ExecuteScriptAsync($"onRuntimeEvent({json})"));
                });
            });
        }

        private static string EscapeJs(string s) => s.Replace("\\", "\\\\").Replace("'", "\\'").Replace("\"", "\\\"");

        private void QuarantineFile(string path)
        {
            try
            {
                string quarantineDir = Path.Combine(
                    Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                    "IAuthBytes", "Quarantine");
                Directory.CreateDirectory(quarantineDir);

                if (File.Exists(path))
                {
                    string dest = Path.Combine(quarantineDir, Path.GetFileName(path) + "." + DateTime.Now.ToString("yyyyMMddHHmmss") + ".quarantine");
                    File.Move(path, dest);
                    Logger.Log($"Quarantined: {path} -> {dest}");
                }
                else if (Directory.Exists(path))
                {
                    string dest = Path.Combine(quarantineDir, Path.GetFileName(path) + "." + DateTime.Now.ToString("yyyyMMddHHmmss") + ".quarantine");
                    Directory.Move(path, dest);
                    Logger.Log($"Quarantined directory: {path} -> {dest}");
                }
            }
            catch (Exception ex)
            {
                Logger.LogException("Quarantine", ex);
            }
        }

        private void LaunchGt(string gtPath)
        {
            try
            {
                string exe = Path.Combine(gtPath, "Gorilla Tag.exe");
                if (File.Exists(exe))
                {
                    Process.Start(new ProcessStartInfo(exe) { WorkingDirectory = gtPath });
                }
                else
                {
                    Process.Start(new ProcessStartInfo("cmd", "/c start steam://rungameid/1533390") { CreateNoWindow = true });
                }
            }
            catch (Exception ex)
            {
                Logger.LogException("Launch GT", ex);
            }
        }

        protected override void OnClosed(EventArgs e)
        {
            RuntimeGuard.StopMonitoring();
            RuntimeGuard.StopFileMonitoring();
            _scanCts?.Dispose();
            _guardCts?.Dispose();
            base.OnClosed(e);
            Application.Current.Shutdown();
        }

        private const int WM_NCLBUTTONDOWN = 0xA1;
        private const int HTCAPTION = 0x2;

        [DllImport("user32.dll")]
        private static extern int SendMessage(IntPtr hWnd, int Msg, IntPtr wParam, IntPtr lParam);

        [DllImport("user32.dll")]
        private static extern bool ReleaseCapture();
    }
}
