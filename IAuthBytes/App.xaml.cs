using System;
using System.Threading.Tasks;
using System.Windows;

namespace IAuthBytes
{
    public partial class App : Application
    {
        private void OnStartup(object sender, StartupEventArgs e)
        {
            Logger.Log("=== Application Starting ===");
            Logger.Log($"OS: {Environment.OSVersion}");
            Logger.Log($"CLR: {Environment.Version}");
            Logger.Log($"64-bit: {Environment.Is64BitProcess}");
            Logger.Log($"Args: {string.Join(" ", e.Args)}");

            AppDomain.CurrentDomain.UnhandledException += (_, args) =>
            {
                Logger.Log("=== UNHANDLED EXCEPTION ===");
                if (args.ExceptionObject is Exception ex)
                    Logger.LogCrash("Unhandled", ex);
                else
                    Logger.Log($"Unhandled: {args.ExceptionObject}");

                MessageBox.Show($"Fatal error. Check Crashes folder\n\n{args.ExceptionObject}",
                    "IAuthBytes", MessageBoxButton.OK, MessageBoxImage.Error);
            };

            DispatcherUnhandledException += (_, args) =>
            {
                Logger.LogCrash("Dispatcher", args.Exception);
                args.Handled = true;
            };

            TaskScheduler.UnobservedTaskException += (_, args) =>
            {
                Logger.LogCrash("UnobservedTask", args.Exception);
                args.SetObserved();
            };

            try
            {
                Logger.Log("Creating MainWindow...");
                var window = new MainWindow();
                Logger.Log("MainWindow created. Calling Show()...");
                window.Show();
                Logger.Log("Show() called successfully.");
            }
            catch (Exception ex)
            {
                Logger.LogCrash("Startup", ex);
                MessageBox.Show($"Failed to start:\n{ex}\n\nCheck Crashes folder",
                    "IAuthBytes", MessageBoxButton.OK, MessageBoxImage.Error);
                Shutdown();
            }
        }
    }
}
