// ============================================================================
//  Strix Disk Cleaner - minimal native launcher
//
//  Purpose: start the installed PowerShell application with NO console window
//  ever appearing. Built as a GUI-subsystem executable (so the launcher itself
//  has no console) and starts powershell with CREATE_NO_WINDOW (so the child
//  has no console either). The WPF window the script creates shows normally.
//
//  This is deliberately tiny and transparent. Unlike the old launcher it does
//  NOT embed, extract, or drop a payload - it simply runs the .ps1 that sits
//  next to it (installed into Program Files, writable only by an administrator).
//  That "no drop, no hidden-shell dance" shape is far less likely to trip an
//  antivirus ML heuristic. It still should be code-signed for a warning-free
//  install; see installer\README-PACKAGING.md.
//
//  The app.manifest requests Administrator once, so there is a single clean UAC
//  prompt and the script never has to relaunch itself (no console flash).
// ============================================================================
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
using System.Runtime.InteropServices;

[assembly: AssemblyTitle("Strix Disk Cleaner")]
[assembly: AssemblyProduct("Strix Disk Cleaner")]
[assembly: AssemblyDescription("Professional Data Destruction Tool")]
[assembly: AssemblyCompany("Strix")]
[assembly: AssemblyCopyright("(c) Strix")]
[assembly: AssemblyVersion("2.3.0.0")]
[assembly: AssemblyFileVersion("2.3.0.0")]

internal static class Program
{
    [DllImport("user32.dll", CharSet = CharSet.Unicode)]
    private static extern int MessageBoxW(IntPtr hWnd, string text, string caption, uint type);

    private static void Fail(string msg)
    {
        MessageBoxW(IntPtr.Zero, msg, "Strix Disk Cleaner", 0x10); // MB_ICONERROR
        Environment.Exit(1);
    }

    private static int Main()
    {
        try
        {
            string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
            string ps1 = Path.Combine(dir, "StrixDiskCleaner.ps1");
            if (!File.Exists(ps1)) { Fail("StrixDiskCleaner.ps1 was not found next to the launcher."); return 1; }

            // Absolute path to Windows PowerShell; never trust PATH.
            string pwsh = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.System),
                @"WindowsPowerShell\v1.0\powershell.exe");
            if (!File.Exists(pwsh)) pwsh = "powershell.exe";

            var psi = new ProcessStartInfo
            {
                FileName = pwsh,
                Arguments = "-NoProfile -ExecutionPolicy Bypass -WindowStyle Hidden -File \"" + ps1 + "\"",
                UseShellExecute = false,
                CreateNoWindow = true,          // no console for the child
                WorkingDirectory = dir,
            };
            Process.Start(psi);                 // launcher exits immediately; WPF window takes over
            return 0;
        }
        catch (Exception ex)
        {
            Fail("Could not start the application:\n\n" + ex.Message);
            return 1;
        }
    }
}
