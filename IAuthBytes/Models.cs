using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Linq;

namespace IAuthBytes
{
    public class ThreatInfo
    {
        public string FileName { get; set; } = "";
        public string FilePath { get; set; } = "";
        public string ThreatType { get; set; } = "";
        public string FileSize { get; set; } = "";
        public Severity Severity { get; set; }
        public string Description { get; set; } = "";

        public string ThreatTag
        {
            get
            {
                string desc = Description.ToLowerInvariant();
                if (desc.Contains("stealer") || desc.Contains("steam credential") || desc.Contains("token theft"))
                    return "Stealer";
                if (desc.Contains("keylogger"))
                    return "Keylogger";
                if (desc.Contains("screen capture") || desc.Contains("screenshot"))
                    return "Screen Cap";
                if (desc.Contains("clipboard"))
                    return "Clipboard";
                if (desc.Contains("process inject") || desc.Contains("injection api") || desc.Contains("nt api inject"))
                    return "Inject";
                if (desc.Contains("process hollow"))
                    return "Hollow";
                if (desc.Contains("hidden console") || desc.Contains("alloc+freeconsole"))
                    return "Hidden";
                if (desc.Contains("ransomware"))
                    return "Ransomware";
                if (desc.Contains("credential") || desc.Contains("dpapi"))
                    return "Credential";
                if (desc.Contains("c2") || desc.Contains("socket c2") || desc.Contains("network c2") || desc.Contains("http exfil"))
                    return "C2";
                if (desc.Contains("discord") || desc.Contains("exfil"))
                    return "Exfil";
                if (desc.Contains("powershell"))
                    return "PowerShell";
                if (desc.Contains("anti-debug"))
                    return "Anti-Debug";
                if (desc.Contains("anti-vm"))
                    return "Anti-VM";
                if (desc.Contains("graze"))
                    return "Graze";
                if (desc.Contains("embedded executable") || desc.Contains("pe/s"))
                    return "Dropper";
                if (desc.Contains("reflection") || desc.Contains("reflective"))
                    return "Reflective";
                if (desc.Contains("dynamic dll") || desc.Contains("dynamic load"))
                    return "Loader";
                if (desc.Contains("registry"))
                    return "Registry";
                if (desc.Contains("wmi"))
                    return "WMI";
                if (desc.Contains("service"))
                    return "Service";
                if (desc.Contains("scheduled task"))
                    return "Scheduler";
                if (desc.Contains("dns exfil"))
                    return "DNS Exfil";
                if (desc.Contains("lsass"))
                    return "LSASS";
                if (desc.Contains("multi-stage") || desc.Contains("base64"))
                    return "Multi-Stage";
                if (desc.Contains("malware size"))
                    return "Known Bad";
                if (desc.Contains("unsigned plugin") || desc.Contains("unsigned dll"))
                    return "Unsigned";
                if (desc.Contains("high entropy"))
                    return "Obfuscated";
                if (desc.Contains("overlay"))
                    return "Overlay";
                if (desc.Contains("tamper") || desc.Contains("hash mismatch") || desc.Contains("size mismatch") || desc.Contains("critical file missing"))
                    return "Tamper";
                if (desc.Contains("suspicious"))
                    return "Suspicious";
                if (desc.Contains("inline hook") || desc.Contains("jmp hook") || desc.Contains("call hook") ||
                    desc.Contains("indirect jmp") || desc.Contains("nop sled") || desc.Contains("push+ret") ||
                    desc.Contains("mov rax+jmp") || desc.Contains("iathook") || desc.Contains("debugger detected") ||
                    desc.Contains("remote debugger") || desc.Contains("ntquery debug") || desc.Contains("anti-hook"))
                    return "Anti-Hook";
                if (desc.Contains("hidden file") || desc.Contains("hidden attribute"))
                    return "Hidden";
                if (desc.Contains("symlink") || desc.Contains("reparse point"))
                    return "Symlink";
                if (desc.Contains("double extension") || desc.Contains("magic byte mismatch") ||
                    desc.Contains("magic bytes") || desc.Contains("disguise"))
                    return "Disguise";
                if (desc.Contains("integrity") || desc.Contains("hash mismatch") && desc.Contains("iauthbytes"))
                    return "Integrity";
                if (ThreatType.Contains("Graze"))
                    return "Graze";
                return ThreatType;
            }
        }

        public string ThreatTagColor => ThreatTag switch
        {
            "Stealer" => "Red",
            "Keylogger" => "Red",
            "Screen Cap" => "Orange",
            "Clipboard" => "Orange",
            "Inject" => "Red",
            "Hollow" => "Red",
            "Hidden" => "Orange",
            "Ransomware" => "Red",
            "Credential" => "Red",
            "C2" => "Red",
            "Exfil" => "Orange",
            "PowerShell" => "Yellow",
            "Anti-Debug" => "Yellow",
            "Anti-VM" => "Yellow",
            "Graze" => "Red",
            "Dropper" => "Red",
            "Reflective" => "Orange",
            "Loader" => "Orange",
            "Registry" => "Yellow",
            "WMI" => "Yellow",
            "Service" => "Yellow",
            "Scheduler" => "Yellow",
            "DNS Exfil" => "Orange",
            "LSASS" => "Red",
            "Multi-Stage" => "Orange",
            "Known Bad" => "Red",
            "Unsigned" => "TextMuted",
            "Obfuscated" => "Yellow",
            "Overlay" => "Yellow",
            "Tamper" => "Red",
            "Suspicious" => "Orange",
            "Anti-Hook" => "Red",
            "Symlink" => "Yellow",
            "Disguise" => "Red",
            "Integrity" => "Red",
            _ => "TextMuted",
        };

        public string ThreatTagBgColor => ThreatTagColor switch
        {
            "Red" => "RedLight",
            "Orange" => "OrangeLight",
            "Yellow" => "YellowLight",
            "Green" => "GreenLight",
            _ => "InputBg",
        };

        public string SeverityLabel => Severity switch
        {
            Severity.Critical => "CRITICAL",
            Severity.High => "SUSPECTED",
            Severity.Medium => "POSSIBLE",
            Severity.Low => "LOW",
            _ => "INFO",
        };

        public string SeverityColorKey => Severity switch
        {
            Severity.Critical => "Red",
            Severity.High => "Orange",
            Severity.Medium => "Yellow",
            Severity.Low => "Green",
            _ => "TextMuted",
        };

        public string SeverityBgColorKey => Severity switch
        {
            Severity.Critical => "RedLight",
            Severity.High => "OrangeLight",
            Severity.Medium => "YellowLight",
            Severity.Low => "GreenLight",
            _ => "InputBg",
        };
    }

    public class LogEntry
    {
        public string Timestamp { get; set; } = "";
        public string Source { get; set; } = "";
        public string Type { get; set; } = "";
        public string Message { get; set; } = "";
    }

    public class RuntimeEvent
    {
        public string Timestamp { get; set; } = DateTime.Now.ToString("HH:mm:ss");
        public string Type { get; set; } = "";
        public string Severity { get; set; } = "info";
        public string Message { get; set; } = "";
        public int? Pid { get; set; }
    }

    public enum Severity { Low, Medium, High, Critical }
    public enum LogType { Info, Warning, Error, Threat }
}
