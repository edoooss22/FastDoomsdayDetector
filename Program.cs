using System.Diagnostics;
using System.Text;

namespace Doomsday;

internal static class Program
{
    public const string Version = "1.0";

    private static bool _wait = true;
    private static bool _verbose;

    private static int Main(string[] args)
    {
        try { Console.OutputEncoding = Encoding.UTF8; } catch { }
        Console.Title = "Doomsday";

        int pid = 0;
        for (int i = 0; i < args.Length; i++)
        {
            switch (args[i])
            {
                case "--pid" when i + 1 < args.Length: int.TryParse(args[++i], out pid); break;
                case "--nowait": _wait = false; break;
                case "--all": _verbose = true; break;
            }
        }

        Native.EnablePrivilege("SeDebugPrivilege");

        Process? process = null;
        try { process = pid > 0 ? Process.GetProcessById(pid) : Scanner.FindTarget(); }
        catch { }
        if (process is null)
        {
            Line(pid > 0 ? $"{pid} - процесс не найден" : "javaw.exe не найден", ConsoleColor.Red);
            Wait();
            return 2;
        }

        IntPtr h;
        TargetInfo target;
        try
        {
            h = Scanner.Open(process.Id);
            target = Scanner.Describe(h, process);
        }
        catch (Exception ex)
        {
            Line($"{process.Id} - ошибка открытия процесса: {ex.Message}", ConsoleColor.Red);
            Wait();
            return 3;
        }

        string head = $"{target.Pid} - {(target.Window.Length > 0 ? target.Window : "(без окна)")}";

        if (_verbose)
        {
            Line($"[+] Процесс: {target.Name} (pid {target.Pid}), рабочее множество {target.WorkingSet / (1024 * 1024)} МБ",
                ConsoleColor.Gray);
            Line($"    {target.Path}", ConsoleColor.DarkGray);
        }
        if (target.Wow64)
        {
            Native.CloseHandle(h);
            Line($"{head} - DOOMSDAY UNKNOWN (процесс 32-разрядный)", ConsoleColor.Yellow);
            Wait();
            return 3;
        }

        List<ModuleScan> scans = new();
        try
        {
            var images = Scanner.FindImages(h, Rules.Module);
            if (images.Count == 0)
            {
                Line($"{head} - DOOMSDAY UNKNOWN ({Rules.Module} не загружен)", ConsoleColor.Yellow);
                Wait();
                return 5;
            }
            foreach (var (b, path) in images)
            {
                var m = Scanner.Scan(h, b, path);
                if (m is null)
                {
                    if (_verbose) Line($"[-] 0x{b:X} {path}: заголовок PE не читается", ConsoleColor.Yellow);
                }
                else scans.Add(m);
            }
        }
        catch (Exception ex)
        {
            Line($"{head} - DOOMSDAY UNKNOWN (ошибка чтения: {ex.Message})", ConsoleColor.Yellow);
            Wait();
            return 3;
        }
        finally { Native.CloseHandle(h); }

        bool detected = false;
        foreach (var m in scans)
        {
            var verdict = Rules.Evaluate(m);
            if (_verbose) Report(m, verdict);
            detected |= verdict.Detected;
        }

        if (_verbose) Console.WriteLine();
        if (detected) Line($"{head} - DOOMSDAY DETECTED", ConsoleColor.Red);
        else Line($"{head} - DOOMSDAY UNDETECTED", ConsoleColor.Green);

        Wait();
        return detected ? 1 : 0;
    }

    private static void Report(ModuleScan m, Verdict verdict)
    {
        Console.WriteLine();
        Line($"[+] {m.Name}  база 0x{m.Base:X}  образ 0x{m.Image.SizeOfImage:X}  " +
             $"TimeDateStamp 0x{m.Image.TimeDateStamp:X8}  экспортов {m.Image.Exports.Length}  функций {m.Image.Functions.Length}",
            ConsoleColor.Gray);
        Line($"    {m.Path}", ConsoleColor.DarkGray);

        if (m.Disk is null)
            Line($"    диск: не сверен — {m.DiskError}", ConsoleColor.Yellow);
        else
        {
            long delta = (long)m.Base - (long)m.Disk.ImageBase;
            Line($"    диск: {m.DiskLength} байт, ImageBase 0x{m.Disk.ImageBase:X}, сдвиг загрузки {(delta >= 0 ? "+" : "-")}0x{Math.Abs(delta):X}, " +
                 $"релокаций {m.Disk.Relocs.Length}" +
                 (m.Disk.Relocs.Any(r => m.Disk.SectionOf(r.Rva)?.Executable == true) ? "" : " (в коде нет)"),
                ConsoleColor.DarkGray);
        }

        foreach (var sec in m.Image.Sections.Where(s => m.Pages.Any(p => p.Section == s.Name)))
        {
            var pages = m.Pages.Where(p => p.Section == sec.Name).ToList();
            int priv = pages.Count(p => p.State == PageState.Private);
            int unknown = pages.Count(p => p.State == PageState.Unknown);
            int differ = pages.Count(p => p.MatchesDisk == false);
            Line($"    секция {sec.Name,-8} RVA 0x{sec.Va:X}..0x{sec.End:X}  страниц {pages.Count}, " +
                 $"общих {pages.Count - priv - unknown}, приватных {priv}, вне памяти {unknown}, отличных от диска {differ}",
                priv > 0 || differ > 0 ? ConsoleColor.Yellow : ConsoleColor.DarkGray);
        }

        foreach (var page in m.Pages)
        {
            if (page.State != PageState.Private && page.MatchesDisk != false) continue;
            PrintPage(m, page);
        }

        Console.WriteLine();
        if (verdict.Detected)
        {
            Line($"    правило {verdict.Rule}:", ConsoleColor.Red);
            foreach (var mark in verdict.Marks) Line($"      {mark}", ConsoleColor.Red);
        }
        else
        {
            int stray = m.Pages.Count(p => p.Executable && p.State == PageState.Private);
            if (stray > 0)
                Line($"    приватных страниц кода вне опорных функций: {stray} — правило не сработало",
                    ConsoleColor.Yellow);
            else
                Line("    следов записи в код нет", ConsoleColor.Green);
        }
    }

    private static void PrintPage(ModuleScan m, PageInfo page)
    {
        string state = page.State switch
        {
            PageState.Private => "ПРИВАТНАЯ",
            PageState.Shared => "общая",
            _ => page.SharedOriginal ? "вне памяти, прообраз общий" : "вне памяти, прообраз не общий",
        };
        string disk = page.MatchesDisk switch
        {
            true when page.State == PageState.Private => "[байты совпадают с диском — изменения ВОЗВРАЩЕНЫ]",
            true => "[байты совпадают с диском]",
            false => $"[байты ОТЛИЧАЮТСЯ от диска: {page.Diffs.Count} участков]",
            null => "[диск не сверен]",
        };
        string sym = page.NearestExport.Length > 0
            ? $"{m.Name}!{page.NearestExport}+0x{page.NearestOffset:X}"
            : $"{m.Name}+0x{page.Rva:X}";

        var color = page.State == PageState.Private || page.MatchesDisk == false
            ? ConsoleColor.Yellow : ConsoleColor.DarkGray;
        Line($"  0x{page.Address:X}  RVA 0x{page.Rva:X8}  секция {page.Section}  {Native.Prot(page.Protect)}  " +
             $"{state}  {sym}  {disk}", color);
        Line($"        функций начинается на странице: {page.FunctionsStarting}", color);
        if (page.Exports.Count > 0)
            Line($"        экспорты: {string.Join(" ", page.Exports)}", ConsoleColor.DarkGray);

        var anchors = Rules.AnchorsOn(m, page);
        if (anchors.Count > 0)
            Line($"        опорные функции: {string.Join(" ", anchors)}", ConsoleColor.Red);

        foreach (var d in page.Diffs.Take(8))
            Line($"        0x{d.Rva:X8} {d.Function}: диск {Rules.Hex(d.Disk)}  память {Rules.Hex(d.Memory)}",
                ConsoleColor.Red);
        if (page.Diffs.Count > 8) Line($"        … ещё {page.Diffs.Count - 8}", ConsoleColor.Red);
    }

    private static void Line(string text, ConsoleColor color)
    {
        Console.ForegroundColor = color;
        Console.WriteLine(text);
        Console.ResetColor();
    }

    private static void Wait()
    {
        if (!_wait) return;
        Console.WriteLine();
        Console.WriteLine("Нажмите любую клавишу, чтобы закрыть окно.");
        try { Console.ReadKey(true); } catch { }
    }
}
